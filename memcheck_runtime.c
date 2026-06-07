#include "memcheck_runtime.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEMCHECK_MAGIC_LIVE 0x4D43484B4C495645ULL
#define MEMCHECK_MAGIC_FREED 0x4D43484B46524545ULL
#define FRONT_GUARD_SIZE 32
#define REAR_GUARD_SIZE 32
#define GUARD_BYTE 0xA5
#define FREED_BYTE 0xDD
#define STACK_DEPTH_MAX 48
#define PATH_SIZE 512
#define ALLOC_BYTE 0xCC

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *ptr, size_t size);
void __real_free(void *ptr);
char *__real__strdup(const char *str);
char *__real_strdup(const char *str);

void *__wrap_malloc(size_t size);
void *__wrap_calloc(size_t count, size_t size);
void *__wrap_realloc(void *ptr, size_t size);
void __wrap_free(void *ptr);
char *__wrap__strdup(const char *str);
char *__wrap_strdup(const char *str);

typedef struct memcheck_options {
  size_t quarantine_bytes;
  unsigned stack_depth;
  int write_jsonl;
  int write_ai_report;
  int fail_on_error;
  int fail_on_leak;
  int aggressive;
  int validate_each_op;
  int fill_allocations;
  int fail_fast;
  char report_prefix[PATH_SIZE];
} memcheck_options;

typedef struct memcheck_header {
  uint64_t magic;
  size_t requested_size;
  size_t total_size;
  unsigned long sequence;
  unsigned long free_sequence;
  DWORD thread_id;
  DWORD free_thread_id;
  USHORT alloc_stack_depth;
  USHORT free_stack_depth;
  void *alloc_stack[STACK_DEPTH_MAX];
  void *free_stack[STACK_DEPTH_MAX];
  struct memcheck_header *prev;
  struct memcheck_header *next;
  struct memcheck_header *q_prev;
  struct memcheck_header *q_next;
  unsigned char front_guard[FRONT_GUARD_SIZE];
} memcheck_header;

typedef struct leak_group {
  void *top_frame;
  unsigned long count;
  size_t bytes;
} leak_group;

static INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_lock;
static memcheck_header *g_live_head;
static memcheck_header *g_quarantine_head;
static memcheck_header *g_quarantine_tail;
static size_t g_quarantine_bytes;
static unsigned long g_next_sequence;
static unsigned long g_total_allocations;
static unsigned long g_live_allocations;
static unsigned long g_freed_allocations;
static unsigned long g_errors;
static unsigned long g_guard_errors;
static unsigned long g_invalid_free_errors;
static unsigned long g_double_free_errors;
static unsigned long g_aggressive_scans;
static unsigned long g_aggressive_scan_failures;
static unsigned long g_oom_failures;
static memcheck_options g_options;
static uintptr_t g_module_base;
static char g_exe_path[PATH_SIZE];
static int g_reporting;

static void option_defaults(void)
{
  g_options.quarantine_bytes = 64u * 1024u * 1024u;
  g_options.stack_depth = 32;
  g_options.write_jsonl = 1;
  g_options.write_ai_report = 1;
  g_options.fail_on_error = 0;
  g_options.fail_on_leak = 0;
  g_options.aggressive = 0;
  g_options.validate_each_op = 0;
  g_options.fill_allocations = 0;
  g_options.fail_fast = 0;
  strcpy(g_options.report_prefix, "memcheck");
}

static int option_bool(const char *value, int fallback)
{
  if (!value || !*value) {
    return fallback;
  }
  return !(strcmp(value, "0") == 0 || _stricmp(value, "false") == 0 || _stricmp(value, "no") == 0);
}

static size_t parse_size_mb(const char *value, size_t fallback)
{
  char *end = NULL;
  unsigned long mb;
  if (!value || !*value) {
    return fallback;
  }
  mb = strtoul(value, &end, 10);
  if (end == value) {
    return fallback;
  }
  return ((size_t)mb) * 1024u * 1024u;
}

static void parse_env_options(void)
{
  const char *value;
  option_defaults();

  value = getenv("MEMCHECK_REPORT_PREFIX");
  if (value && *value) {
    strncpy(g_options.report_prefix, value, sizeof(g_options.report_prefix) - 1);
    g_options.report_prefix[sizeof(g_options.report_prefix) - 1] = '\0';
  }

  g_options.quarantine_bytes = parse_size_mb(getenv("MEMCHECK_QUARANTINE_MB"), g_options.quarantine_bytes);

  value = getenv("MEMCHECK_STACK_DEPTH");
  if (value && *value) {
    unsigned long depth = strtoul(value, NULL, 10);
    if (depth > 0 && depth <= STACK_DEPTH_MAX) {
      g_options.stack_depth = (unsigned)depth;
    }
  }

  g_options.write_jsonl = option_bool(getenv("MEMCHECK_JSONL"), g_options.write_jsonl);
  g_options.write_ai_report = option_bool(getenv("MEMCHECK_AI_REPORT"), g_options.write_ai_report);
  g_options.fail_on_error = option_bool(getenv("MEMCHECK_FAIL_ON_ERROR"), g_options.fail_on_error);
  g_options.fail_on_leak = option_bool(getenv("MEMCHECK_FAIL_ON_LEAK"), g_options.fail_on_leak);
  g_options.aggressive = option_bool(getenv("MEMCHECK_AGGRESSIVE"), g_options.aggressive);
  g_options.validate_each_op = option_bool(getenv("MEMCHECK_VALIDATE_EACH_OP"), g_options.validate_each_op);
  g_options.fill_allocations = option_bool(getenv("MEMCHECK_FILL_ALLOCATIONS"), g_options.fill_allocations);
  g_options.fail_fast = option_bool(getenv("MEMCHECK_FAIL_FAST"), g_options.fail_fast);

  if (g_options.aggressive) {
    if (!getenv("MEMCHECK_VALIDATE_EACH_OP")) {
      g_options.validate_each_op = 1;
    }
    if (!getenv("MEMCHECK_FILL_ALLOCATIONS")) {
      g_options.fill_allocations = 1;
    }
    if (!getenv("MEMCHECK_STACK_DEPTH")) {
      g_options.stack_depth = STACK_DEPTH_MAX;
    }
    if (!getenv("MEMCHECK_QUARANTINE_MB")) {
      g_options.quarantine_bytes = 256u * 1024u * 1024u;
    }
  }
}

static void report_path(char *buffer, size_t buffer_size, const char *suffix)
{
  snprintf(buffer, buffer_size, "%s-%s", g_options.report_prefix, suffix);
}

static BOOL CALLBACK memcheck_init_once(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
  (void)once;
  (void)parameter;
  (void)context;
  parse_env_options();
  g_module_base = (uintptr_t)GetModuleHandleA(NULL);
  GetModuleFileNameA(NULL, g_exe_path, sizeof(g_exe_path));
  InitializeCriticalSection(&g_lock);
  atexit(memcheck_dump_reports);
  return TRUE;
}

static void memcheck_init(void)
{
  InitOnceExecuteOnce(&g_init_once, memcheck_init_once, NULL, NULL);
}

static unsigned char *user_ptr_from_header(memcheck_header *header)
{
  return ((unsigned char *)header) + sizeof(memcheck_header);
}

static unsigned char *rear_guard(memcheck_header *header)
{
  return user_ptr_from_header(header) + header->requested_size;
}

static void fill_guards(memcheck_header *header)
{
  memset(header->front_guard, GUARD_BYTE, FRONT_GUARD_SIZE);
  memset(rear_guard(header), GUARD_BYTE, REAR_GUARD_SIZE);
}

static int guard_is_valid(const unsigned char *guard, size_t size)
{
  size_t i;
  for (i = 0; i < size; ++i) {
    if (guard[i] != GUARD_BYTE) {
      return 0;
    }
  }
  return 1;
}

static void capture_stack(void **stack, USHORT *depth, ULONG frames_to_skip)
{
  *depth = CaptureStackBackTrace(frames_to_skip, g_options.stack_depth, stack, NULL);
}

static void append_json_event(const char *kind, const void *ptr, const memcheck_header *header)
{
  char path[PATH_SIZE];
  FILE *file;
  USHORT i;
  int was_reporting;
  if (!g_options.write_jsonl) {
    return;
  }
  was_reporting = g_reporting;
  g_reporting = 1;
  report_path(path, sizeof(path), "events.jsonl");
  file = fopen(path, "a");
  if (file) {
    fprintf(file, "{\"kind\":\"%s\",\"ptr\":\"%p\",\"module_base\":\"0x%llx\",\"exe\":\"",
            kind, ptr, (unsigned long long)g_module_base);
    {
      const char *p = g_exe_path;
      while (*p) {
        if (*p == '\\' || *p == '"') {
          fputc('\\', file);
        }
        fputc(*p, file);
        ++p;
      }
    }
    fprintf(file, "\"");
    if (header) {
      fprintf(file, ",\"seq\":%lu,\"size\":%zu,\"thread\":%lu",
              header->sequence, header->requested_size, (unsigned long)header->thread_id);
      fprintf(file, ",\"alloc_stack\":[");
      for (i = 0; i < header->alloc_stack_depth; ++i) {
        fprintf(file, "%s\"%p\"", i ? "," : "", header->alloc_stack[i]);
      }
      fprintf(file, "]");
      if (header->free_stack_depth) {
        fprintf(file, ",\"free_stack\":[");
        for (i = 0; i < header->free_stack_depth; ++i) {
          fprintf(file, "%s\"%p\"", i ? "," : "", header->free_stack[i]);
        }
        fprintf(file, "]");
      }
    }
    fprintf(file, "}\n");
    fclose(file);
  }
  g_reporting = was_reporting;
}

static void record_error(const char *kind, void *ptr, const memcheck_header *header)
{
  char path[PATH_SIZE];
  FILE *file;
  USHORT i;
  void *current_stack[STACK_DEPTH_MAX];
  USHORT current_stack_depth = 0;
  if (g_reporting) {
    return;
  }
  if (!header) {
    capture_stack(current_stack, &current_stack_depth, 2);
  }
  g_reporting = 1;
  report_path(path, sizeof(path), "errors.txt");
  file = fopen(path, "a");
  if (file) {
    fprintf(file, "%s ptr=%p", kind, ptr);
    if (header) {
      fprintf(file, " seq=%lu size=%zu thread=%lu", header->sequence,
              header->requested_size, (unsigned long)header->thread_id);
      fprintf(file, "\n  allocation stack:\n");
      for (i = 0; i < header->alloc_stack_depth; ++i) {
        fprintf(file, "    frame[%u]=%p\n", (unsigned)i, header->alloc_stack[i]);
      }
      if (header->free_stack_depth) {
        fprintf(file, "  free stack:\n");
        for (i = 0; i < header->free_stack_depth; ++i) {
          fprintf(file, "    frame[%u]=%p\n", (unsigned)i, header->free_stack[i]);
        }
      }
    } else {
      fprintf(file, "\n  current stack:\n");
      for (i = 0; i < current_stack_depth; ++i) {
        fprintf(file, "    frame[%u]=%p\n", (unsigned)i, current_stack[i]);
      }
    }
    fclose(file);
  }
  ++g_errors;
  if (strstr(kind, "guard")) {
    ++g_guard_errors;
  } else if (strstr(kind, "double-free")) {
    ++g_double_free_errors;
  } else if (strstr(kind, "invalid")) {
    ++g_invalid_free_errors;
  }
  g_reporting = 0;
  append_json_event(kind, ptr, header);
  if (g_options.fail_fast) {
    fflush(NULL);
    DebugBreak();
    ExitProcess(3);
  }
}

static int validate_guards_only(memcheck_header *header, const char *kind)
{
  int ok = 1;
  if (!header) {
    return 1;
  }
  if (header->magic != MEMCHECK_MAGIC_LIVE && header->magic != MEMCHECK_MAGIC_FREED) {
    record_error("metadata-corruption", user_ptr_from_header(header), header);
    return 0;
  }
  if (!guard_is_valid(header->front_guard, FRONT_GUARD_SIZE)) {
    record_error(kind ? kind : "front-guard-corruption", user_ptr_from_header(header), header);
    ok = 0;
  }
  if (!guard_is_valid(rear_guard(header), REAR_GUARD_SIZE)) {
    record_error(kind ? kind : "rear-guard-corruption", user_ptr_from_header(header), header);
    ok = 0;
  }
  return ok;
}

static void aggressive_scan_locked(const char *reason)
{
  memcheck_header *cur;
  int ok = 1;
  (void)reason;
  if (!g_options.validate_each_op || g_reporting) {
    return;
  }
  ++g_aggressive_scans;
  cur = g_live_head;
  while (cur) {
    ok = validate_guards_only(cur, NULL) && ok;
    cur = cur->next;
  }
  cur = g_quarantine_head;
  while (cur) {
    ok = validate_guards_only(cur, "quarantined-block-corruption") && ok;
    cur = cur->q_next;
  }
  if (!ok) {
    ++g_aggressive_scan_failures;
  }
}

static void live_insert(memcheck_header *header)
{
  header->prev = NULL;
  header->next = g_live_head;
  if (g_live_head) {
    g_live_head->prev = header;
  }
  g_live_head = header;
  ++g_live_allocations;
  ++g_total_allocations;
}

static void live_remove(memcheck_header *header)
{
  if (header->prev) {
    header->prev->next = header->next;
  } else if (g_live_head == header) {
    g_live_head = header->next;
  }
  if (header->next) {
    header->next->prev = header->prev;
  }
  header->prev = NULL;
  header->next = NULL;
  if (g_live_allocations > 0) {
    --g_live_allocations;
  }
}

static void quarantine_append(memcheck_header *header)
{
  header->q_prev = g_quarantine_tail;
  header->q_next = NULL;
  if (g_quarantine_tail) {
    g_quarantine_tail->q_next = header;
  } else {
    g_quarantine_head = header;
  }
  g_quarantine_tail = header;
  g_quarantine_bytes += header->total_size;
  ++g_freed_allocations;
}

static void quarantine_remove(memcheck_header *header)
{
  if (header->q_prev) {
    header->q_prev->q_next = header->q_next;
  } else if (g_quarantine_head == header) {
    g_quarantine_head = header->q_next;
  }
  if (header->q_next) {
    header->q_next->q_prev = header->q_prev;
  } else if (g_quarantine_tail == header) {
    g_quarantine_tail = header->q_prev;
  }
  if (g_quarantine_bytes >= header->total_size) {
    g_quarantine_bytes -= header->total_size;
  } else {
    g_quarantine_bytes = 0;
  }
  header->q_prev = NULL;
  header->q_next = NULL;
}

static void quarantine_trim(void)
{
  while (g_quarantine_bytes > g_options.quarantine_bytes && g_quarantine_head) {
    memcheck_header *victim = g_quarantine_head;
    quarantine_remove(victim);
    __real_free(victim);
  }
}

static memcheck_header *header_from_user_ptr(void *ptr)
{
  if (!ptr) {
    return NULL;
  }
  return (memcheck_header *)(((unsigned char *)ptr) - sizeof(memcheck_header));
}

static int memory_is_readable(const void *ptr, size_t size)
{
  MEMORY_BASIC_INFORMATION mbi;
  uintptr_t start = (uintptr_t)ptr;
  uintptr_t end = start + size;
  uintptr_t cursor = start;
  if (!ptr || end < start) {
    return 0;
  }
  while (cursor < end) {
    DWORD protect;
    if (!VirtualQuery((const void *)cursor, &mbi, sizeof(mbi))) {
      return 0;
    }
    protect = mbi.Protect & 0xff;
    if (mbi.State != MEM_COMMIT || protect == PAGE_NOACCESS || protect == PAGE_EXECUTE) {
      return 0;
    }
    cursor = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    if (cursor <= start) {
      return 0;
    }
  }
  return 1;
}

static int validate_allocation(memcheck_header *header, void *user_ptr)
{
  if (!header || !memory_is_readable(header, sizeof(*header))) {
    record_error("invalid-pointer", user_ptr, NULL);
    return 0;
  }
  if (header->magic == MEMCHECK_MAGIC_FREED) {
    record_error("double-free-or-use-after-free", user_ptr, header);
    return 0;
  }
  if (header->magic != MEMCHECK_MAGIC_LIVE) {
    record_error("invalid-pointer", user_ptr, NULL);
    return 0;
  }
  if (!memory_is_readable(header, header->total_size)) {
    record_error("metadata-corruption", user_ptr, header);
    return 0;
  }
  if (!guard_is_valid(header->front_guard, FRONT_GUARD_SIZE)) {
    record_error("front-guard-corruption", user_ptr, header);
  }
  if (!guard_is_valid(rear_guard(header), REAR_GUARD_SIZE)) {
    record_error("rear-guard-corruption", user_ptr, header);
  }
  return 1;
}

void *__wrap_malloc(size_t size)
{
  size_t total;
  memcheck_header *header;

  memcheck_init();
  if (g_reporting) {
    return __real_malloc(size);
  }

  total = sizeof(memcheck_header) + size + REAR_GUARD_SIZE;
  header = (memcheck_header *)__real_malloc(total);
  if (!header) {
    ++g_oom_failures;
    return NULL;
  }

  memset(header, 0, sizeof(*header));
  header->magic = MEMCHECK_MAGIC_LIVE;
  header->requested_size = size;
  header->total_size = total;
  header->sequence = InterlockedIncrement((volatile LONG *)&g_next_sequence);
  header->thread_id = GetCurrentThreadId();
  capture_stack(header->alloc_stack, &header->alloc_stack_depth, 2);
  fill_guards(header);
  if (g_options.fill_allocations && size) {
    memset(user_ptr_from_header(header), ALLOC_BYTE, size);
  }

  EnterCriticalSection(&g_lock);
  aggressive_scan_locked("malloc");
  live_insert(header);
  LeaveCriticalSection(&g_lock);

  append_json_event("alloc", user_ptr_from_header(header), header);
  return user_ptr_from_header(header);
}

void *__wrap_calloc(size_t count, size_t size)
{
  size_t total;
  void *ptr;
  if (count != 0 && size > ((size_t)-1) / count) {
    ++g_oom_failures;
    return NULL;
  }
  total = count * size;
  ptr = __wrap_malloc(total);
  if (ptr) {
    memset(ptr, 0, total);
  }
  return ptr;
}

void *__wrap_realloc(void *ptr, size_t size)
{
  memcheck_header *old_header;
  void *new_ptr;
  size_t copy_size;

  if (!ptr) {
    return __wrap_malloc(size);
  }
  if (size == 0) {
    __wrap_free(ptr);
    return NULL;
  }

  old_header = header_from_user_ptr(ptr);
  if (!validate_allocation(old_header, ptr)) {
    return NULL;
  }

  new_ptr = __wrap_malloc(size);
  if (!new_ptr) {
    return NULL;
  }

  copy_size = old_header->requested_size < size ? old_header->requested_size : size;
  memcpy(new_ptr, ptr, copy_size);
  __wrap_free(ptr);
  return new_ptr;
}

void __wrap_free(void *ptr)
{
  memcheck_header *header;
  if (!ptr) {
    return;
  }

  memcheck_init();
  header = header_from_user_ptr(ptr);
  if (!validate_allocation(header, ptr)) {
    return;
  }

  capture_stack(header->free_stack, &header->free_stack_depth, 2);
  header->free_sequence = InterlockedIncrement((volatile LONG *)&g_next_sequence);
  header->free_thread_id = GetCurrentThreadId();

  EnterCriticalSection(&g_lock);
  aggressive_scan_locked("free-before");
  live_remove(header);
  memset(ptr, FREED_BYTE, header->requested_size);
  header->magic = MEMCHECK_MAGIC_FREED;
  quarantine_append(header);
  quarantine_trim();
  aggressive_scan_locked("free-after");
  LeaveCriticalSection(&g_lock);

  append_json_event("free", ptr, header);
}

char *__wrap__strdup(const char *str)
{
  size_t length;
  char *copy;
  if (!str) {
    return NULL;
  }
  length = strlen(str) + 1;
  copy = (char *)__wrap_malloc(length);
  if (copy) {
    memcpy(copy, str, length);
  }
  return copy;
}

char *__wrap_strdup(const char *str)
{
  return __wrap__strdup(str);
}

static void add_group(leak_group *groups, size_t group_cap, size_t *group_count, memcheck_header *header)
{
  size_t i;
  void *top = header->alloc_stack_depth ? header->alloc_stack[0] : NULL;
  for (i = 0; i < *group_count; ++i) {
    if (groups[i].top_frame == top) {
      ++groups[i].count;
      groups[i].bytes += header->requested_size;
      return;
    }
  }
  if (*group_count < group_cap) {
    groups[*group_count].top_frame = top;
    groups[*group_count].count = 1;
    groups[*group_count].bytes = header->requested_size;
    ++(*group_count);
  }
}

static void sort_groups(leak_group *groups, size_t group_count)
{
  size_t i;
  int swapped;
  if (group_count < 2) {
    return;
  }
  do {
    swapped = 0;
    for (i = 1; i < group_count; ++i) {
      if (groups[i].bytes > groups[i - 1].bytes) {
        leak_group tmp = groups[i - 1];
        groups[i - 1] = groups[i];
        groups[i] = tmp;
        swapped = 1;
      }
    }
  } while (swapped);
}

static void write_ai_report(unsigned long leak_count, size_t leak_bytes, leak_group *groups, size_t group_count)
{
  char path[PATH_SIZE];
  FILE *file;
  size_t i;
  if (!g_options.write_ai_report) {
    return;
  }
  report_path(path, sizeof(path), "ai-report.md");
  file = fopen(path, "w");
  if (!file) {
    return;
  }
  fprintf(file, "# Memcheck AI Report\n\n");
  fprintf(file, "## Executive Summary\n\n");
  fprintf(file, "- Errors: %lu\n", g_errors);
  fprintf(file, "- Guard errors: %lu\n", g_guard_errors);
  fprintf(file, "- Invalid frees: %lu\n", g_invalid_free_errors);
  fprintf(file, "- Double-free/use-after-free: %lu\n", g_double_free_errors);
  fprintf(file, "- Leaks: %lu allocations, %zu bytes\n", leak_count, leak_bytes);
  fprintf(file, "- Total allocations: %lu\n", g_total_allocations);
  fprintf(file, "- Freed allocations: %lu\n", g_freed_allocations);
  fprintf(file, "- Quarantine bytes retained: %zu\n", g_quarantine_bytes);
  fprintf(file, "- Aggressive scans: %lu\n", g_aggressive_scans);
  fprintf(file, "- Aggressive scan failures: %lu\n\n", g_aggressive_scan_failures);
  fprintf(file, "- Executable: `%s`\n", g_exe_path);
  fprintf(file, "- Module base: `0x%llx`\n\n", (unsigned long long)g_module_base);

  fprintf(file, "## Top Leak Groups\n\n");
  for (i = 0; i < group_count && i < 20; ++i) {
    fprintf(file, "%zu. top_frame=%p count=%lu bytes=%zu\n",
            i + 1, groups[i].top_frame, groups[i].count, groups[i].bytes);
  }

  fprintf(file, "\n## AI Investigation Prompt\n\n");
  fprintf(file, "You are reviewing a Windows-native MinGW memory-check report. ");
  fprintf(file, "Prioritize guard corruption, double-free/use-after-free, then leak groups by bytes. ");
  fprintf(file, "Use `%s-events.jsonl`, `%s-errors.txt`, and `%s-leaks.txt` as evidence. ",
          g_options.report_prefix, g_options.report_prefix, g_options.report_prefix);
  fprintf(file, "Map stack addresses to symbols using the diagnostic executable and `addr2line` or `gdb`. ");
  fprintf(file, "Return likely root causes, confidence, and concrete next code locations to inspect.\n");
  fclose(file);
}

void memcheck_dump_reports(void)
{
  char path[PATH_SIZE];
  FILE *summary;
  FILE *leaks;
  FILE *groups_file;
  memcheck_header *cur;
  unsigned long leak_count = 0;
  size_t leak_bytes = 0;
  leak_group groups[256];
  size_t group_count = 0;

  memcheck_init();
  if (g_reporting) {
    return;
  }
  g_reporting = 1;
  memset(groups, 0, sizeof(groups));

  report_path(path, sizeof(path), "summary.txt");
  summary = fopen(path, "w");
  report_path(path, sizeof(path), "leaks.txt");
  leaks = fopen(path, "w");
  report_path(path, sizeof(path), "leak-groups.txt");
  groups_file = fopen(path, "w");

  EnterCriticalSection(&g_lock);
  aggressive_scan_locked("dump");
  cur = g_live_head;
  while (cur) {
    if (cur->magic == MEMCHECK_MAGIC_LIVE) {
      USHORT i;
      ++leak_count;
      leak_bytes += cur->requested_size;
      add_group(groups, sizeof(groups) / sizeof(groups[0]), &group_count, cur);
      if (leaks) {
        fprintf(leaks, "leak seq=%lu size=%zu thread=%lu user=%p\n",
                cur->sequence, cur->requested_size,
                (unsigned long)cur->thread_id, user_ptr_from_header(cur));
        for (i = 0; i < cur->alloc_stack_depth; ++i) {
          fprintf(leaks, "  frame[%u]=%p\n", (unsigned)i, cur->alloc_stack[i]);
        }
      }
      append_json_event("leak", user_ptr_from_header(cur), cur);
    }
    cur = cur->next;
  }
  LeaveCriticalSection(&g_lock);

  sort_groups(groups, group_count);
  if (groups_file) {
    size_t i;
    for (i = 0; i < group_count; ++i) {
      fprintf(groups_file, "group=%zu top_frame=%p count=%lu bytes=%zu\n",
              i + 1, groups[i].top_frame, groups[i].count, groups[i].bytes);
    }
    fclose(groups_file);
  }

  if (summary) {
    fprintf(summary, "total_allocations=%lu\n", g_total_allocations);
    fprintf(summary, "live_allocations=%lu\n", g_live_allocations);
    fprintf(summary, "freed_allocations=%lu\n", g_freed_allocations);
    fprintf(summary, "quarantine_bytes=%zu\n", g_quarantine_bytes);
    fprintf(summary, "quarantine_limit_bytes=%zu\n", g_options.quarantine_bytes);
    fprintf(summary, "leak_count=%lu\n", leak_count);
    fprintf(summary, "leak_bytes=%zu\n", leak_bytes);
    fprintf(summary, "leak_groups=%zu\n", group_count);
    fprintf(summary, "errors=%lu\n", g_errors);
    fprintf(summary, "guard_errors=%lu\n", g_guard_errors);
    fprintf(summary, "invalid_free_errors=%lu\n", g_invalid_free_errors);
    fprintf(summary, "double_free_errors=%lu\n", g_double_free_errors);
    fprintf(summary, "aggressive=%d\n", g_options.aggressive);
    fprintf(summary, "validate_each_op=%d\n", g_options.validate_each_op);
    fprintf(summary, "fill_allocations=%d\n", g_options.fill_allocations);
    fprintf(summary, "fail_fast=%d\n", g_options.fail_fast);
    fprintf(summary, "aggressive_scans=%lu\n", g_aggressive_scans);
    fprintf(summary, "aggressive_scan_failures=%lu\n", g_aggressive_scan_failures);
    fprintf(summary, "oom_failures=%lu\n", g_oom_failures);
    fprintf(summary, "stack_depth=%u\n", g_options.stack_depth);
    fprintf(summary, "jsonl=%d\n", g_options.write_jsonl);
    fprintf(summary, "exe=%s\n", g_exe_path);
    fprintf(summary, "module_base=0x%llx\n", (unsigned long long)g_module_base);
    fclose(summary);
  }
  if (leaks) {
    fclose(leaks);
  }

  write_ai_report(leak_count, leak_bytes, groups, group_count);

  if ((g_options.fail_on_error && g_errors) || (g_options.fail_on_leak && leak_count)) {
    fflush(NULL);
    ExitProcess(2);
  }

  g_reporting = 0;
}
