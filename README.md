# MemCheck Overwatch

MemCheck Overwatch is a non-injecting Windows-native memory checker for MinGW
diagnostic builds.

It is designed to be linked into diagnostic builds of native programs.
For MinGW targets, use linker wrapping so allocation calls are routed through
the checker runtime:

```sh
gcc -g -O0 target.c memcheck_runtime.c \
  -Wl,--wrap=malloc \
  -Wl,--wrap=calloc \
  -Wl,--wrap=realloc \
  -Wl,--wrap=free \
  -Wl,--wrap=_strdup \
  -o target-memcheck.exe
```

This does not attach to or inject into a running process. The target opts into
diagnostics by linking this runtime.

The AI-assist layer turns raw allocation evidence into a symbolized markdown
report with an **AI Overwatch** section that flags meta-level issues like
missing evidence, counter mismatches, broad suppressions, and whether aggressive
mode should be rerun.

Reports are written beside the executable:

- `memcheck-summary.txt`
- `memcheck-leaks.txt`
- `memcheck-errors.txt`
- `memcheck-leak-groups.txt`
- `memcheck-events.jsonl`
- `memcheck-ai-report.md`

Useful environment variables:

- `MEMCHECK_REPORT_PREFIX=sample`
- `MEMCHECK_STACK_DEPTH=32`
- `MEMCHECK_QUARANTINE_MB=64`
- `MEMCHECK_JSONL=1`
- `MEMCHECK_AI_REPORT=1`
- `MEMCHECK_FAIL_ON_ERROR=1`
- `MEMCHECK_FAIL_ON_LEAK=1`
- `MEMCHECK_AGGRESSIVE=1`
- `MEMCHECK_VALIDATE_EACH_OP=1`
- `MEMCHECK_FILL_ALLOCATIONS=1`
- `MEMCHECK_FAIL_FAST=1`

`MEMCHECK_AGGRESSIVE=1` is a preset for slower but sharper checking:

- validates all live and quarantined guards on every allocation/free
- fills newly allocated memory with `0xCC`
- raises default stack depth to 48
- raises default quarantine to 256 MB

`MEMCHECK_FAIL_FAST=1` calls `DebugBreak()` and exits on the first detected
checker error.

To generate a symbolized AI report for the sample:

```sh
make analyze-sample
```

The analyzer converts ASLR runtime addresses back to the executable image base
and calls `addr2line`.

Suppressions are substring matches, one per line, in `memcheck-suppressions.txt`
or `<prefix>-suppressions.txt`. Suppressed leaks remain in raw reports but are
moved out of the primary AI triage list.

The symbolized report includes an **AI Overwatch** section. It checks for
meta-level issues such as missing JSONL evidence, counter mismatches,
symbolization gaps, broad suppressions, and whether aggressive mode should be
rerun.

For review workflow guidance, see `AI_TRIAGE_PLAYBOOK.md`.
