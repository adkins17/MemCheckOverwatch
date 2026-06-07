CC ?= gcc
CFLAGS ?= -g -O0 -Wall -Wextra
WRAP_FLAGS = -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free -Wl,--wrap=_strdup

.PHONY: all clean

all: sample_leak.exe

sample_leak.exe: sample_leak.c memcheck_runtime.c memcheck_runtime.h
	$(CC) $(CFLAGS) sample_leak.c memcheck_runtime.c $(WRAP_FLAGS) -o $@

clean:
	rm -f sample_leak.exe
	rm -f memcheck-summary.txt memcheck-errors.txt memcheck-leaks.txt memcheck-leak-groups.txt memcheck-events.jsonl memcheck-ai-report.md memcheck-ai-symbolized.md
	rm -f sample-summary.txt sample-errors.txt sample-leaks.txt sample-leak-groups.txt sample-events.jsonl sample-ai-report.md sample-ai-symbolized.md

analyze-sample: sample_leak.exe
	MEMCHECK_REPORT_PREFIX=sample ./sample_leak.exe
	python analyze_memcheck.py --prefix sample
