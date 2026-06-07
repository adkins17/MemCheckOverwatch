# AI Triage Playbook

Use this when reviewing `*-ai-symbolized.md`, `*-events.jsonl`, and raw
memcheck reports.

## Priority Order

1. Guard corruption.
2. Double-free or use-after-free.
3. Invalid free.
4. Unsuppressed leak groups by total bytes.
5. Unsuppressed leak groups by allocation count.

## Questions For The AI Assistant

- What exact source lines are implicated by the first error?
- Did AI Overwatch flag missing evidence, symbolization gaps, over-broad
  suppressions, or counter mismatches?
- Is the reported allocation site the root cause or only where the damaged
  allocation was created?
- Is there a matching free stack?
- Does ownership transfer across a function boundary?
- Could this be CRT/library startup noise that needs suppression instead of a
  source fix?
- What is the smallest code path to reproduce this allocation?

## Good Final Answer Shape

For each finding, include:

- Severity.
- Evidence file.
- Allocation stack.
- Free stack, when present.
- Why the lifetime looks wrong.
- Concrete source file/function to inspect next.
- Confidence.
- Overwatch caveats that limit confidence.

## Useful Commands

```sh
make analyze-sample
python analyze_memcheck.py --prefix memcheck
python analyze_memcheck.py --prefix pennmush --suppressions pennmush-suppressions.txt
```

## PennMUSH Notes

For PennMUSH diagnostic builds, prefer a separate executable such as
`netmush-memcheck.exe`. Do not replace the production `netmush.exe`.

Recommended environment:

```sh
MEMCHECK_REPORT_PREFIX=pennmush
MEMCHECK_STACK_DEPTH=40
MEMCHECK_QUARANTINE_MB=128
MEMCHECK_JSONL=1
MEMCHECK_AI_REPORT=1
```

For maximum bug-finding during short repros:

```sh
MEMCHECK_AGGRESSIVE=1
MEMCHECK_FAIL_FAST=0
```

Use `MEMCHECK_FAIL_FAST=1` only when a debugger is attached or when stopping on
the first fault is more useful than a full report.
