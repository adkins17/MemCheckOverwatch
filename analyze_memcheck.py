#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


def parse_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.startswith("0x"):
        return int(text, 16)
    return int(text, 16) if re.fullmatch(r"[0-9a-fA-F]+", text) else int(text)


def read_summary(path):
    data = {}
    if not path.exists():
        return data
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
    return data


def read_events(path):
    events = []
    if not path.exists():
        return events
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"kind": "malformed-jsonl", "raw": line})
    return events


def read_suppressions(paths):
    patterns = []
    for path in paths:
        if not path or not path.exists():
            continue
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    return patterns


def image_base(exe, objdump):
    try:
        result = subprocess.run(
            [objdump, "-p", str(exe)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception:
        return 0x140000000
    match = re.search(r"ImageBase\s+([0-9a-fA-F]+)", result.stdout)
    return int(match.group(1), 16) if match else 0x140000000


def symbolize_many(exe, addrs, runtime_base, preferred_base, addr2line):
    unique = []
    seen = set()
    for addr in addrs:
        if addr is None or addr in seen:
            continue
        seen.add(addr)
        unique.append(addr)
    if not unique:
        return {}

    translated = [hex(addr - runtime_base + preferred_base) for addr in unique]
    try:
        result = subprocess.run(
            [addr2line, "-f", "-C", "-e", str(exe), *translated],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception as exc:
        return {addr: f"<symbolization failed: {exc}>" for addr in unique}

    lines = result.stdout.splitlines()
    symbols = {}
    for index, addr in enumerate(unique):
        fn = lines[index * 2].strip() if index * 2 < len(lines) else "??"
        loc = lines[index * 2 + 1].strip() if index * 2 + 1 < len(lines) else "??:0"
        symbols[addr] = f"{fn} at {loc}"
    return symbols


def stack_addresses(events):
    for event in events:
        for key in ("alloc_stack", "free_stack"):
            for addr in event.get(key, []) or []:
                try:
                    yield parse_int(addr)
                except Exception:
                    continue


def first_stack_symbol(event, symbols):
    for addr_text in event.get("alloc_stack", []) or []:
        addr = parse_int(addr_text)
        symbol = symbols.get(addr)
        if symbol:
            return symbol
    return "<no stack>"


def is_suppressed(site, suppressions):
    return any(pattern in site for pattern in suppressions)


def int_summary(summary, key, default=0):
    try:
        return int(summary.get(key, default))
    except Exception:
        return default


def build_overwatch(summary, events, symbols, leak_groups, suppressed_leak_groups, error_events):
    notes = []
    total_events = len(events)
    alloc_events = sum(1 for event in events if event.get("kind") == "alloc")
    free_events = sum(1 for event in events if event.get("kind") == "free")
    leak_count = int_summary(summary, "leak_count")
    errors = int_summary(summary, "errors")
    aggressive = int_summary(summary, "aggressive")
    aggressive_scans = int_summary(summary, "aggressive_scans")
    scan_failures = int_summary(summary, "aggressive_scan_failures")
    live_allocations = int_summary(summary, "live_allocations")
    freed_allocations = int_summary(summary, "freed_allocations")
    total_allocations = int_summary(summary, "total_allocations")
    unsymbolized = sum(1 for symbol in symbols.values() if symbol.startswith("??"))
    symbol_count = len(symbols)
    suppressed_bytes = sum(stats["bytes"] for stats in suppressed_leak_groups.values())
    unsuppressed_bytes = sum(stats["bytes"] for stats in leak_groups.values())

    if not events:
        notes.append(("high", "No JSONL events were read. The raw report may be missing, truncated, or generated with MEMCHECK_JSONL=0."))
    if summary and total_allocations and alloc_events and total_allocations != alloc_events:
        notes.append(("medium", f"Allocation counter mismatch: summary total_allocations={total_allocations}, JSON alloc events={alloc_events}."))
    if summary and live_allocations and leak_count and live_allocations != leak_count:
        notes.append(("medium", f"Live allocation count differs from leak count: live={live_allocations}, leaks={leak_count}."))
    if total_allocations and freed_allocations and freed_allocations > total_allocations:
        notes.append(("high", f"Freed allocation count exceeds total allocations: freed={freed_allocations}, total={total_allocations}."))
    if errors and not error_events:
        notes.append(("high", f"Summary reports {errors} errors, but no error events were parsed. Check report prefix and JSONL integrity."))
    if error_events and not aggressive:
        notes.append(("medium", "Errors exist and aggressive mode was off. Re-run with MEMCHECK_AGGRESSIVE=1 to catch nearby corruption earlier."))
    if aggressive and aggressive_scans == 0:
        notes.append(("medium", "Aggressive mode is enabled, but no aggressive scans were recorded. The runtime may have exited before wrapped operations ran."))
    if scan_failures:
        notes.append(("high", f"Aggressive scans found corruption {scan_failures} time(s). Prefer the earliest error event over later leak noise."))
    if symbol_count and unsymbolized / max(symbol_count, 1) > 0.4:
        notes.append(("medium", f"More than 40% of stack addresses were not symbolized ({unsymbolized}/{symbol_count}). Check debug symbols and executable path."))
    if suppressed_bytes > unsuppressed_bytes and suppressed_bytes > 0:
        notes.append(("low", f"Suppressed leak bytes ({suppressed_bytes}) exceed unsuppressed leak bytes ({unsuppressed_bytes}). Review suppressions before trusting a clean-looking report."))
    if leak_count and not leak_groups and suppressed_leak_groups:
        notes.append(("medium", "All leak groups were suppressed. This may be valid CRT noise, but review suppression patterns before closing the issue."))
    if free_events == 0 and alloc_events > 10:
        notes.append(("medium", "Allocations were recorded but no frees were observed. This can mean the run ended too early or wrappers missed deallocation APIs."))
    if any(event.get("kind") == "invalid-pointer" for event in error_events):
        notes.append(("high", "Invalid pointer frees are present. This often indicates ownership confusion or freeing memory allocated by a different allocator."))
    if any(event.get("kind") == "rear-guard-corruption" for event in error_events):
        notes.append(("high", "Rear guard corruption usually means a write past the end of an allocation. Inspect string copies, buffer lengths, and terminators."))
    if any(event.get("kind") == "front-guard-corruption" for event in error_events):
        notes.append(("high", "Front guard corruption usually means a write before the start of an allocation or pointer arithmetic underflow."))
    if any(event.get("kind") == "double-free-or-use-after-free" for event in error_events):
        notes.append(("high", "Double-free/use-after-free is present. Compare allocation and free stacks and look for duplicated ownership cleanup paths."))
    if not notes:
        notes.append(("info", "No meta-level inconsistencies detected by overwatch heuristics. Continue with normal finding triage."))
    return notes


def main():
    parser = argparse.ArgumentParser(description="Analyze standalone memcheck reports.")
    parser.add_argument("--prefix", default="memcheck", help="Report prefix, such as memcheck or sample.")
    parser.add_argument("--addr2line", default=os.environ.get("ADDR2LINE", "addr2line"))
    parser.add_argument("--objdump", default=os.environ.get("OBJDUMP", "objdump"))
    parser.add_argument("--out", default=None, help="Output markdown path.")
    parser.add_argument("--suppressions", default=None, help="Suppression file. Defaults to <prefix>-suppressions.txt then memcheck-suppressions.txt.")
    args = parser.parse_args()

    prefix = Path(args.prefix)
    summary = read_summary(Path(f"{args.prefix}-summary.txt"))
    events = read_events(Path(f"{args.prefix}-events.jsonl"))
    suppression_paths = []
    if args.suppressions:
        suppression_paths.append(Path(args.suppressions))
    suppression_paths.extend([Path(f"{args.prefix}-suppressions.txt"), Path("memcheck-suppressions.txt")])
    suppressions = read_suppressions(suppression_paths)
    exe = Path(summary.get("exe") or "")
    runtime_base = parse_int(summary.get("module_base")) or 0
    preferred_base = image_base(exe, args.objdump) if exe.exists() else 0

    symbols = symbolize_many(
        exe,
        list(stack_addresses(events)),
        runtime_base,
        preferred_base,
        args.addr2line,
    ) if exe.exists() and runtime_base else {}

    kind_counts = Counter(event.get("kind", "unknown") for event in events)
    leak_groups = defaultdict(lambda: {"count": 0, "bytes": 0})
    suppressed_leak_groups = defaultdict(lambda: {"count": 0, "bytes": 0})
    for event in events:
        if event.get("kind") == "leak":
            site = first_stack_symbol(event, symbols)
            target = suppressed_leak_groups if is_suppressed(site, suppressions) else leak_groups
            target[site]["count"] += 1
            target[site]["bytes"] += int(event.get("size", 0))

    error_events = [
        event for event in events
        if event.get("kind") not in ("alloc", "free", "leak")
    ]
    overwatch_notes = build_overwatch(summary, events, symbols, leak_groups, suppressed_leak_groups, error_events)

    out_path = Path(args.out or f"{args.prefix}-ai-symbolized.md")
    with out_path.open("w", encoding="utf-8") as out:
        out.write("# Symbolized Memcheck AI Report\n\n")
        out.write("## Summary\n\n")
        for key in (
            "errors", "guard_errors", "double_free_errors", "invalid_free_errors",
            "leak_count", "leak_bytes", "leak_groups", "total_allocations",
            "freed_allocations", "quarantine_bytes", "aggressive",
            "validate_each_op", "fill_allocations", "fail_fast",
            "aggressive_scans", "aggressive_scan_failures",
        ):
            out.write(f"- {key}: {summary.get(key, 'unknown')}\n")
        out.write(f"- executable: `{exe}`\n")
        out.write(f"- runtime module base: `{summary.get('module_base', 'unknown')}`\n")
        out.write(f"- preferred image base: `0x{preferred_base:x}`\n\n")
        out.write(f"- suppression patterns loaded: {len(suppressions)}\n\n")

        out.write("## Event Counts\n\n")
        for kind, count in kind_counts.most_common():
            out.write(f"- {kind}: {count}\n")

        out.write("\n## Errors To Investigate First\n\n")
        if not error_events:
            out.write("No errors recorded.\n")
        for event in error_events[:30]:
            out.write(f"- {event.get('kind')} ptr={event.get('ptr')} seq={event.get('seq')} size={event.get('size')}\n")
            out.write(f"  - allocation: {first_stack_symbol(event, symbols)}\n")
            free_stack = event.get("free_stack") or []
            if free_stack:
                addr = parse_int(free_stack[0])
                out.write(f"  - free: {symbols.get(addr, '<unknown>')}\n")

        out.write("\n## Leak Groups By Symbol\n\n")
        if not leak_groups:
            out.write("No leaks recorded.\n")
        for site, stats in sorted(leak_groups.items(), key=lambda item: item[1]["bytes"], reverse=True)[:30]:
            out.write(f"- {stats['bytes']} bytes in {stats['count']} allocation(s): {site}\n")

        out.write("\n## Suppressed Leak Groups\n\n")
        if not suppressed_leak_groups:
            out.write("No suppressed leaks.\n")
        for site, stats in sorted(suppressed_leak_groups.items(), key=lambda item: item[1]["bytes"], reverse=True)[:30]:
            out.write(f"- {stats['bytes']} bytes in {stats['count']} allocation(s): {site}\n")

        out.write("\n## AI Overwatch\n\n")
        for severity, note in overwatch_notes:
            out.write(f"- [{severity}] {note}\n")

        out.write("\n## AI Triage Instructions\n\n")
        out.write("Prioritize fixes in this order: guard corruption, double-free/use-after-free, invalid frees, then leak groups by bytes. ")
        out.write("Use the symbolized locations above as starting points, but confirm ownership and allocation lifetime in source before changing code.\n")

    print(out_path)


if __name__ == "__main__":
    main()
