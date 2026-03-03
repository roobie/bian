#!/usr/bin/env python3
"""
agh_search_replace.py

Safe, review-first search-and-replace helper intended to assist the per-test
refactors in this repository. Designed to be used alongside `agh` sessions.

The point is: do not make broad refactorings using `sed` and similar.

Features:
- Walk files under a path (default: repo root) and find text files with given
  extensions.
- Apply a regex search/replace with support for backreferences.
- Preview diffs for all candidate files before applying.
- Interactive per-file confirmation mode.
- Safety checks: ensure git working tree is clean by default.
- Produces a patch file (optional) so changes can be reviewed and applied with
  standard tools.

Usage examples:

# Dry-run preview of matches under src/ for pattern -> replacement
./tools/agh_search_replace.py --path src --pattern "defer if \(desc\..+\) allocator.free\(desc\..+\);" \
  --replace "defer root.freeBinaryDescription(allocator, {var})" --preview

# Apply interactively (prompt per-file), only for .zig files
./tools/agh_search_replace.py --path src --pattern "old" --replace "new" \
  --interactive --extensions .zig

# Apply non-interactively (dangerous). Use with --force to allow dirty git tree.
./tools/agh_search_replace.py --path src --pattern "old" --replace "new" --apply --force

"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple
import difflib
import subprocess

TEXT_FILE_SAMPLE_BYTES = 4096
DEFAULT_EXTS = [
    ".zig", ".c", ".h", ".cpp", ".hpp", ".py", ".rs", ".md", ".txt", ".json", ".toml", ".yaml", ".yml"
]


def is_text_file(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            sample = f.read(TEXT_FILE_SAMPLE_BYTES)
            if not sample:
                return True
            # If there's a NUL byte, treat as binary
            if b"\x00" in sample:
                return False
            # Otherwise heuristic: try to decode as utf-8
            try:
                sample.decode("utf-8")
                return True
            except Exception:
                return False
    except Exception:
        return False


def git_is_clean() -> bool:
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"], stderr=subprocess.DEVNULL)
        return len(out.strip()) == 0
    except Exception:
        return False


def find_candidate_files(base: Path, exts: List[str]) -> List[Path]:
    matches: List[Path] = []
    for p in base.rglob("*"):
        if p.is_file():
            if exts and p.suffix not in exts:
                continue
            if is_text_file(p):
                matches.append(p)
    return matches


def apply_regex_to_text(text: str, pattern: re.Pattern, repl: str) -> Tuple[str, int]:
    new_text, n = pattern.subn(repl, text)
    return new_text, n


def unified_diff(original: str, modified: str, filename: str) -> str:
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    ud = difflib.unified_diff(orig_lines, mod_lines, fromfile=filename, tofile=filename + " (modified)")
    return "".join(ud)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Safe search/replace helper for agent refactors")
    ap.add_argument("--path", default=".", help="Base path to search (default: repo root)")
    ap.add_argument("--pattern", required=True, help="Regex search pattern")
    ap.add_argument("--replace", required=True, help="Replacement string (Python re syntax, use \\1 etc for groups)")
    ap.add_argument("--preview", action="store_true", help="Only show diffs; do not modify files")
    ap.add_argument("--apply", action="store_true", help="Apply changes to files (unsafe unless reviewed)")
    ap.add_argument("--interactive", action="store_true", help="Ask for confirmation per-file when applying")
    ap.add_argument("--extensions", default=",".join(DEFAULT_EXTS), help=f"Comma-separated list of extensions to include (default: {','.join(DEFAULT_EXTS)})")
    ap.add_argument("--patch-file", help="Write an aggregated patch file with all diffs")
    ap.add_argument("--force", action="store_true", help="Allow running when git working tree is dirty")
    ap.add_argument("--preview-only-matching", action="store_true", help="When previewing, only print filenames that would change")
    args = ap.parse_args(argv)

    base = Path(args.path).resolve()
    if not base.exists():
        print(f"Base path does not exist: {base}")
        return 2

    exts = [e if e.startswith(".") else "." + e for e in args.extensions.split(",") if e.strip()]

    if not args.force and args.apply:
        if not git_is_clean():
            print("Git working tree is dirty. Commit or use --force to override.")
            return 3

    try:
        pattern = re.compile(args.pattern)
    except re.error as e:
        print(f"Invalid regex pattern: {e}")
        return 2

    files = find_candidate_files(base, exts)
    if not files:
        print("No candidate files found")
        return 0

    total_matches = 0
    file_diffs = []
    file_changes = []  # (Path, original_text, new_text, nsubs)

    for p in files:
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            # skip files that cannot be decoded as utf-8
            continue
        new_text, n = apply_regex_to_text(text, pattern, args.replace)
        if n > 0:
            total_matches += n
            diff = unified_diff(text, new_text, str(p))
            file_diffs.append((p, diff))
            file_changes.append((p, text, new_text, n))

    if not file_changes:
        print("No matches found for the given pattern")
        return 0

    print(f"Found {total_matches} replacements across {len(file_changes)} files")

    if args.preview:
        if args.preview_only_matching:
            for p, _, _, n in file_changes:
                print(f"{p} -> {n} replacements")
        else:
            for p, diff in file_diffs:
                print("= " + str(p))
                print(diff)
        if args.patch_file:
            with open(args.patch_file, "w", encoding="utf-8") as f:
                for _, diff in file_diffs:
                    f.write(diff)
            print(f"Wrote patch file: {args.patch_file}")
        return 0

    # If we reach here, user intends to apply changes
    if not args.apply:
        print("No --apply provided. Use --preview to inspect changes or --apply to make them.")
        return 0

    # Apply changes
    for p, orig, new, n in file_changes:
        apply_file = True
        if args.interactive:
            print("File:", p)
            print(f"Replacements: {n}")
            print(unified_diff(orig, new, str(p)))
            resp = input("Apply changes to this file? [y/N] ").strip().lower()
            apply_file = resp == "y"
        if apply_file:
            backup = p.with_suffix(p.suffix + ".agh.bak")
            try:
                # create a small backup in case of mistakes
                backup.write_text(orig, encoding="utf-8")
                p.write_text(new, encoding="utf-8")
                print(f"Applied changes to {p} (backup: {backup.name})")
            except Exception as e:
                print(f"Failed to write {p}: {e}")

    # Optionally write a combined patch file
    if args.patch_file:
        with open(args.patch_file, "w", encoding="utf-8") as f:
            for _, diff in file_diffs:
                f.write(diff)
        print(f"Wrote patch file: {args.patch_file}")

    print("Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
