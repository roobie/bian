#!/usr/bin/env python3
"""
Simple helper to append an entry to a chronicle markdown file.

Usage examples:
  # Append inline message
  tools/append_chronicle.py --file chronicles/refactor-2026-02-28-reset-and-common.md \
      --title "moved foo to common" --body "Moved foo and bar into common.zig"

  # Read body from stdin (useful for multi-line message)
  echo "Detailed notes..." | tools/append_chronicle.py -f chronicles/my.md -t "notes"

Behavior:
- Creates the target file if it doesn't exist.
- Appends an entry with an ISO-8601 timestamp and the provided title and body.
- Adds a trailing separator ("---") for readability.

This script intentionally avoids external deps and uses only the Python stdlib.
"""

import argparse
import datetime
import sys
from pathlib import Path


def make_entry(title: str, body: str, author: str | None = None) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).astimezone()
    # Format like: ## 2026-02-28 14:32:10+01:00 — Title
    ts = now.isoformat(sep=' ', timespec='seconds')
    header = f"## {ts} — {title}\n\n"
    author_line = f"*by {author}*\n\n" if author else ""
    body_text = body.rstrip() + "\n\n"
    sep = "---\n\n"
    return header + author_line + body_text + sep


def main(argv=None):
    p = argparse.ArgumentParser(description="Append an entry to a chronicle markdown file")
    p.add_argument("-f", "--file", type=Path, required=True, help="Path to chronicle markdown file (will be created if missing)")
    p.add_argument("-t", "--title", required=True, help="Short title for the chronicle entry")
    p.add_argument("-b", "--body", help="Body text for the entry. If omitted, read from STDIN")
    p.add_argument("-a", "--author", help="Optional author name to include")
    args = p.parse_args(argv)

    if args.body:
        body = args.body
    else:
        if sys.stdin.isatty():
            print("Reading entry body from stdin. End input with EOF (Ctrl-D on *nix).", file=sys.stderr)
        body = sys.stdin.read()
        if not body:
            print("Error: no body provided (pass --body or pipe text to stdin)", file=sys.stderr)
            return 2

    entry = make_entry(args.title, body, args.author)

    # Ensure parent dir exists
    args.file.parent.mkdir(parents=True, exist_ok=True)

    # Append in UTF-8
    mode = 'a' if args.file.exists() else 'w'
    with args.file.open(mode, encoding='utf-8') as fh:
        fh.write(entry)

    print(f"Appended entry to {args.file}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
