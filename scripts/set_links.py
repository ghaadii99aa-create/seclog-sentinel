#!/usr/bin/env python3
"""Replace the YOUR-* placeholders with your real links.

Usage:
    python scripts/set_links.py --github your-username --linkedin your-handle [--app https://your-app.onrender.com]

Run it once after you create the GitHub repository. Run it again with --app after Render
gives you the live URL.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ["README.md", "render.yaml"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--github", help="Your GitHub username")
    parser.add_argument("--linkedin", help="Your LinkedIn handle (the part after linkedin.com/in/)")
    parser.add_argument("--app", help="Live URL, for example https://seclog-sentinel.onrender.com")
    args = parser.parse_args()

    if not (args.github or args.linkedin or args.app):
        parser.error("give at least one of --github, --linkedin, --app")

    if args.github and not re.fullmatch(r"[A-Za-z0-9-]{1,39}", args.github):
        parser.error("--github must be a GitHub username (letters, digits, hyphens)")
    if args.linkedin and not re.fullmatch(r"[A-Za-z0-9\-_%]{3,100}", args.linkedin):
        parser.error("--linkedin must be only the handle, not the full URL")
    if args.app:
        match = re.fullmatch(r"https://([A-Za-z0-9.-]+)/?", args.app)
        if not match:
            parser.error("--app must look like https://your-app.onrender.com")
        host = match.group(1)

    for name in FILES:
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        if args.github:
            text = text.replace("YOUR-USERNAME", args.github)
        if args.linkedin:
            text = text.replace("YOUR-LINKEDIN-HANDLE", args.linkedin)
        if args.app:
            text = text.replace("YOUR-APP.onrender.com", host)
        path.write_text(text, encoding="utf-8")
        print(f"updated {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
