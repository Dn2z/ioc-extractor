#!/usr/bin/env python3
"""
IOC (Indicators of Compromise) Extractor
------------------------------------------
Extracts printable ASCII and UTF-16LE strings from a file (or a whole
directory of files) and flags anything that looks like a network or
filesystem indicator: IP addresses, domains, URLs, email addresses,
Windows file paths, registry keys, and Bitcoin addresses.

This is one of the first things analysts do when triaging a suspicious
binary - a quick, low-effort scan that often reveals a lot about what a
file talks to or touches, without ever running it.

Usage:
    python3 ioc_extractor.py path/to/file
    python3 ioc_extractor.py path/to/directory --recursive
    python3 ioc_extractor.py path/to/file --json
"""

import argparse
import json
import re
import sys
from pathlib import Path

MIN_STRING_LEN_DEFAULT = 4

COMMON_TLDS = [
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "biz",
    "info", "name", "mobi", "ru", "cn", "uk", "de", "fr", "jp", "br",
    "in", "au", "ca", "us", "xyz", "top", "club", "online", "site",
    "tech", "click", "link", "icu", "cc", "tv", "me", "ws", "pw", "su",
    "one", "live", "world", "life", "store", "vip", "work", "fun", "buzz",
    "app", "dev", "cloud",
]

IOC_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b"
    ),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:"
        + "|".join(COMMON_TLDS)
        + r")\b",
        re.IGNORECASE,
    ),
    "windows_path": re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+"),
    "registry_key": re.compile(
        r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
        r"HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU)\\[^\s\"']+"
    ),
    "bitcoin_address": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
}


def extract_ascii_strings(data: bytes, min_len: int) -> list:
    """Extract runs of printable ASCII bytes, like the classic 'strings' tool."""
    pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_len)
    return [m.decode("ascii") for m in pattern.findall(data)]


def extract_wide_strings(data: bytes, min_len: int) -> list:
    """Extract UTF-16LE ('wide') strings, common inside Windows binaries."""
    pattern = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len)
    return [m.decode("utf-16-le") for m in pattern.findall(data)]


def find_iocs(strings: list) -> dict:
    """Run every IOC regex against every extracted string, deduplicating hits."""
    results = {key: set() for key in IOC_PATTERNS}
    for s in strings:
        for name, pattern in IOC_PATTERNS.items():
            for match in pattern.findall(s):
                results[name].add(match)
    return {k: sorted(v) for k, v in results.items() if v}


def analyze_file(filepath: Path, min_len: int) -> dict:
    data = filepath.read_bytes()
    strings = extract_ascii_strings(data, min_len) + extract_wide_strings(data, min_len)
    return find_iocs(strings)


def print_report(filepath: Path, iocs: dict) -> None:
    print(f"\n{filepath}")
    print("=" * 60)
    if not iocs:
        print("No indicators found.")
        return
    for category, values in iocs.items():
        print(f"\n{category.upper()} ({len(values)})")
        for v in values:
            print(f"  {v}")


def gather_files(path: Path, recursive: bool) -> list:
    if path.is_file():
        return [path]
    if recursive:
        return [p for p in path.rglob("*") if p.is_file()]
    return [p for p in path.iterdir() if p.is_file()]


def main():
    parser = argparse.ArgumentParser(
        description="Extract indicators of compromise (IPs, domains, URLs, "
        "paths, registry keys, BTC addresses) from a file or directory."
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "-r", "--recursive", action="store_true", help="Scan directories recursively"
    )
    parser.add_argument(
        "--min-len",
        type=int,
        default=MIN_STRING_LEN_DEFAULT,
        help=f"Minimum string length to consider (default: {MIN_STRING_LEN_DEFAULT})",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"Error: '{target}' does not exist.")
        sys.exit(1)

    files = gather_files(target, args.recursive)
    if not files:
        print("No files found to scan.")
        sys.exit(0)

    all_results = {}
    for f in files:
        try:
            iocs = analyze_file(f, args.min_len)
        except (OSError, PermissionError) as e:
            print(f"Skipping {f}: {e}", file=sys.stderr)
            continue
        if iocs:
            all_results[str(f)] = iocs

    if args.json:
        print(json.dumps(all_results, indent=2))
        return

    if not all_results:
        print("No indicators found in any scanned file.")
        return

    for f, iocs in all_results.items():
        print_report(Path(f), iocs)


if __name__ == "__main__":
    main()
