# IOC Extractor

A command-line tool that pulls printable strings out of any file and flags
the ones that look like indicators of compromise (IOCs): IP addresses,
domains, URLs, email addresses, Windows file paths, registry keys, and
Bitcoin addresses.

This is usually one of the very first things an analyst does with a
suspicious file — a cheap, fast scan that often reveals a surprising amount
about what a file talks to or touches, all without running it.

## Why string extraction matters

Malware authors are often lazy (or their tooling is): hardcoded C2 server
addresses, dropped file paths, registry persistence keys, and ransom-note
Bitcoin addresses frequently sit in a binary in plain text, or as UTF-16LE
"wide" strings (the format Windows programs commonly use internally). Pulling
these out early can save hours of deeper reverse engineering.

## Features

- Extracts both ASCII and UTF-16LE strings (most `strings`-style tools only
  catch one or the other)
- Regex-matches for: IPv4 addresses, URLs, emails, domains, Windows file
  paths, registry keys, and Bitcoin addresses
- Scans a single file or an entire directory (`--recursive`)
- Optional `--json` output for feeding into other tools or scripts
- Zero external dependencies — pure Python standard library

## Setup

```bash
git clone https://github.com/Dn2z/ioc-extractor.git
cd ioc-extractor
```

That's it — no `pip install` needed, it only uses the standard library.

## Usage

```bash
python3 ioc_extractor.py path/to/file
python3 ioc_extractor.py path/to/directory --recursive
python3 ioc_extractor.py path/to/file --json
python3 ioc_extractor.py path/to/file --min-len 6   # ignore short/noisy strings
```

## Safe testing

You can test this against any file at all — it just reads bytes, never
executes anything. To see every category light up at once, make a text file
with fake indicators using addresses reserved for documentation (so nothing
here points at a real system):

```bash
cat > test_sample.txt << 'EOF'
C2 server: http://example.com/gate.php
Backup C2 IP: 203.0.113.42
Contact: baduser@example.org
Install path: C:\Users\Public\malware.exe
Persistence key: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
EOF
python3 ioc_extractor.py test_sample.txt
```

(`203.0.113.0/24` and `example.com`/`example.org` are ranges IANA reserves
specifically for documentation and testing — they're not real destinations.)

## Example output

```
test_sample.txt
============================================================

IPV4 (1)
  203.0.113.42

URL (1)
  http://example.com/gate.php

EMAIL (1)
  baduser@example.org

WINDOWS_PATH (1)
  C:\Users\Public\malware.exe

REGISTRY_KEY (1)
  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

## Extending this project

- Add a denylist/allowlist so common noisy false positives (e.g. Microsoft's
  own telemetry domains) can be filtered out
- Add IPv6 and bech32 (`bc1...`) Bitcoin address support
- Cross-reference extracted domains/IPs against a threat intel feed
  automatically
- Chain with [pe-file-analyzer](https://github.com/Dn2z/pe-file-analyzer)
  so one command handles static header analysis *and* IOC extraction

## Disclaimer

This tool is for defensive security research and learning. Always analyze
untrusted files in an isolated, offline virtual machine — never on your host
machine.

## License

MIT — see [LICENSE](LICENSE).
