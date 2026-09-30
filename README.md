# reconote

[![CI](https://github.com/greenpure61/reconote/actions/workflows/ci.yml/badge.svg)](https://github.com/greenpure61/reconote/actions/workflows/ci.yml)

A small nmap-ish CLI recon tool for CTFs, TryHackMe/HTB rooms, and
authorized/closed lab environments. It scans a target for open TCP and
UDP ports and annotates every finding: **what the service is**, **why it
matters** from an attacker's perspective, and **concrete next-step
commands** to try.

> **Only scan systems you are authorized to test.** CTF boxes, TryHackMe/HTB
> rooms, your own lab VMs, or targets you have explicit written permission
> to assess. Scanning systems without authorization is illegal in most
> jurisdictions. This tool does not exploit anything itself -- it points you
> to the standard enumeration tools/commands for the next step.

## Install

```bash
git clone https://github.com/greenpure61/reconote.git
cd reconote
pip install -e .
```

This installs a `reconote` command on your PATH. If you'd rather not
install it, `python -m reconote ...` works the same way from inside the
repo.

Optional: if `nmap` is installed on your system, reconote automatically
uses it for better TCP service/version detection (`-sV`). Without it,
reconote falls back to its own built-in multithreaded TCP connect scanner
+ banner grabber -- no extra privileges or dependencies required.

## Usage

**Interactive mode** (menu-driven CLI interface):

```bash
reconote
```

Walks you through setting a target, choosing a port range, picking an
engine, toggling UDP, running the scan, and saving the report.

**Direct / scriptable mode:**

```bash
# Scan the top 100 common TCP ports
reconote 10.10.10.10 --top 100

# Scan a custom port range/list
reconote 10.10.10.10 -p 22,80,443,1000-2000

# Scan everything (slow)
reconote 10.10.10.10 --all-ports

# Also scan common UDP ports (DNS, SNMP, NTP, NetBIOS, etc.)
reconote 10.10.10.10 --udp

# Custom UDP port list
reconote 10.10.10.10 --udp-ports 53,161,500-520

# Force an engine
reconote 10.10.10.10 --engine nmap
reconote 10.10.10.10 --engine socket

# Save an annotated report (markdown or JSON)
reconote 10.10.10.10 --top 1000 -o report.md
reconote 10.10.10.10 --top 1000 -o report.json

# Skip the authorization confirmation prompt (e.g. in scripts)
reconote 10.10.10.10 -y
```

## Scope allowlist (safety rail)

Copy [`scope.example.txt`](scope.example.txt) to `scope.txt` in the
directory you run reconote from, and list the CIDR ranges/IPs you're
actually authorized to test:

```
10.10.10.0/24
192.168.56.10
```

Once that file exists, reconote refuses to scan anything outside it:

```
$ reconote 8.8.8.8
Blocked by scope check: 8.8.8.8 is not covered by the scope file
(scope.txt). Allowed ranges: 10.10.10.0/24, 192.168.56.10/32. ...
```

No scope file present = no restriction (fine for casual single-box CTF
use). Point at a specific file with `--scope path/to/file`, or bypass
entirely with `--no-scope-check` (not recommended -- the whole point is
to catch you before you scan the wrong host).

`scope.txt` is gitignored so a real engagement's target list never ends
up committed.

## What you get

For every open port, reconote prints (and can save):

- The protocol (TCP/UDP), state, service name, and detected banner/version
- What the service is, in plain English
- Why it's relevant to a CTF/pentest engagement
- A short list of concrete next commands (`smbclient`, `gobuster`,
  `enum4linux`, `nmap --script ...`, etc.)

UDP results can show `open` (got a real protocol response -- reconote
sends proper DNS/NTP/SNMP probes for those services) or `open|filtered`
(no response, which is inherently ambiguous for UDP -- could be open and
silent, could be firewalled). Both are reported; the report flags which
is which.

The knowledge base covers ~40 of the most common CTF/lab services (FTP,
SSH, SMB, HTTP(S), databases, RDP/WinRM, SNMP, LDAP, NFS, Redis,
Elasticsearch, MongoDB, DNS, NTP, TFTP, and more), plus a generic fallback
for anything unrecognized.

## Extending the knowledge base

The knowledge base lives in
[`src/reconote/data/services.yaml`](src/reconote/data/services.yaml) --
plain YAML, no code changes needed. Add an entry like:

```yaml
"1234":
  name: Some Service
  what: What it is.
  why: Why it matters for recon/CTF purposes.
  next:
    - "command one {target} {port}"
    - "command two {target}"
```

`{target}` and `{port}` are filled in automatically when the report is
generated.

## Development

```bash
pip install -e ".[dev]"
pytest -v
ruff check src tests
```

CI runs the same lint + test suite on Python 3.10-3.12 on every push/PR.

## Project layout

- `src/reconote/cli.py` -- CLI entry point (interactive menu + argparse flags)
- `src/reconote/scanner.py` -- TCP scan engines (socket connect scan, nmap XML wrapper)
- `src/reconote/udp_scanner.py` -- UDP scan engine with protocol-aware probes
- `src/reconote/kb.py` -- knowledge base loader (reads `data/services.yaml`)
- `src/reconote/scope.py` -- authorized-target allowlist enforcement
- `src/reconote/report.py` -- turns raw results into an annotated report (console/md/json)
- `tests/` -- pytest suite
- `.github/workflows/ci.yml` -- lint + test on every push/PR

## License

MIT
