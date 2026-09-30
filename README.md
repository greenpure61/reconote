# reconote

A small nmap-ish CLI recon tool for CTFs, TryHackMe/HTB rooms, and
authorized/closed lab environments. It scans a target for open ports and
annotates every finding: **what the service is**, **why it matters** from
an attacker's perspective, and **concrete next-step commands** to try.

> **Only scan systems you are authorized to test.** CTF boxes, TryHackMe/HTB
> rooms, your own lab VMs, or targets you have explicit written permission
> to assess. Scanning systems without authorization is illegal in most
> jurisdictions. This tool does not exploit anything itself -- it points you
> to the standard enumeration tools/commands for the next step.

## Install

```bash
git clone https://github.com/greenpure61/reconote.git
cd reconote
pip install -r requirements.txt
chmod +x reconote.py
```

Optional: if `nmap` is installed on your system, reconote will automatically
use it for better service/version detection (`-sV`). Without it, reconote
falls back to its own built-in multithreaded TCP connect scanner + banner
grabber -- no extra privileges or dependencies required.

## Usage

**Interactive mode** (menu-driven CLI interface):

```bash
./reconote.py
```

Walks you through setting a target, choosing a port range, picking an
engine, running the scan, and saving the report.

**Direct / scriptable mode:**

```bash
# Scan the top 100 common ports
./reconote.py 10.10.10.10 --top 100

# Scan a custom port range/list
./reconote.py 10.10.10.10 -p 22,80,443,1000-2000

# Scan everything (slow)
./reconote.py 10.10.10.10 --all-ports

# Force an engine
./reconote.py 10.10.10.10 --engine nmap
./reconote.py 10.10.10.10 --engine socket

# Save an annotated report (markdown or JSON)
./reconote.py 10.10.10.10 --top 1000 -o report.md
./reconote.py 10.10.10.10 --top 1000 -o report.json

# Skip the authorization confirmation prompt (e.g. in scripts)
./reconote.py 10.10.10.10 -y
```

## What you get

For every open port, reconote prints (and can save):

- The service name and detected banner/version
- What the service is, in plain English
- Why it's relevant to a CTF/pentest engagement
- A short list of concrete next commands (`smbclient`, `gobuster`,
  `enum4linux`, `nmap --script ...`, etc.)

The knowledge base (`kb.py`) currently covers ~40 of the most common
CTF/lab services (FTP, SSH, SMB, HTTP(S), databases, RDP/WinRM, SNMP, LDAP,
NFS, Redis, Elasticsearch, MongoDB, and more), plus a generic fallback for
anything unrecognized.

## Extending it

Add or edit entries in `kb.py` -- each one is just:

```python
PORT_NUMBER: {
    "name": "Short label",
    "what": "What the service is.",
    "why": "Why it matters for recon/CTF purposes.",
    "next": [
        "command one {target} {port}",
        "command two {target}",
    ],
},
```

`{target}` and `{port}` are filled in automatically when the report is
generated.

## Files

- `reconote.py` -- CLI entry point (interactive menu + argparse flags)
- `scanner.py` -- scan engines (socket-based connect scan, nmap XML wrapper)
- `kb.py` -- the service knowledge base
- `report.py` -- turns raw results into an annotated report (console/md/json)

## License

MIT
