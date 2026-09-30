#!/usr/bin/env python3
"""
reconote -- a small nmap-ish CLI recon tool for CTFs, TryHackMe, and
authorized/closed lab environments.

It scans a target for open ports, then annotates each finding with a
plain-English explanation of the service and concrete next-step
enumeration commands -- so you get "here's what's open, here's what
it means, here's what to try next" in one place.

ONLY use this against systems you are authorized to test
(CTF boxes, TryHackMe/HTB rooms, your own lab VMs, or targets you have
explicit written permission to assess). Scanning systems without
authorization is illegal in most jurisdictions.

Usage:
  Interactive:   ./reconote.py
  Direct scan:   ./reconote.py 10.10.10.10 --top 100
  Custom ports:  ./reconote.py scanme.example.com -p 1-1024
  Save report:   ./reconote.py 10.10.10.10 --top 100 -o report.md
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt

import report as report_mod
import scanner

console = Console()

BANNER = r"""
[bold cyan] ____                            _       [/bold cyan]
[bold cyan]|  _ \ ___  ___ ___  _ __   ___ | |_ ___ [/bold cyan]
[bold cyan]| |_) / _ \/ __/ _ \| '_ \ / _ \| __/ _ \[/bold cyan]
[bold cyan]|  _ <  __/ (_| (_) | | | | (_) | ||  __/[/bold cyan]
[bold cyan]|_| \_\___|\___\___/|_| |_|\___/ \__\___|[/bold cyan]
[dim]scan it. understand it. know what's next.[/dim]
"""

AUTH_NOTICE = (
    "[yellow]Only scan systems you are authorized to test "
    "(CTF/TryHackMe/HTB boxes, your own lab VMs, or targets you have "
    "explicit written permission for).[/yellow]"
)


def run_scan(target: str, ports: list[int], engine: str, timeout: float, threads: int) -> dict:
    resolved = scanner.resolve_target(target)
    used_engine = engine

    if engine == "auto":
        used_engine = "nmap" if scanner.nmap_available() else "socket"

    if used_engine == "nmap" and not scanner.nmap_available():
        console.print("[yellow]nmap not found on this system, falling back to the built-in scanner.[/yellow]")
        used_engine = "socket"

    console.print(f"[dim]Scanning {target} ({resolved}) -- {len(ports)} ports -- engine: {used_engine}[/dim]")

    if used_engine == "nmap":
        raw = scanner.nmap_scan(resolved, ports)
    else:
        with console.status(f"[cyan]Scanning...[/cyan]") as status:
            def progress(done, total):
                status.update(f"[cyan]Scanning... {done}/{total} ports checked[/cyan]")
            raw = scanner.socket_scan(resolved, ports, timeout=timeout, threads=threads, progress_cb=progress)

    return report_mod.annotate(target, raw, used_engine)


def cmd_scan_and_show(target: str, ports: list[int], engine: str, timeout: float,
                       threads: int, out_path: str | None) -> dict:
    rpt = run_scan(target, ports, engine, timeout, threads)
    report_mod.render_console(rpt, console)
    if out_path:
        report_mod.save_report(rpt, out_path)
        console.print(f"\n[green]Report saved to {out_path}[/green]")
    return rpt


def interactive_menu() -> None:
    console.print(BANNER)
    console.print(Panel(AUTH_NOTICE, border_style="red"))

    state = {
        "target": "",
        "port_spec": "top100",
        "engine": "auto",
        "timeout": 1.0,
        "threads": 100,
    }
    last_report: dict | None = None

    while True:
        console.print()
        console.print("[bold]reconote menu[/bold]")
        console.print(f"  1) Set target            [dim](current: {state['target'] or 'not set'})[/dim]")
        console.print(f"  2) Set ports             [dim](current: {state['port_spec']})[/dim]")
        console.print(f"  3) Set engine            [dim](current: {state['engine']})[/dim]")
        console.print(f"  4) Run scan")
        console.print(f"  5) Save last report")
        console.print(f"  6) Quit")
        choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4", "5", "6"], default="4")

        if choice == "1":
            state["target"] = Prompt.ask("Target (IP or hostname)").strip()
        elif choice == "2":
            console.print("Presets: top100, top1000, all, or a custom spec like 22,80,1000-2000")
            state["port_spec"] = Prompt.ask("Ports", default=state["port_spec"]).strip()
        elif choice == "3":
            state["engine"] = Prompt.ask("Engine", choices=["auto", "socket", "nmap"], default=state["engine"])
        elif choice == "4":
            if not state["target"]:
                console.print("[red]Set a target first (option 1).[/red]")
                continue
            ports = resolve_port_spec(state["port_spec"])
            if not ports:
                console.print("[red]Couldn't parse that port spec.[/red]")
                continue
            if not Confirm.ask(
                f"Confirm: you are authorized to scan '{state['target']}'?", default=True
            ):
                console.print("[yellow]Skipped -- not authorized.[/yellow]")
                continue
            last_report = cmd_scan_and_show(
                state["target"], ports, state["engine"], state["timeout"], state["threads"], None
            )
        elif choice == "5":
            if not last_report:
                console.print("[red]No report yet -- run a scan first.[/red]")
                continue
            path = Prompt.ask("Save as (.md or .json)", default="reconote-report.md")
            report_mod.save_report(last_report, path)
            console.print(f"[green]Saved to {path}[/green]")
        elif choice == "6":
            console.print("Bye.")
            break


def resolve_port_spec(spec: str) -> list[int]:
    spec = spec.lower().strip()
    if spec == "top100":
        return scanner.TOP_100_PORTS
    if spec == "top1000":
        return list(range(1, 1001))
    if spec == "all":
        return list(range(1, 65536))
    try:
        return scanner.parse_ports(spec)
    except ValueError:
        return []


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconote",
        description="A small nmap-ish recon tool with built-in annotations for CTF/lab use.",
    )
    p.add_argument("target", nargs="?", help="IP or hostname to scan. Omit to launch the interactive menu.")
    p.add_argument("-p", "--ports", default=None, help="Port spec, e.g. '22,80,1000-2000'. Overrides --top.")
    p.add_argument("--top", type=int, default=100, choices=[100, 1000], help="Scan the top N common ports (default 100).")
    p.add_argument("--all-ports", action="store_true", help="Scan all 65535 ports (slow).")
    p.add_argument("--engine", choices=["auto", "socket", "nmap"], default="auto", help="Scan engine (default: auto-detect nmap).")
    p.add_argument("--timeout", type=float, default=1.0, help="Per-port connect timeout in seconds (socket engine).")
    p.add_argument("--threads", type=int, default=100, help="Concurrent threads (socket engine).")
    p.add_argument("-o", "--output", default=None, help="Save the annotated report to a file (.md or .json).")
    p.add_argument("-y", "--yes", action="store_true", help="Skip the authorization confirmation prompt.")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    if not args.target:
        interactive_menu()
        return

    if args.ports:
        ports = scanner.parse_ports(args.ports)
    elif args.all_ports:
        ports = list(range(1, 65536))
    elif args.top == 1000:
        ports = list(range(1, 1001))
    else:
        ports = scanner.TOP_100_PORTS

    console.print(Panel(AUTH_NOTICE, border_style="red"))
    if not args.yes and not Confirm.ask(f"Confirm: you are authorized to scan '{args.target}'?", default=True):
        console.print("[yellow]Aborted -- not authorized.[/yellow]")
        sys.exit(1)

    cmd_scan_and_show(args.target, ports, args.engine, args.timeout, args.threads, args.output)


if __name__ == "__main__":
    main()
