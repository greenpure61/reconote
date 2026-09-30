"""
report.py -- turns raw scan results into an annotated report, and
renders/saves it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import kb


def annotate(target: str, raw_results, engine: str) -> dict:
    """Attach KB explanations to each open port.

    raw_results can be a dict of {port: info} (as returned by a single
    scanner) or any iterable of info dicts (e.g. combining TCP + UDP
    results). Each info dict must have its own "port" key. Returns a
    report dict.
    """
    values = raw_results.values() if isinstance(raw_results, dict) else raw_results
    findings = []
    for info in values:
        port = info["port"]
        service_hint = info.get("service") or info.get("product") or ""
        entry = kb.lookup(port, service_hint)
        next_steps = [
            step.format(target=target, port=port) for step in entry["next"]
        ]
        findings.append(
            {
                "port": port,
                "protocol": info.get("protocol", "tcp"),
                "state": info.get("state", "open"),
                "service": info.get("service", ""),
                "product": info.get("product", ""),
                "version": info.get("version", ""),
                "banner": info.get("banner", ""),
                "kb_name": entry["name"],
                "what": entry["what"],
                "why": entry["why"],
                "next_steps": next_steps,
            }
        )
    # tcp before udp, then by port number, matches how most people scan-read
    findings.sort(key=lambda f: (f["protocol"] != "tcp", f["port"]))
    return {
        "target": target,
        "engine": engine,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "open_ports": len(findings),
        "findings": findings,
    }


def render_console(report: dict, console) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console.print(
        Panel(
            f"[bold]Target:[/bold] {report['target']}   "
            f"[bold]Engine:[/bold] {report['engine']}   "
            f"[bold]Open ports:[/bold] {report['open_ports']}",
            title="reconote scan summary",
            border_style="cyan",
        )
    )

    if not report["findings"]:
        console.print("[yellow]No open ports found in the scanned range.[/yellow]")
        return

    table = Table(title="Open ports", show_lines=False)
    table.add_column("Port", style="bold green")
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Banner / Version")
    for f in report["findings"]:
        version_bit = " ".join(x for x in [f["product"], f["version"]] if x)
        banner_col = version_bit or f["banner"]
        state_style = "yellow" if f["state"] == "open|filtered" else "green"
        table.add_row(
            str(f["port"]),
            f["protocol"],
            f"[{state_style}]{f['state']}[/{state_style}]",
            f["service"] or f["kb_name"],
            banner_col,
        )
    console.print(table)

    for f in report["findings"]:
        body = Text()
        body.append("What it is: ", style="bold")
        body.append(f["what"] + "\n")
        body.append("Why it matters: ", style="bold")
        body.append(f["why"] + "\n\n")
        if f["state"] == "open|filtered":
            body.append(
                "Note: no response to the probe -- could be open with a "
                "silent service, or filtered by a firewall. Not confirmed.\n\n",
                style="italic yellow",
            )
        body.append("Suggested next steps:\n", style="bold")
        for step in f["next_steps"]:
            body.append(f"  - {step}\n", style="dim")
        console.print(
            Panel(
                body,
                title=f"[bold cyan]{f['port']}/{f['protocol']}[/bold cyan] -- {f['kb_name']}",
                border_style="blue",
            )
        )


def to_markdown(report: dict) -> str:
    lines = [
        "# reconote scan report",
        "",
        f"- **Target:** {report['target']}",
        f"- **Engine:** {report['engine']}",
        f"- **Scanned at:** {report['scanned_at']}",
        f"- **Open ports:** {report['open_ports']}",
        "",
    ]
    for f in report["findings"]:
        lines.append(f"## {f['port']}/{f['protocol']} ({f['state']}) -- {f['kb_name']}")
        version_bit = " ".join(x for x in [f["product"], f["version"]] if x)
        if version_bit or f["banner"]:
            lines.append(f"- **Detected:** {version_bit or f['banner']}")
        lines.append(f"- **What it is:** {f['what']}")
        lines.append(f"- **Why it matters:** {f['why']}")
        lines.append("- **Suggested next steps:**")
        for step in f["next_steps"]:
            lines.append(f"  - `{step}`")
        lines.append("")
    return "\n".join(lines)


def save_report(report: dict, path: str) -> None:
    if path.endswith(".json"):
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)
    else:
        with open(path, "w") as fh:
            fh.write(to_markdown(report))
