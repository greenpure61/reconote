"""
report.py -- turns raw scan results into an annotated report, and
renders/saves it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from kb import lookup


def annotate(target: str, raw_results: dict, engine: str) -> dict:
    """Attach KB explanations to each open port. Returns a report dict."""
    findings = []
    for port in sorted(raw_results):
        info = raw_results[port]
        service_hint = info.get("service") or info.get("product") or ""
        entry = lookup(port, service_hint)
        next_steps = [
            step.format(target=target, port=port) for step in entry["next"]
        ]
        findings.append(
            {
                "port": port,
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
    table.add_column("Service")
    table.add_column("Banner / Version")
    for f in report["findings"]:
        version_bit = " ".join(x for x in [f["product"], f["version"]] if x)
        banner_col = version_bit or f["banner"]
        table.add_row(str(f["port"]), f["service"] or f["kb_name"], banner_col)
    console.print(table)

    for f in report["findings"]:
        body = Text()
        body.append(f"What it is: ", style="bold")
        body.append(f["what"] + "\n")
        body.append(f"Why it matters: ", style="bold")
        body.append(f["why"] + "\n\n")
        body.append("Suggested next steps:\n", style="bold")
        for step in f["next_steps"]:
            body.append(f"  - {step}\n", style="dim")
        console.print(
            Panel(
                body,
                title=f"[bold cyan]{f['port']}/tcp[/bold cyan] -- {f['kb_name']}",
                border_style="blue",
            )
        )


def to_markdown(report: dict) -> str:
    lines = [
        f"# reconote scan report",
        "",
        f"- **Target:** {report['target']}",
        f"- **Engine:** {report['engine']}",
        f"- **Scanned at:** {report['scanned_at']}",
        f"- **Open ports:** {report['open_ports']}",
        "",
    ]
    for f in report["findings"]:
        lines.append(f"## {f['port']}/tcp -- {f['kb_name']}")
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
