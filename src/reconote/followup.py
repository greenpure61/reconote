"""
followup.py -- interactively pick and run one of a scan report's
suggested next-step commands.

Every command is shown in full and requires an explicit confirmation
before it runs -- reconote never executes a suggested command on its
own. Commands are editable before running since some KB entries
contain <placeholder> values (a username, a domain name, a filename)
that only the person running the tool can fill in.
"""

from __future__ import annotations

from rich.prompt import Confirm, Prompt

from . import runner


def _flatten(report: dict) -> list[tuple[int, str, str, str]]:
    """Every (port, protocol, service name, command) across all findings."""
    entries = []
    for f in report["findings"]:
        for step in f["next_steps"]:
            entries.append((f["port"], f["protocol"], f["kb_name"], step))
    return entries


def pick_and_run(report: dict, console) -> None:
    entries = _flatten(report)
    if not entries:
        console.print("[yellow]No suggested commands available.[/yellow]")
        return

    while True:
        console.print()
        console.print("[bold]Suggested commands[/bold]  [dim](0 to go back)[/dim]")
        for i, (port, proto, name, step) in enumerate(entries, start=1):
            console.print(f"  [cyan]{i:>2}[/cyan]) [dim][{port}/{proto} {name}][/dim] {step}")

        choice = Prompt.ask("Pick a command to run", default="0").strip()
        if choice in ("0", ""):
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(entries)):
            console.print("[red]Not a valid choice.[/red]")
            continue

        _, _, _, raw_cmd = entries[int(choice) - 1]
        cmd_to_run = Prompt.ask("Edit if needed, Enter to run as-is", default=raw_cmd).strip()
        if not cmd_to_run:
            continue

        if "<" in cmd_to_run and ">" in cmd_to_run:
            console.print(
                "[yellow]Heads up: this still has a <placeholder> in it -- "
                "edit it above before running, or it'll likely fail.[/yellow]"
            )

        if not Confirm.ask(f"Run [bold]{cmd_to_run}[/bold] ?", default=True):
            continue

        console.print(f"[dim]$ {cmd_to_run}[/dim]")
        code = runner.run_shell_command(cmd_to_run)
        style = "green" if code == 0 else "red"
        console.print(f"[{style}](exit code {code})[/{style}]")

        if not Confirm.ask("Run another command?", default=False):
            return
