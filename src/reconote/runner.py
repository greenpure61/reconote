"""
runner.py -- executes a suggested next-step command in the system shell.

reconote never runs one of these on its own initiative; a human always
sees the exact command and confirms before anything executes. See
followup.py for the interactive picker that calls this.
"""

from __future__ import annotations

import subprocess


def run_shell_command(cmd: str) -> int:
    """Run cmd through the system shell, streaming output live.

    Returns the process exit code, 130 on Ctrl+C, or 1 if the command
    couldn't even be launched (e.g. the tool isn't installed).
    """
    try:
        proc = subprocess.run(cmd, shell=True, check=False)
        return proc.returncode
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        print(f"Failed to run command: {exc}")
        return 1
