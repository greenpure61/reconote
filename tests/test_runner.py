import sys

from reconote import runner


def _python_cmd(exit_code: int) -> str:
    # Quote the interpreter path so this works even if it contains spaces;
    # shell=True hands the whole string to cmd.exe (Windows) or sh (POSIX).
    return f'"{sys.executable}" -c "import sys; sys.exit({exit_code})"'


def test_run_shell_command_returns_zero_exit_code():
    assert runner.run_shell_command(_python_cmd(0)) == 0


def test_run_shell_command_returns_nonzero_exit_code():
    assert runner.run_shell_command(_python_cmd(3)) == 3


def test_run_shell_command_handles_a_command_that_cannot_launch():
    # An empty command can't be executed; this should not raise, just
    # return a non-zero-ish result depending on platform.
    code = runner.run_shell_command("")
    assert isinstance(code, int)
