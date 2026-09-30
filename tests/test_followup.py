from reconote import followup


class FakeConsole:
    def __init__(self):
        self.lines = []

    def print(self, *args, **kwargs):
        self.lines.append(" ".join(str(a) for a in args))


def _fake_report():
    return {
        "findings": [
            {
                "port": 80,
                "protocol": "tcp",
                "kb_name": "HTTP",
                "next_steps": [
                    "curl -sI http://10.10.10.5/",
                    "gobuster dir -u http://10.10.10.5/ -w list.txt",
                ],
            },
            {
                "port": 22,
                "protocol": "tcp",
                "kb_name": "SSH",
                "next_steps": ["ssh -v 10.10.10.5"],
            },
        ]
    }


def test_flatten_produces_one_entry_per_step():
    entries = followup._flatten(_fake_report())
    assert len(entries) == 3
    assert entries[0] == (80, "tcp", "HTTP", "curl -sI http://10.10.10.5/")
    assert entries[2] == (22, "tcp", "SSH", "ssh -v 10.10.10.5")


def test_flatten_empty_report_returns_empty_list():
    assert followup._flatten({"findings": []}) == []


def test_pick_and_run_goes_back_immediately_on_zero(monkeypatch):
    monkeypatch.setattr(followup.Prompt, "ask", lambda *a, **k: "0")
    executed = []
    monkeypatch.setattr(followup.runner, "run_shell_command", lambda cmd: executed.append(cmd) or 0)

    followup.pick_and_run(_fake_report(), FakeConsole())

    assert executed == []


def test_pick_and_run_executes_the_chosen_command(monkeypatch):
    prompt_answers = iter(["1", "curl -sI http://10.10.10.5/"])
    monkeypatch.setattr(followup.Prompt, "ask", lambda *a, **k: next(prompt_answers))
    confirm_answers = iter([True, False])  # confirm run, then decline "run another"
    monkeypatch.setattr(followup.Confirm, "ask", lambda *a, **k: next(confirm_answers))
    executed = []
    monkeypatch.setattr(followup.runner, "run_shell_command", lambda cmd: executed.append(cmd) or 0)

    followup.pick_and_run(_fake_report(), FakeConsole())

    assert executed == ["curl -sI http://10.10.10.5/"]


def test_pick_and_run_lets_you_edit_the_command_before_running(monkeypatch):
    prompt_answers = iter(["1", "curl -sI -v http://10.10.10.5/"])  # edited version
    monkeypatch.setattr(followup.Prompt, "ask", lambda *a, **k: next(prompt_answers))
    confirm_answers = iter([True, False])
    monkeypatch.setattr(followup.Confirm, "ask", lambda *a, **k: next(confirm_answers))
    executed = []
    monkeypatch.setattr(followup.runner, "run_shell_command", lambda cmd: executed.append(cmd) or 0)

    followup.pick_and_run(_fake_report(), FakeConsole())

    assert executed == ["curl -sI -v http://10.10.10.5/"]


def test_pick_and_run_declining_confirmation_does_not_run(monkeypatch):
    prompt_answers = iter(["1", "curl -sI http://10.10.10.5/", "0"])
    monkeypatch.setattr(followup.Prompt, "ask", lambda *a, **k: next(prompt_answers))
    monkeypatch.setattr(followup.Confirm, "ask", lambda *a, **k: False)  # decline the run
    executed = []
    monkeypatch.setattr(followup.runner, "run_shell_command", lambda cmd: executed.append(cmd) or 0)

    followup.pick_and_run(_fake_report(), FakeConsole())

    assert executed == []


def test_pick_and_run_handles_invalid_choice_then_backs_out(monkeypatch):
    prompt_answers = iter(["99", "not-a-number", "0"])
    monkeypatch.setattr(followup.Prompt, "ask", lambda *a, **k: next(prompt_answers))
    executed = []
    monkeypatch.setattr(followup.runner, "run_shell_command", lambda cmd: executed.append(cmd) or 0)

    followup.pick_and_run(_fake_report(), FakeConsole())

    assert executed == []


def test_pick_and_run_no_findings_does_not_prompt(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("should not prompt when there's nothing to run")

    monkeypatch.setattr(followup.Prompt, "ask", _boom)
    followup.pick_and_run({"findings": []}, FakeConsole())
