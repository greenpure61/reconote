import pytest

from reconote import scope


def test_load_scope_parses_cidrs_and_bare_ips(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "# engagement notes\n"
        "10.10.10.0/24\n"
        "\n"
        "192.168.56.10\n"
    )
    networks = scope.load_scope(scope_file)
    assert len(networks) == 2


def test_load_scope_rejects_bad_lines(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("not-an-ip\n")
    with pytest.raises(ValueError):
        scope.load_scope(scope_file)


def test_in_scope_matches_cidr(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.10.10.0/24\n")
    networks = scope.load_scope(scope_file)
    assert scope.in_scope("10.10.10.5", networks) is True
    assert scope.in_scope("10.10.11.5", networks) is False


def test_check_passes_silently_when_no_scope_file():
    scope.check("1.2.3.4", None)  # should not raise


def test_check_raises_for_out_of_scope_target(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.10.10.0/24\n")
    with pytest.raises(scope.ScopeError):
        scope.check("8.8.8.8", scope_file)


def test_check_allows_in_scope_target(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("10.10.10.0/24\n")
    scope.check("10.10.10.50", scope_file)  # should not raise


def test_find_default_scope_file(tmp_path):
    assert scope.find_default_scope_file(tmp_path) is None
    (tmp_path / "scope.txt").write_text("10.0.0.0/8\n")
    found = scope.find_default_scope_file(tmp_path)
    assert found is not None
    assert found.name == "scope.txt"
