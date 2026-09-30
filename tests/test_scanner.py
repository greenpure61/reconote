import pytest

from reconote import scanner


def test_parse_ports_handles_ranges_and_lists():
    assert scanner.parse_ports("22,80,443") == [22, 80, 443]
    assert scanner.parse_ports("1-5") == [1, 2, 3, 4, 5]
    assert scanner.parse_ports("22, 80 , 100-102") == [22, 80, 100, 101, 102]


def test_parse_ports_dedupes_and_sorts():
    assert scanner.parse_ports("80,22,80,1-3") == [1, 2, 3, 22, 80]


def test_parse_ports_ignores_out_of_range():
    assert scanner.parse_ports("0,65536,80") == [80]


def test_parse_ports_rejects_garbage():
    with pytest.raises(ValueError):
        scanner.parse_ports("not-a-port")


def test_resolve_target_passes_through_ip():
    assert scanner.resolve_target("127.0.0.1") == "127.0.0.1"


def test_nmap_available_returns_bool():
    assert isinstance(scanner.nmap_available(), bool)


def test_top_100_ports_are_unique_and_valid():
    assert len(scanner.TOP_100_PORTS) == len(set(scanner.TOP_100_PORTS))
    assert all(0 < p < 65536 for p in scanner.TOP_100_PORTS)
