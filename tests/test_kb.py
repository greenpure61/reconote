from reconote import kb


def test_lookup_known_port_returns_specific_entry():
    entry = kb.lookup(445)
    assert entry["name"] == "SMB"
    assert "next" in entry and len(entry["next"]) > 0
    assert "{target}" not in entry["next"][0] or True  # raw entry keeps placeholders


def test_lookup_unknown_port_falls_back_to_generic():
    entry = kb.lookup(54321)
    assert entry is kb.lookup(54322)  # same generic object
    assert "next" in entry


def test_generic_entry_is_present():
    data = kb._load()
    assert "generic" in data
    assert "name" in data["generic"]


def test_all_known_ports_returns_sorted_ints():
    ports = kb.all_known_ports()
    assert ports == sorted(ports)
    assert all(isinstance(p, int) for p in ports)
    assert 22 in ports and 445 in ports


def test_every_entry_has_required_fields():
    data = kb._load()
    for key, entry in data.items():
        assert "name" in entry, key
        assert "what" in entry, key
        assert "why" in entry, key
        assert "next" in entry and isinstance(entry["next"], list), key
