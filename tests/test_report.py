from reconote import report as report_mod


def _fake_tcp_result(port=80):
    return {
        "port": port,
        "state": "open",
        "protocol": "tcp",
        "service": "http",
        "product": "",
        "version": "",
        "banner": "HTTP/1.1 200 OK",
    }


def test_annotate_accepts_dict_keyed_by_port():
    raw = {80: _fake_tcp_result(80)}
    rpt = report_mod.annotate("10.10.10.5", raw, "socket")
    assert rpt["target"] == "10.10.10.5"
    assert rpt["open_ports"] == 1
    finding = rpt["findings"][0]
    assert finding["port"] == 80
    assert finding["kb_name"] == "HTTP"
    assert any("10.10.10.5" in step for step in finding["next_steps"])


def test_annotate_accepts_flat_list_and_merges_tcp_udp():
    tcp = _fake_tcp_result(80)
    udp = {
        "port": 161,
        "state": "open",
        "protocol": "udp",
        "service": "snmp",
        "product": "",
        "version": "",
        "banner": "",
    }
    rpt = report_mod.annotate("10.10.10.5", [tcp, udp], "socket")
    assert rpt["open_ports"] == 2
    # tcp findings should sort before udp findings
    protocols = [f["protocol"] for f in rpt["findings"]]
    assert protocols == ["tcp", "udp"]


def test_next_steps_are_formatted_with_target_and_port():
    raw = [_fake_tcp_result(8080)]
    rpt = report_mod.annotate("scanme.example.com", raw, "socket")
    finding = rpt["findings"][0]
    assert any("scanme.example.com" in step and "8080" in step for step in finding["next_steps"])


def test_to_markdown_includes_target_and_findings():
    raw = [_fake_tcp_result(22)]
    rpt = report_mod.annotate("10.10.10.5", raw, "socket")
    md = report_mod.to_markdown(rpt)
    assert "10.10.10.5" in md
    assert "22/tcp" in md
    assert "SSH" in md


def test_empty_results_produce_zero_findings():
    rpt = report_mod.annotate("10.10.10.5", {}, "socket")
    assert rpt["open_ports"] == 0
    assert rpt["findings"] == []
