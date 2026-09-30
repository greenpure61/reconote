from reconote import udp_scanner


def test_top_udp_ports_are_unique_and_valid():
    assert len(udp_scanner.TOP_UDP_PORTS) == len(set(udp_scanner.TOP_UDP_PORTS))
    assert all(0 < p < 65536 for p in udp_scanner.TOP_UDP_PORTS)


def test_known_probes_are_nonempty_bytes():
    for probe in udp_scanner.UDP_PROBES.values():
        assert isinstance(probe, bytes)
        assert len(probe) > 0


def test_dns_probe_has_standard_header_length():
    # 12-byte header + 1-byte root name + 2-byte qtype + 2-byte qclass
    assert len(udp_scanner._DNS_PROBE) == 17


def test_ntp_probe_is_48_bytes_client_request():
    assert len(udp_scanner._NTP_PROBE) == 48
    assert udp_scanner._NTP_PROBE[0] == 0x1B


def test_snmp_probe_is_well_formed_ber():
    # top-level SEQUENCE tag 0x30, and total length matches declared length byte
    probe = udp_scanner._SNMP_PROBE
    assert probe[0] == 0x30
    declared_len = probe[1]
    assert len(probe) - 2 == declared_len
