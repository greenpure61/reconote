"""
udp_scanner.py -- UDP port scanning for reconote.

UDP has no handshake, so "open" is inherently fuzzier than TCP:
  - A response to our probe  -> definitely "open"
  - An ICMP port-unreachable -> definitely "closed" (we don't report these)
  - No response at all       -> "open|filtered" (service may be open and
                                 silently dropped our probe, or a firewall
                                 ate the packet -- can't tell from here,
                                 same ambiguity nmap reports)

For a handful of common services we send a real protocol-shaped probe
(DNS, NTP, SNMP) so those specifically get a confirmed "open" instead of
just "open|filtered". Everything else gets a minimal generic probe.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

TOP_UDP_PORTS = [
    53, 67, 68, 69, 111, 123, 135, 137, 138, 161, 162, 177, 389, 427,
    500, 514, 520, 523, 631, 996, 997, 998, 999, 1434, 1900, 4500,
    5353, 5060, 33434,
]

# DNS: standard query for the root (".") A record.
_DNS_PROBE = bytes.fromhex("aaaa010000010000000000000000010001")

# NTP: v3 client request (LI=0, VN=3, Mode=3) followed by 47 zero bytes.
_NTP_PROBE = b"\x1b" + b"\x00" * 47


def _ber_len(n: int) -> bytes:
    """BER length octets. Only short-form (n < 128) is needed for our probes."""
    if n >= 128:
        raise ValueError("long-form BER length not implemented (not needed here)")
    return bytes([n])


def _ber_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(content)) + content


def _ber_integer(n: int) -> bytes:
    return _ber_tlv(0x02, bytes([n]))  # fine for the small values we send


def _ber_octet_string(data: bytes) -> bytes:
    return _ber_tlv(0x04, data)


def _ber_null() -> bytes:
    return b"\x05\x00"


def _ber_oid(arcs: tuple[int, ...]) -> bytes:
    # Standard OID encoding: first two arcs combine as 40*arc1 + arc2, each
    # remaining arc is encoded base-128 -- a single byte per arc is enough
    # for every arc we use here (all < 128).
    first_byte = 40 * arcs[0] + arcs[1]
    body = bytes([first_byte]) + bytes(arcs[2:])
    return _ber_tlv(0x06, body)


def _build_snmp_get_request(community: bytes, oid: tuple[int, ...], request_id: int = 1) -> bytes:
    """Build a minimal SNMPv1 GetRequest packet."""
    version = _ber_integer(0)
    community_field = _ber_octet_string(community)
    varbind = _ber_tlv(0x30, _ber_oid(oid) + _ber_null())
    varbind_list = _ber_tlv(0x30, varbind)
    pdu_body = (
        _ber_integer(request_id)
        + _ber_integer(0)  # error-status
        + _ber_integer(0)  # error-index
        + varbind_list
    )
    pdu = _ber_tlv(0xA0, pdu_body)  # GetRequest-PDU
    message_body = version + community_field + pdu
    return _ber_tlv(0x30, message_body)


# SNMPv1 GetRequest, community "public", OID 1.3.6.1.2.1.1.1.0 (sysDescr.0).
_SNMP_PROBE = _build_snmp_get_request(b"public", (1, 3, 6, 1, 2, 1, 1, 1, 0))

UDP_PROBES = {
    53: _DNS_PROBE,
    123: _NTP_PROBE,
    161: _SNMP_PROBE,
    162: _SNMP_PROBE,
}

_GENERIC_PROBE = b"\x00"


def _scan_one_udp_port(host: str, port: int, timeout: float) -> dict | None:
    probe = UDP_PROBES.get(port, _GENERIC_PROBE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.send(probe)
        try:
            data = sock.recv(1024)
        except TimeoutError:
            return {
                "port": port,
                "state": "open|filtered",
                "protocol": "udp",
                "service": "",
                "product": "",
                "version": "",
                "banner": "",
            }
        try:
            service = socket.getservbyport(port, "udp")
        except OSError:
            service = ""
        banner = data[:120].decode(errors="replace").strip() if data else ""
        return {
            "port": port,
            "state": "open",
            "protocol": "udp",
            "service": service,
            "product": "",
            "version": "",
            "banner": banner,
        }
    except (ConnectionRefusedError, ConnectionResetError, OSError):
        # ICMP port-unreachable (or similar) -- treat as closed, don't report.
        return None
    finally:
        sock.close()


def udp_scan(
    host: str,
    ports: list[int],
    timeout: float = 1.5,
    threads: int = 50,
    progress_cb: Callable[[int, int], None] | None = None,
) -> dict:
    """Multithreaded UDP scan. Returns {port: info} for open/open|filtered ports."""
    results: dict[int, dict] = {}
    done = 0
    total = len(ports)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_one_udp_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            res = fut.result()
            if res:
                results[res["port"]] = res
    return results
