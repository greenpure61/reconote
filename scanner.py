"""
scanner.py -- scan engines for reconote.

Two engines:
  - "socket": pure-python multithreaded TCP connect scan + banner grab.
    Always available, no extra privileges needed.
  - "nmap": shells out to nmap (-sV -oX -) and parses the XML if the
    nmap binary is present. Gives better service/version detection.

Both return the same normalized structure:
  {host: {port: {"state": "open", "service": str, "product": str,
                 "version": str, "banner": str}}}
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513,
    514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 7937, 7938, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200,
    9999, 10000, 27017, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

COMMON_BANNER_PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}


def _grab_banner(sock: socket.socket, port: int) -> str:
    try:
        probe = COMMON_BANNER_PROBES.get(port)
        if probe:
            sock.sendall(probe)
        sock.settimeout(1.5)
        data = sock.recv(256)
        return data.decode(errors="replace").strip().split("\n")[0][:120]
    except Exception:
        return ""


def _scan_one_port(host: str, port: int, timeout: float) -> Optional[dict]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = _grab_banner(sock, port)
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = ""
            return {
                "port": port,
                "state": "open",
                "service": service,
                "product": "",
                "version": "",
                "banner": banner,
            }
    except Exception:
        return None


def socket_scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    threads: int = 100,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> dict:
    """Pure-python multithreaded TCP connect scan. Returns {port: info}."""
    results: dict[int, dict] = {}
    done = 0
    total = len(ports)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_one_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            res = fut.result()
            if res:
                results[res["port"]] = res
    return results


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def nmap_scan(host: str, ports: list[int], extra_args: Optional[list[str]] = None) -> dict:
    """Run nmap -sV against a port list and parse the XML output."""
    port_spec = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-sV", "-Pn", "-p", port_spec, "-oX", "-", host]
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    results: dict[int, dict] = {}
    if proc.returncode not in (0,) or not proc.stdout.strip():
        return results
    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return results
    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = int(port_el.get("portid"))
            service_el = port_el.find("service")
            service = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            results[portid] = {
                "port": portid,
                "state": "open",
                "service": service,
                "product": product,
                "version": version,
                "banner": f"{product} {version}".strip(),
            }
    return results


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP, or pass through if already an IP."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,1000-1010' style port specs into a sorted list of ints."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p < 65536)
