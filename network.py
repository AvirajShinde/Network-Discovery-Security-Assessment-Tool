#!/usr/bin/env python3
"""
netaudit - Network Discovery & Security Assessment Tool
=======================================================

A dependency-free (Python 3.8+ standard library only) tool that performs:

  1. Target expansion      single IP, hostname, CIDR, a.b.c.d-e range, or a file of targets
  2. Host discovery        ICMP ping + TCP probes (a refused connection also proves a host is up)
  3. Port scanning         multithreaded TCP connect scan (quick / full / custom ranges)
  4. Service detection     port map + banner grabbing
  5. TLS inspection        protocol, cipher, certificate expiry, self-signed, legacy TLS 1.0/1.1
  6. HTTP inspection       missing security headers, server/technology disclosure
  7. UDP probing           service-specific probes: DNS, TFTP, NTP, NetBIOS, SNMP, SSDP, memcached (--udp)
  8. CVE matching          banner/header versions vs built-in rules, optionally NVD (--cve-online)
  9. Risk findings         exposed admin/database/legacy services with severity + remediation
 10. Reporting             console summary, JSON, HTML, CSV
 11. Change tracking       compare scans over time (--baseline, --diff) for regression alerts

Exit codes: 0 ok, 2 usage/input error, 3 unauthorized target, 4 regression found (diff/baseline)

Only use it against systems you own or have explicit written permission to test.
Targets outside private/loopback ranges require the --authorized flag.

Examples
--------
  python netaudit.py 127.0.0.1
  python netaudit.py 192.168.1.0/24 -p quick --format json,html -o lan_audit
  python netaudit.py 10.0.0.5 -p 1-1024,8080,8443 --timeout 1.5 -t 200
  python netaudit.py -iL targets.txt -p full --authorized -o client_scan
  python netaudit.py 192.168.1.0/24 --udp --cve-online -o today
  python netaudit.py 192.168.1.0/24 --baseline last_week.json -o today
  python netaudit.py --diff last_week.json today.json
"""

import argparse
import concurrent.futures as cf
import csv
import datetime as dt
import html
import http.client
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

VERSION = "1.1.0"

# --------------------------------------------------------------------------- #
# Knowledge base
# --------------------------------------------------------------------------- #

QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 636, 993, 995, 1433, 1521, 1723, 2049, 2375, 3000, 3306,
    3389, 5000, 5432, 5601, 5900, 5985, 6379, 8000, 8008, 8080, 8081, 8443,
    8888, 9000, 9090, 9200, 9443, 11211, 27017,
]

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    81: "http-alt", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 631: "ipp", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2375: "docker-api", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 5000: "http-alt", 5432: "postgresql", 5601: "kibana",
    5900: "vnc", 5985: "winrm", 6379: "redis", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
    9443: "https-alt", 11211: "memcached", 27017: "mongodb",
}

HTTP_PORTS = {80, 81, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200}
TLS_WEB_PORTS = {443, 8443, 9443}
TLS_PORTS = TLS_WEB_PORTS | {465, 636, 993, 995}

# port -> (severity, title, recommendation)
RISKY = {
    21: ("Medium", "FTP exposed (cleartext credentials)", "Replace with SFTP/FTPS or restrict by firewall."),
    23: ("High", "Telnet exposed (cleartext remote shell)", "Disable Telnet; use SSH with key-based auth."),
    110: ("Low", "POP3 without TLS", "Use POP3S (995) or STARTTLS."),
    111: ("Medium", "rpcbind/portmapper exposed", "Block at the perimeter; restrict to trusted hosts."),
    135: ("Medium", "Windows RPC endpoint mapper exposed", "Do not expose MSRPC beyond the internal network."),
    139: ("High", "NetBIOS session service exposed", "Disable NetBIOS over TCP/IP or firewall the port."),
    143: ("Low", "IMAP without TLS", "Use IMAPS (993) or enforce STARTTLS."),
    389: ("Low", "LDAP in cleartext", "Use LDAPS (636) or STARTTLS; restrict access."),
    445: ("High", "SMB exposed", "Block SMB at the perimeter, patch hosts, disable SMBv1, require signing."),
    1433: ("Medium", "Microsoft SQL Server exposed", "Restrict to application servers; enforce strong auth and TLS."),
    1521: ("Medium", "Oracle listener exposed", "Restrict to application servers; apply listener hardening."),
    1723: ("Low", "PPTP VPN exposed", "PPTP is cryptographically weak; migrate to IPsec/WireGuard/OpenVPN."),
    2049: ("Medium", "NFS exposed", "Restrict exports to specific hosts; use Kerberos (sec=krb5p)."),
    2375: ("Critical", "Docker API exposed without TLS", "Never expose 2375; use a TLS-protected socket or SSH tunnelling."),
    3306: ("Medium", "MySQL/MariaDB exposed", "Bind to localhost or restrict by firewall; enforce TLS and strong auth."),
    3389: ("High", "RDP exposed", "Place behind VPN/RD Gateway, enable NLA and MFA, patch regularly."),
    5432: ("Medium", "PostgreSQL exposed", "Restrict via pg_hba.conf and firewall; enforce TLS."),
    5601: ("Medium", "Kibana exposed", "Require authentication and restrict network access."),
    5900: ("High", "VNC exposed", "Tunnel through SSH/VPN; require strong passwords or disable."),
    5985: ("Medium", "WinRM (HTTP) exposed", "Restrict to management networks; prefer HTTPS (5986)."),
    6379: ("High", "Redis exposed (often unauthenticated)", "Bind to localhost, set requirepass/ACLs, firewall the port."),
    9200: ("High", "Elasticsearch exposed", "Enable security features and restrict network access."),
    11211: ("High", "Memcached exposed", "Bind to localhost/internal only; disable UDP."),
    27017: ("High", "MongoDB exposed", "Enable authentication, bind to internal interfaces, firewall the port."),
}

SECURITY_HEADERS = {
    "content-security-policy": ("Low", "Missing Content-Security-Policy header"),
    "x-frame-options": ("Low", "Missing X-Frame-Options header (clickjacking protection)"),
    "x-content-type-options": ("Low", "Missing X-Content-Type-Options header"),
    "referrer-policy": ("Info", "Missing Referrer-Policy header"),
}

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_COLOR = {"Critical": "\033[1;95m", "High": "\033[91m", "Medium": "\033[93m",
             "Low": "\033[96m", "Info": "\033[90m"}
RESET = "\033[0m"

# UDP probes: port -> (service, payload). UDP has no handshake, so each service needs its own probe.
_DNS_Q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x07example\x03com\x00\x00\x01\x00\x01")
_NTP_Q = b"\x1b" + b"\x00" * 47
# SNMPv2c GetRequest for sysDescr.0 using the community string "public"
_SNMP_Q = bytes.fromhex(
    "30 29 02 01 01 04 06 70 75 62 6c 69 63 a0 1c 02 04 00 00 00 01 02 01 00 02 01 00 "
    "30 0e 30 0c 06 08 2b 06 01 02 01 01 01 00 05 00")
_NBNS_Q = (b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           b"\x20" + b"CK" + b"A" * 30 + b"\x00\x00\x21\x00\x01")
_SSDP_Q = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
           b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n')
_TFTP_Q = b"\x00\x01netaudit-probe\x00octet\x00"
_MEMC_Q = b"\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n"

UDP_SERVICES = {
    53: ("dns", _DNS_Q),
    69: ("tftp", _TFTP_Q),
    123: ("ntp", _NTP_Q),
    137: ("netbios-ns", _NBNS_Q),
    161: ("snmp", _SNMP_Q),
    1900: ("ssdp", _SSDP_Q),
    11211: ("memcached", _MEMC_Q),
}

# Product detection (applied to banners and HTTP Server / X-Powered-By headers).
PRODUCT_PATTERNS = {
    "vsftpd": r"vsFTPd (\d+(?:\.\d+)+)",
    "OpenSSH": r"OpenSSH[_ ](\d+(?:\.\d+)*)",
    "Apache httpd": r"Apache/(\d+(?:\.\d+)+)",
    "nginx": r"nginx/(\d+(?:\.\d+)+)",
    "ProFTPD": r"ProFTPD (\d+(?:\.\d+)+[a-z]?)",
    "Exim": r"Exim (\d+(?:\.\d+)+)",
    "OpenSSL": r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)",
    "Microsoft IIS": r"Microsoft-IIS/(\d+(?:\.\d+)*)",
}


def vt(version: str) -> tuple:
    """'9.6p1' -> (9, 6); '1.0.1f' -> (1, 0, 1)."""
    return tuple(int(x) for x in re.match(r"\d+(?:\.\d+)*", version).group(0).split("."))


# (product, version predicate, CVE, severity, description)
CVE_RULES = [
    ("vsftpd", lambda v: vt(v) == (2, 3, 4), "CVE-2011-2523", "Critical",
     "vsftpd 2.3.4 shipped with a backdoor that gives remote command execution"),
    ("Apache httpd", lambda v: vt(v) == (2, 4, 49), "CVE-2021-41773", "Critical",
     "Path traversal and possible remote code execution in Apache httpd 2.4.49"),
    ("Apache httpd", lambda v: vt(v) == (2, 4, 50), "CVE-2021-42013", "Critical",
     "Incomplete fix for CVE-2021-41773: path traversal and possible RCE in Apache httpd 2.4.50"),
    ("OpenSSH", lambda v: (8, 5) <= vt(v) < (9, 8), "CVE-2024-6387", "High",
     "regreSSHion: signal handler race condition in sshd (unauthenticated RCE on glibc-based Linux)"),
    ("OpenSSH", lambda v: vt(v) <= (7, 7), "CVE-2018-15473", "Medium",
     "Username enumeration through crafted authentication requests"),
    ("ProFTPD", lambda v: v == "1.3.5", "CVE-2015-3306", "High",
     "mod_copy allows unauthenticated file copy (fixed in 1.3.5a)"),
    ("Exim", lambda v: (4, 87) <= vt(v) <= (4, 91), "CVE-2019-10149", "Critical",
     "Remote command execution in Exim 4.87-4.91 via a crafted recipient address"),
    ("nginx", lambda v: (0, 6, 18) <= vt(v) <= (1, 20, 0), "CVE-2021-23017", "Medium",
     "Off-by-one in the DNS resolver (only exploitable when the resolver directive is configured)"),
    ("OpenSSL", lambda v: re.fullmatch(r"1\.0\.1[a-f]?", v) is not None, "CVE-2014-0160", "High",
     "Heartbleed: memory disclosure in the TLS heartbeat extension (OpenSSL 1.0.1-1.0.1f)"),
    ("Microsoft IIS", lambda v: vt(v) == (6, 0), "CVE-2017-7269", "High",
     "Buffer overflow in the IIS 6.0 WebDAV service (unsupported product)"),
]

VERSION_CAVEAT = ("Version-based match only: distributions often backport fixes without changing "
                  "the version string, so confirm before reporting.")

# NVD (optional, --cve-online): product -> (CPE vendor, CPE product)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_MAP = {
    "vsftpd": ("beasts", "vsftpd"),
    "OpenSSH": ("openbsd", "openssh"),
    "Apache httpd": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "ProFTPD": ("proftpd", "proftpd"),
    "Exim": ("exim", "exim"),
    "OpenSSL": ("openssl", "openssl"),
    "Microsoft IIS": ("microsoft", "internet_information_services"),
}
NVD_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
_NVD = {"disabled": False, "last": 0.0, "cache": {}}

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    host: str
    port: Optional[int]
    severity: str
    title: str
    detail: str = ""
    recommendation: str = ""
    proto: str = "tcp"
    cve: str = ""


@dataclass
class PortInfo:
    port: int
    service: str
    banner: str = ""
    tls: Optional[dict] = None
    http: Optional[dict] = None
    proto: str = "tcp"
    extra: dict = field(default_factory=dict)


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    alive: bool = False
    discovery: str = ""
    ports: List[PortInfo] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_print_lock = threading.Lock()


def log(msg: str = "", err: bool = False):
    with _print_lock:
        print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def colorize(text: str, sev: str) -> str:
    return f"{SEV_COLOR[sev]}{text}{RESET}" if sys.stdout.isatty() else text


def is_internal(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local


def parse_ports(spec: str) -> List[int]:
    if spec == "quick":
        return sorted(set(QUICK_PORTS))
    if spec == "full":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = b = int(part)
        if not (1 <= a <= b <= 65535):
            raise ValueError(f"invalid port range: {part}")
        ports.update(range(a, b + 1))
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)


def expand_target(t: str, max_hosts: int, names: Dict[str, str]) -> List[str]:
    t = t.strip()
    if "/" in t:
        net = ipaddress.ip_network(t, strict=False)
        if net.num_addresses > max_hosts:
            raise ValueError(f"{t} has {net.num_addresses} addresses (limit {max_hosts}; raise --max-hosts)")
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        return [str(h) for h in hosts]
    m = re.fullmatch(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", t)
    if m:
        base, a, b = m.group(1), int(m.group(2)), int(m.group(3))
        if not (0 <= a <= b <= 255):
            raise ValueError(f"invalid range: {t}")
        return [f"{base}.{i}" for i in range(a, b + 1)]
    try:
        ipaddress.ip_address(t)
        return [t]
    except ValueError:
        pass
    if re.fullmatch(r"[\d.]+", t):
        # gethostbyname() would quietly turn "32" into 0.0.0.32
        raise ValueError("not a valid IP address; for a subnet write it as one argument, e.g. 10.98.62.0/24")
    ip = socket.gethostbyname(t)  # raises socket.gaierror on failure
    names[ip] = t
    return [ip]


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


# --------------------------------------------------------------------------- #
# Discovery & scanning
# --------------------------------------------------------------------------- #

DISCOVERY_PORTS = [80, 443, 22, 445, 135, 3389, 8080, 53]


def tcp_state(ip: str, port: int, timeout: float) -> str:
    """Return 'open', 'closed' (RST received) or 'filtered' (no answer)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "filtered"


def icmp_ping(ip: str, timeout: float) -> bool:
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), ip]
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout + 3)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def discover_host(ip: str, timeout: float, use_ping: bool) -> Optional[str]:
    """Return the method that proved the host is up, or None."""
    if use_ping and icmp_ping(ip, timeout):
        return "icmp"
    for p in DISCOVERY_PORTS:
        state = tcp_state(ip, p, timeout)
        if state in ("open", "closed"):
            return f"tcp/{p}-{state}"
    return None


def grab_banner(ip: str, port: int, timeout: float) -> str:
    if port in TLS_PORTS:
        return ""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
            data = s.recv(512)
    except OSError:
        return ""
    text = data.decode("utf-8", "replace")
    return "".join(c if c.isprintable() else " " for c in text).strip()[:160]


def identify_service(port: int, banner: str) -> str:
    b = banner.upper()
    if b.startswith("SSH-"):
        return "ssh"
    if b.startswith("HTTP/"):
        return SERVICES.get(port, "http") if port in SERVICES else "http"
    if b.startswith("220") and "FTP" in b:
        return "ftp"
    if b.startswith("220") and "SMTP" in b:
        return "smtp"
    return SERVICES.get(port, "unknown")


# --------------------------------------------------------------------------- #
# TLS / HTTP inspection
# --------------------------------------------------------------------------- #


def _unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def inspect_tls(ip: str, port: int, timeout: float, sni: Optional[str]) -> Optional[dict]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with _unverified_ctx().wrap_socket(raw, server_hostname=sni) as s:
                info = {"version": s.version(), "cipher": (s.cipher() or ("",))[0]}
                der = s.getpeercert(True)
    except (OSError, ssl.SSLError):
        return None

    # Certificate details (uses a private CPython helper; failure is non-fatal).
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            path = f.name
        try:
            cert = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            os.unlink(path)
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        info.update({
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("commonName", issuer.get("organizationName", "")),
            "not_after": cert["notAfter"],
            "days_left": int((expires - time.time()) // 86400),
            "self_signed": cert.get("subject") == cert.get("issuer"),
        })
    except Exception:
        pass

    # Legacy protocol support
    legacy = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                ctx = _unverified_ctx()
                ctx.minimum_version = ver
                ctx.maximum_version = ver
                try:
                    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                with socket.create_connection((ip, port), timeout=timeout) as raw:
                    with ctx.wrap_socket(raw, server_hostname=sni):
                        legacy.append(name)
            except (OSError, ssl.SSLError, ValueError):
                continue
    info["legacy_protocols"] = legacy
    return info


def inspect_http(ip: str, port: int, timeout: float, tls: bool, host_header: str) -> Optional[dict]:
    try:
        if tls:
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=_unverified_ctx())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        try:
            conn.request("GET", "/", headers={"Host": host_header or ip,
                                              "User-Agent": f"netaudit/{VERSION}",
                                              "Connection": "close"})
            r = conn.getresponse()
            headers = {k.lower(): v for k, v in r.getheaders()}
            r.read(1024)
            return {"status": r.status, "tls": tls, "headers": headers}
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return None


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


def udp_scan_port(ip: str, port: int, timeout: float, retries: int = 2):
    """Send the service-specific probe. Returns (state, data): open / closed / open|filtered."""
    _, payload = UDP_SERVICES[port]
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    for _ in range(retries):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.send(payload)
                return "open", s.recv(4096)
        except ConnectionRefusedError:
            return "closed", b""  # ICMP port unreachable
        except OSError:
            continue
    return "open|filtered", b""


def udp_details(port: int, data: bytes) -> dict:
    info: dict = {}
    if port == 53 and len(data) >= 12:
        info["recursion"] = (bool(data[3] & 0x80) and (data[3] & 0x0F) == 0
                             and int.from_bytes(data[6:8], "big") > 0)
    elif port == 69:
        info["valid"] = data[:2] in (b"\x00\x03", b"\x00\x05")
    elif port == 123 and len(data) >= 48:
        info["stratum"] = data[1]
    elif port == 137:
        info["nbstat"] = True
    elif port == 161:
        info["community_public"] = data[:1] == b"\x30"
        runs = [r for r in re.findall(rb"[ -~]{6,}", data) if r != b"public"]
        info["sysdescr"] = max(runs, key=len).decode("ascii", "replace")[:120] if runs else ""
    elif port == 1900:
        for line in data.decode("latin-1").split("\r\n"):
            if line.lower().startswith("server:"):
                info["server"] = line[7:].strip()
    elif port == 11211:
        info["stats"] = b"STAT" in data
    return info


def analyze_udp(host: HostResult, p: PortInfo) -> None:
    ex = p.extra

    def add(sev: str, title: str, detail: str, rec: str) -> None:
        host.findings.append(Finding(host.ip, p.port, sev, title, detail, rec, proto="udp"))

    if p.service == "snmp" and ex.get("community_public"):
        add("High", "SNMP responds to default community string 'public'", ex.get("sysdescr", ""),
            "Disable SNMPv1/v2c or set unique communities; prefer SNMPv3 with auth+priv and restrict by ACL.")
    elif p.service == "dns" and ex.get("recursion"):
        add("Medium", "DNS resolver answers recursive queries", "Recursion available to this client.",
            "Limit recursion to internal clients (allow-recursion/ACLs) to prevent abuse in amplification attacks.")
    elif p.service == "tftp" and ex.get("valid"):
        add("Medium", "TFTP service responding", "Unauthenticated, cleartext file transfer.",
            "Disable TFTP or restrict it to provisioning VLANs with read-only directories.")
    elif p.service == "ssdp":
        add("Low", "UPnP/SSDP responds to unicast discovery", ex.get("server", ""),
            "Disable UPnP on servers and edge devices; block UDP 1900 at the perimeter.")
    elif p.service == "memcached" and ex.get("stats"):
        add("High", "Memcached exposed over UDP (amplification and data exposure risk)", "",
            "Disable the UDP listener (-U 0), bind to localhost/internal only and firewall the port.")
    elif p.service == "netbios-ns":
        add("Low", "NetBIOS name service responds", "Host and workgroup names can be enumerated.",
            "Disable NetBIOS over TCP/IP where not needed; block UDP 137 at the perimeter.")
    elif p.service == "ntp":
        add("Info", "NTP service responds", f"Stratum {ex.get('stratum', '?')}.",
            "Ensure monlist/mode 7 queries are disabled and restrict queries to trusted clients.")


def detect_products(texts) -> dict:
    found: dict = {}
    for t in texts:
        for product, rx in PRODUCT_PATTERNS.items():
            m = re.search(rx, t or "", re.I)
            if m and product not in found:
                found[product] = m.group(1)
    return found


def nvd_lookup(product: str, version: str, timeout: float = 15, limit: int = 5):
    """Return [(cve_id, cvss_score, severity, description)] from the NVD API (best-effort)."""
    st = _NVD
    if st["disabled"] or product not in CPE_MAP:
        return []
    key = (product, version)
    if key in st["cache"]:
        return st["cache"][key]
    vendor, name = CPE_MAP[product]
    api_key = os.environ.get("NVD_API_KEY")
    wait = (0.7 if api_key else 6.5) - (time.time() - st["last"])  # respect NVD rate limits
    if wait > 0:
        time.sleep(wait)
    st["last"] = time.time()
    cpe = f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*"
    url = NVD_URL + "?" + urllib.parse.urlencode({"cpeName": cpe, "resultsPerPage": 100})
    headers = {"User-Agent": f"netaudit/{VERSION}"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
            data = json.load(r)
        out = []
        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            score, sev = None, ""
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = c.get("metrics", {}).get(mk)
                if m:
                    score = m[0]["cvssData"]["baseScore"]
                    sev = m[0]["cvssData"].get("baseSeverity") or m[0].get("baseSeverity", "")
                    break
            out.append((c["id"], score, NVD_SEV.get(sev.upper(), "Info"), desc))
        out.sort(key=lambda x: -(x[1] or 0))
        st["cache"][key] = out[:limit]
        return st["cache"][key]
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        st["disabled"] = True
        log("[!] NVD lookup failed (offline, blocked or rate-limited); using built-in CVE rules only.", err=True)
        return []


def analyze_versions(host: HostResult, p: PortInfo, texts, online: bool) -> None:
    seen = set()
    for product, ver in detect_products(texts).items():
        for rule_product, pred, cve, sev, desc in CVE_RULES:
            if rule_product != product:
                continue
            try:
                hit = bool(pred(ver))
            except (ValueError, AttributeError):
                hit = False
            if hit:
                seen.add(cve)
                host.findings.append(Finding(
                    host.ip, p.port, sev, f"{cve}: {product} {ver}", f"{desc}. {VERSION_CAVEAT}",
                    f"Upgrade {product} to a patched release; for distro packages check the vendor advisory.",
                    proto=p.proto, cve=cve))
        if online:
            for cid, score, sev, desc in nvd_lookup(product, ver):
                if cid in seen:
                    continue
                seen.add(cid)
                host.findings.append(Finding(
                    host.ip, p.port, sev, f"{cid} (NVD, CVSS {score}): {product} {ver}",
                    f"{desc[:200]} {VERSION_CAVEAT}",
                    "Review the advisory, confirm applicability to your build/config, then patch or mitigate.",
                    proto=p.proto, cve=cid))


def _pl(keys) -> list:
    return [f"{port}/{proto}" for proto, port in sorted(keys)]


def diff_reports(old: dict, new: dict) -> dict:
    """Compare two netaudit JSON reports."""
    def pmap(h):
        return {(p.get("proto", "tcp"), p["port"]): p for p in h.get("ports", [])}

    def fmap(h):
        return {(f.get("proto", "tcp"), f.get("port") or 0, f["title"]): f for f in h.get("findings", [])}

    def fsum(f):
        return {"severity": f["severity"], "port": f.get("port"), "proto": f.get("proto", "tcp"),
                "title": f["title"]}

    def fsorted(m, keys):
        return [fsum(m[k]) for k in sorted(keys, key=lambda k: (SEV_ORDER[m[k]["severity"]], k[1], k[2]))]

    oh = {h["ip"]: h for h in old.get("hosts", [])}
    nh = {h["ip"]: h for h in new.get("hosts", [])}
    d = {"old_started": old.get("started"), "new_started": new.get("started"),
         "new_hosts": [], "gone_hosts": sorted(set(oh) - set(nh)), "changed_hosts": {}}
    for ip in sorted(set(nh) - set(oh)):
        h = nh[ip]
        d["new_hosts"].append({"ip": ip, "ports": _pl(pmap(h)),
                               "findings": [fsum(f) for f in h.get("findings", [])]})
    for ip in sorted(set(oh) & set(nh)):
        op, np_, of, nf = pmap(oh[ip]), pmap(nh[ip]), fmap(oh[ip]), fmap(nh[ip])
        common = sorted(op.keys() & np_.keys())
        change = {
            "opened": _pl(np_.keys() - op.keys()),
            "closed": _pl(op.keys() - np_.keys()),
            "service_changed": [{"port": f"{k[1]}/{k[0]}", "old": op[k]["service"], "new": np_[k]["service"]}
                                for k in common if op[k]["service"] != np_[k]["service"]],
            "cert_changed": [],
            "new_findings": fsorted(nf, nf.keys() - of.keys()),
            "resolved_findings": fsorted(of, of.keys() - nf.keys()),
        }
        for k in common:
            ot, nt = op[k].get("tls") or {}, np_[k].get("tls") or {}
            if ot and nt and (ot.get("subject"), ot.get("not_after")) != (nt.get("subject"), nt.get("not_after")):
                change["cert_changed"].append({
                    "port": f"{k[1]}/{k[0]}",
                    "old": f"{ot.get('subject')} (expires {ot.get('not_after')})",
                    "new": f"{nt.get('subject')} (expires {nt.get('not_after')})"})
        if any(change.values()):
            d["changed_hosts"][ip] = change
    bad = {"Critical", "High", "Medium"}
    d["regression"] = bool(d["new_hosts"]) or any(
        c["opened"] or any(f["severity"] in bad for f in c["new_findings"])
        for c in d["changed_hosts"].values())
    return d


def print_diff(d: dict, label: str = "") -> None:
    log("\n" + "=" * 72)
    log("Changes" + (f" ({label})" if label else ""))
    if not (d["new_hosts"] or d["gone_hosts"] or d["changed_hosts"]):
        log("  No changes detected.")
        return
    for h in d["new_hosts"]:
        log(f"  [+] New host {h['ip']}: open {', '.join(h['ports']) or 'none'}; {len(h['findings'])} finding(s)")
    for ip in d["gone_hosts"]:
        log(f"  [-] Host not seen this time: {ip}")
    for ip, c in d["changed_hosts"].items():
        log(f"  Host {ip}")
        for p in c["opened"]:
            log(f"    [+] port opened: {p}")
        for p in c["closed"]:
            log(f"    [-] port closed: {p}")
        for s in c["service_changed"]:
            log(f"    [~] service changed on {s['port']}: {s['old']} -> {s['new']}")
        for s in c["cert_changed"]:
            log(f"    [~] TLS certificate changed on {s['port']}: {s['old']} -> {s['new']}")
        for f in c["new_findings"]:
            log(f"    [+] NEW {colorize(f['severity'].upper(), f['severity'])}: {f['title']} ({f['port']}/{f['proto']})")
        for f in c["resolved_findings"]:
            log(f"    [-] RESOLVED {f['severity']}: {f['title']} ({f['port']}/{f['proto']})")
    log("Result: " + ("REGRESSION - new exposure detected" if d["regression"] else "no regressions"))


def run_diff_mode(args) -> int:
    old_path, new_path = args.diff
    try:
        with open(old_path, encoding="utf-8") as a, open(new_path, encoding="utf-8") as b:
            old, new = json.load(a), json.load(b)
    except (OSError, ValueError) as exc:
        log(f"[!] Cannot read reports: {exc}", err=True)
        return 2
    if old.get("tool") != "netaudit" or new.get("tool") != "netaudit":
        log("[!] Both files must be JSON reports produced by netaudit.", err=True)
        return 2
    d = diff_reports(old, new)
    print_diff(d, f"{old_path} -> {new_path}")
    if args.output:
        with open(args.output + ".diff.json", "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)
        log(f"[+] Diff written: {args.output}.diff.json")
    return 4 if d["regression"] else 0


def analyze(host: HostResult, online: bool = False) -> None:
    f = host.findings
    for p in host.ports:
        if p.proto == "udp":
            analyze_udp(host, p)
            continue
        if p.port in RISKY:
            sev, title, rec = RISKY[p.port]
            f.append(Finding(host.ip, p.port, sev, title, f"Port {p.port}/tcp ({p.service}) is reachable.", rec))

        if p.banner and re.search(r"\d+\.\d+", p.banner) and not p.banner.upper().startswith("HTTP/"):
            f.append(Finding(host.ip, p.port, "Info", "Service banner discloses software/version",
                             p.banner, "Suppress or genericise version strings where possible."))

        if p.tls:
            t = p.tls
            if t.get("days_left") is not None:
                if t["days_left"] < 0:
                    f.append(Finding(host.ip, p.port, "High", "TLS certificate expired",
                                     f"Expired {-t['days_left']} day(s) ago ({t.get('not_after')}).",
                                     "Renew and deploy a valid certificate."))
                elif t["days_left"] < 30:
                    f.append(Finding(host.ip, p.port, "Medium", "TLS certificate expires soon",
                                     f"{t['days_left']} day(s) remaining ({t.get('not_after')}).",
                                     "Renew the certificate; consider automated renewal."))
            if t.get("self_signed"):
                f.append(Finding(host.ip, p.port, "Medium", "Self-signed TLS certificate",
                                 f"Subject/issuer: {t.get('subject')}",
                                 "Use a certificate from a trusted CA (or an internal CA distributed to clients)."))
            if t.get("legacy_protocols"):
                f.append(Finding(host.ip, p.port, "Medium", "Deprecated TLS protocol versions enabled",
                                 ", ".join(t["legacy_protocols"]),
                                 "Disable TLS 1.0/1.1; allow TLS 1.2+ only."))
            if t.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
                f.append(Finding(host.ip, p.port, "High", "Weak TLS version negotiated", t["version"],
                                 "Allow TLS 1.2+ only."))

        if p.http:
            h = p.http["headers"]
            for name, (sev, title) in SECURITY_HEADERS.items():
                if name not in h:
                    f.append(Finding(host.ip, p.port, sev, title, "", f"Add the {name} response header."))
            if p.http["tls"] and "strict-transport-security" not in h:
                f.append(Finding(host.ip, p.port, "Low", "Missing Strict-Transport-Security header", "",
                                 "Add HSTS (e.g. max-age=31536000; includeSubDomains)."))
            if not p.http["tls"] and p.http["status"] not in (301, 302, 307, 308):
                f.append(Finding(host.ip, p.port, "Low", "Web service available over plain HTTP",
                                 f"HTTP {p.http['status']} without redirect to HTTPS.",
                                 "Redirect to HTTPS and enable HSTS."))
            for hn in ("server", "x-powered-by", "x-aspnet-version"):
                if hn in h:
                    f.append(Finding(host.ip, p.port, "Info", f"Technology disclosure via {hn} header", h[hn],
                                     "Remove or genericise this header."))

        texts = [p.banner]
        if p.http:
            texts += [p.http["headers"].get(k, "") for k in ("server", "x-powered-by")]
        analyze_versions(host, p, texts, online)
    f.sort(key=lambda x: (SEV_ORDER[x.severity], x.proto, x.port or 0))


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def enrich_port(host: HostResult, port: int, args) -> PortInfo:
    banner = "" if args.no_banner else grab_banner(host.ip, port, args.timeout)
    info = PortInfo(port=port, service=identify_service(port, banner), banner=banner)
    sni = host.hostname or None
    if not args.no_tls and port in TLS_PORTS:
        info.tls = inspect_tls(host.ip, port, args.timeout, sni)
    is_web = port in HTTP_PORTS or port in TLS_WEB_PORTS or banner.upper().startswith("HTTP/")
    if not args.no_http and is_web:
        info.http = inspect_http(host.ip, port, args.timeout + 1, port in TLS_WEB_PORTS,
                                 host.hostname)
    return info


def run_scan(args, ips: List[str], names: Dict[str, str], ports: List[int]) -> List[HostResult]:
    results: Dict[str, HostResult] = {ip: HostResult(ip=ip, hostname=names.get(ip, "")) for ip in ips}

    # 1. Discovery
    if args.skip_discovery:
        for r in results.values():
            r.alive, r.discovery = True, "skipped"
    else:
        log(f"[*] Host discovery on {len(ips)} address(es)...")
        with cf.ThreadPoolExecutor(max_workers=min(args.threads, 256)) as ex:
            futs = {ex.submit(discover_host, ip, args.timeout, not args.no_ping): ip for ip in ips}
            for fu in cf.as_completed(futs):
                method = fu.result()
                r = results[futs[fu]]
                if method:
                    r.alive, r.discovery = True, method
    alive = [r for r in results.values() if r.alive]
    log(f"[+] {len(alive)} host(s) up")
    for r in alive:
        if not r.hostname:
            r.hostname = reverse_dns(r.ip)

    # 2. Port scan
    jobs = [(r.ip, p) for r in alive for p in ports]
    open_ports: Dict[str, List[int]] = {r.ip: [] for r in alive}
    if jobs:
        log(f"[*] Scanning {len(jobs)} ip:port pair(s) with {args.threads} threads...")
        done = 0

        def work(job):
            if args.delay:
                time.sleep(args.delay)
            return job, tcp_state(job[0], job[1], args.timeout)

        with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for fu in cf.as_completed([ex.submit(work, j) for j in jobs]):
                (ip, port), state = fu.result()
                done += 1
                if state == "open":
                    open_ports[ip].append(port)
                if len(jobs) > 2000 and done % 2000 == 0:
                    log(f"    ... {done}/{len(jobs)}", err=True)

    # 2b. UDP probing (service-specific; only ports that answered are reported as open)
    if args.udp and alive:
        udp_ports = [p for p in (parse_ports(args.udp_ports) if args.udp_ports else sorted(UDP_SERVICES))
                     if p in UDP_SERVICES]
        log(f"[*] UDP probing {len(udp_ports)} port(s) on {len(alive)} host(s)...")
        with cf.ThreadPoolExecutor(max_workers=min(args.threads, 64)) as ex:
            ufuts = {ex.submit(udp_scan_port, r.ip, p, args.timeout): (r, p) for r in alive for p in udp_ports}
            for fu in cf.as_completed(ufuts):
                r, p = ufuts[fu]
                state, data = fu.result()
                if state == "open":
                    r.ports.append(PortInfo(port=p, service=UDP_SERVICES[p][0], proto="udp",
                                            extra=udp_details(p, data)))

    # 3. Enrichment
    enrich_jobs = [(results[ip], p) for ip, pl in open_ports.items() for p in pl]
    if enrich_jobs:
        log(f"[*] Fingerprinting {len(enrich_jobs)} open port(s)...")
        with cf.ThreadPoolExecutor(max_workers=min(args.threads, 64)) as ex:
            futs = {ex.submit(enrich_port, h, p, args): (h, p) for h, p in enrich_jobs}
            for fu in cf.as_completed(futs):
                futs_host, _ = futs[fu]
                futs_host.ports.append(fu.result())
    for r in alive:
        r.ports.sort(key=lambda x: (x.proto, x.port))
        analyze(r, args.cve_online)
    return sorted(results.values(), key=lambda r: ipaddress.ip_address(r.ip))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def summary_counts(hosts: List[HostResult]) -> Dict[str, int]:
    c = {s: 0 for s in SEV_ORDER}
    for h in hosts:
        for f in h.findings:
            c[f.severity] += 1
    return c


def print_console(hosts: List[HostResult]) -> None:
    log("\n" + "=" * 72)
    for h in hosts:
        if not h.alive:
            continue
        name = f" ({h.hostname})" if h.hostname else ""
        log(f"\nHost {h.ip}{name}   [discovered via {h.discovery}]")
        if not h.ports:
            log("  No open ports found in the scanned range.")
            continue
        log(f"  {'PORT':<11}{'SERVICE':<16}DETAILS")
        for p in h.ports:
            extra = ""
            if p.proto == "udp":
                extra = "; ".join(f"{k}={v}" for k, v in p.extra.items() if v not in ("", None))[:60]
            elif p.tls:
                extra = f"{p.tls.get('version', '')} {p.tls.get('cipher', '')}".strip()
            elif p.banner:
                extra = p.banner[:60]
            log(f"  {str(p.port) + '/' + p.proto:<11}{p.service:<16}{extra}")
        if h.findings:
            log("  Findings:")
            for f in h.findings:
                where = f":{f.port}/{f.proto}" if f.port else ""
                log(f"    [{colorize(f.severity.upper(), f.severity)}] {h.ip}{where} - {f.title}")
    c = summary_counts(hosts)
    log("\n" + "=" * 72)
    log("Summary: " + ", ".join(f"{k}: {v}" for k, v in c.items()))


def build_report(args, hosts, started, finished, ports) -> dict:
    return {
        "tool": "netaudit", "version": VERSION,
        "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"),
        "targets": args.targets or [args.input_list],
        "ports_scanned": len(ports),
        "summary": summary_counts(hosts),
        "hosts": [asdict(h) for h in hosts if h.alive],
    }


def write_json(path: str, report: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def write_csv(path: str, hosts: List[HostResult]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "hostname", "port", "proto", "severity", "cve", "title", "detail", "recommendation"])
        for h in hosts:
            for f in h.findings:
                w.writerow([h.ip, h.hostname, f.port or "", f.proto, f.severity, f.cve, f.title, f.detail,
                            f.recommendation])


def write_html(path: str, report: dict, hosts: List[HostResult]) -> None:
    e = html.escape
    colors = {"Critical": "#7b1fa2", "High": "#d32f2f", "Medium": "#f57c00", "Low": "#0288d1", "Info": "#757575"}
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<title>netaudit report</title><style>",
        "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1000px;padding:0 1rem;color:#222}",
        "table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}",
        "th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:14px;vertical-align:top}",
        "th{background:#f5f5f5}.badge{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px}",
        ".cards{display:flex;gap:.75rem;flex-wrap:wrap}.card{border:1px solid #ddd;border-radius:8px;padding:.6rem 1rem}",
        "code{background:#f2f2f2;padding:1px 4px;border-radius:3px}</style></head><body>",
        "<h1>Network Discovery &amp; Security Assessment</h1>",
        f"<p>Generated by netaudit v{VERSION} &middot; {e(report['started'])} &rarr; {e(report['finished'])}"
        f" &middot; {report['ports_scanned']} ports per host</p><div class='cards'>",
    ]
    for sev, n in report["summary"].items():
        out.append(f"<div class='card'><b style='color:{colors[sev]}'>{n}</b><br>{sev}</div>")
    out.append("</div>")
    for h in hosts:
        if not h.alive:
            continue
        out.append(f"<h2>{e(h.ip)} <small>{e(h.hostname)}</small></h2>")
        if h.ports:
            out.append("<table><tr><th>Port</th><th>Service</th><th>Banner / TLS</th></tr>")
            for p in h.ports:
                det = p.banner
                if p.proto == "udp":
                    det = ", ".join(f"{k}={v}" for k, v in p.extra.items() if v not in ("", None))
                elif p.tls:
                    det = f"{p.tls.get('version', '')} {p.tls.get('cipher', '')} | cert: {p.tls.get('subject', '')}"
                out.append(f"<tr><td>{p.port}/{p.proto}</td><td>{e(p.service)}</td><td><code>{e(det)}</code></td></tr>")
            out.append("</table>")
        else:
            out.append("<p>No open ports found.</p>")
        if h.findings:
            out.append("<table><tr><th>Severity</th><th>Port</th><th>Finding</th><th>Recommendation</th></tr>")
            for f in h.findings:
                badge = f"<span class='badge' style='background:{colors[f.severity]}'>{f.severity}</span>"
                detail = f"<br><small>{e(f.detail)}</small>" if f.detail else ""
                out.append(f"<tr><td>{badge}</td><td>{f.port or ''}</td><td>{e(f.title)}{detail}</td>"
                           f"<td>{e(f.recommendation)}</td></tr>")
            out.append("</table>")
    out.append("<p><small>Findings are indicators from non-intrusive checks and should be manually validated.</small></p>")
    out.append("</body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="netaudit",
        description="Network Discovery & Security Assessment Tool (use only with authorization).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n  netaudit.py 192.168.1.0/24 -p quick -o lan\n"
                "  netaudit.py 10.0.0.5 -p 1-1024,8080 --format json,html\n"
                "  netaudit.py 10.0.0.5 --udp --cve-online\n"
                "  netaudit.py --diff old.json new.json\n\n"
                "Exit codes: 0 ok, 2 input error, 3 unauthorized target, 4 regression (--diff/--baseline)"),
    )
    ap.add_argument("targets", nargs="*", help="IP, hostname, CIDR (10.0.0.0/24) or range (10.0.0.1-50)")
    ap.add_argument("-iL", "--input-list", help="file with one target per line")
    ap.add_argument("-p", "--ports", default="quick", help="quick | full | e.g. 22,80,443 or 1-1024 (default: quick)")
    ap.add_argument("-t", "--threads", type=int, default=100, help="worker threads (default 100)")
    ap.add_argument("--timeout", type=float, default=1.0, help="per-connection timeout in seconds (default 1.0)")
    ap.add_argument("--delay", type=float, default=0.0, help="delay before each probe, to throttle (seconds)")
    ap.add_argument("-Pn", "--skip-discovery", action="store_true", help="treat all targets as up")
    ap.add_argument("--no-ping", action="store_true", help="disable ICMP, use TCP probes only")
    ap.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    ap.add_argument("--no-tls", action="store_true", help="skip TLS inspection")
    ap.add_argument("--no-http", action="store_true", help="skip HTTP header checks")
    ap.add_argument("--udp", action="store_true",
                    help="also probe UDP services (DNS, TFTP, NTP, NetBIOS, SNMP, SSDP, memcached)")
    ap.add_argument("--udp-ports", help="comma list of UDP ports to probe (default: all supported)")
    ap.add_argument("--cve-online", action="store_true",
                    help="also query NVD for CVEs matching detected versions (needs internet; "
                         "set NVD_API_KEY for a higher rate limit)")
    ap.add_argument("--baseline", help="previous JSON report; show changes against it after the scan")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), help="compare two JSON reports (no scan)")
    ap.add_argument("--max-hosts", type=int, default=1024, help="safety cap on addresses per CIDR (default 1024)")
    ap.add_argument("-o", "--output", help="output file prefix (no extension)")
    ap.add_argument("--format", default="json,html,csv", help="comma list of json,html,csv (with -o)")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you have permission to scan non-private targets")
    ap.add_argument("--version", action="version", version=f"netaudit {VERSION}")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.diff:
        return run_diff_mode(args)
    raw_targets = list(args.targets)
    if args.input_list:
        try:
            with open(args.input_list, encoding="utf-8") as fh:
                raw_targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as exc:
            log(f"[!] Cannot read {args.input_list}: {exc}", err=True)
            return 2
    if not raw_targets:
        log("[!] No targets given. See --help.", err=True)
        return 2

    try:
        ports = parse_ports(args.ports)
        if args.udp_ports:
            unsupported = [p for p in parse_ports(args.udp_ports) if p not in UDP_SERVICES]
            if unsupported:
                log(f"[!] No UDP probe for port(s) {unsupported}; supported: {sorted(UDP_SERVICES)}", err=True)
    except ValueError as exc:
        log(f"[!] {exc}", err=True)
        return 2

    names: Dict[str, str] = {}
    ips: List[str] = []
    for t in raw_targets:
        try:
            ips += expand_target(t, args.max_hosts, names)
        except (ValueError, socket.gaierror) as exc:
            log(f"[!] Skipping '{t}': {exc}", err=True)
    ips = list(dict.fromkeys(ips))
    if not ips:
        log("[!] No valid targets.", err=True)
        return 2
    if len(ips) > args.max_hosts:
        log(f"[!] {len(ips)} targets exceeds --max-hosts {args.max_hosts}.", err=True)
        return 2

    external = [ip for ip in ips if not is_internal(ip)]
    if external and not args.authorized:
        log(f"[!] {len(external)} target(s) are outside private/loopback ranges (e.g. {external[0]}).\n"
            "    Scanning systems without permission may be illegal. If you are authorized, re-run with --authorized.",
            err=True)
        return 3

    log(f"netaudit v{VERSION} - {len(ips)} target(s), {len(ports)} port(s) each")
    started = dt.datetime.now()
    hosts = run_scan(args, ips, names, ports)
    finished = dt.datetime.now()

    print_console(hosts)

    report = build_report(args, hosts, started, finished, ports)
    regression = False
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                old = json.load(fh)
            if old.get("tool") != "netaudit":
                raise ValueError("not a netaudit JSON report")
            d = diff_reports(old, report)
            report["diff"] = d
            print_diff(d, f"vs baseline {args.baseline}")
            regression = d["regression"]
        except (OSError, ValueError) as exc:
            log(f"[!] Could not use baseline {args.baseline}: {exc}", err=True)

    if args.output:
        fmts = {f.strip().lower() for f in args.format.split(",")}
        if "json" in fmts:
            write_json(args.output + ".json", report)
        if "html" in fmts:
            write_html(args.output + ".html", report, hosts)
        if "csv" in fmts:
            write_csv(args.output + ".csv", hosts)
        log("[+] Reports written: " + ", ".join(f"{args.output}.{f}" for f in sorted(fmts)
                                                if f in ("json", "html", "csv")))
    log(f"[+] Completed in {(finished - started).total_seconds():.1f}s")
    return 4 if regression else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\n[!] Interrupted.", err=True)
        sys.exit(130)
