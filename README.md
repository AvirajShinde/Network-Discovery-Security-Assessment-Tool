# Network Discovery & Security Assessment Tool

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

A single-file, dependency-free Python tool that discovers hosts on a network, scans their ports, fingerprints the services it finds, and turns the results into a prioritised list of security findings with remediation advice. Reports can be saved as JSON, HTML or CSV, and two scans can be compared to see what changed.

> **Authorised use only.** Scan only systems you own or have explicit written permission to test. See [Legal & Ethical Use](#legal--ethical-use).

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Command-Line Options](#command-line-options)
- [What It Checks](#what-it-checks)
- [Sample Output](#sample-output)
- [Reports](#reports)
- [Comparing Scans (Change Tracking)](#comparing-scans-change-tracking)
- [Exit Codes](#exit-codes)
- [Limitations](#limitations)
- [Legal & Ethical Use](#legal--ethical-use)
- [Roadmap](#roadmap)

---

## Features

| Area | Details |
|------|---------|
| **Target input** | Single IP, hostname, CIDR (`10.0.0.0/24`), range (`10.0.0.1-50`) or a file of targets |
| **Host discovery** | ICMP ping plus TCP probes. A refused connection (RST) also proves a host is up, which catches hosts that block ping |
| **Port scanning** | Multithreaded TCP connect scan with `quick` (48 common ports), `full` (1-65535) or custom ranges |
| **UDP probing** | Service-specific probes for DNS, TFTP, NTP, NetBIOS, SNMP, SSDP and memcached |
| **Service detection** | Port-to-service mapping refined by banner grabbing |
| **TLS inspection** | Negotiated version and cipher, certificate expiry, self-signed certificates, legacy TLS 1.0/1.1 support |
| **HTTP inspection** | Missing security headers, plain-HTTP exposure, server/technology disclosure |
| **CVE matching** | Built-in version rules, plus optional live lookup against the NVD API |
| **Risk findings** | Exposed admin, database and legacy services rated Critical / High / Medium / Low / Info with fixes |
| **Reporting** | Colour console summary, JSON, HTML and CSV |
| **Change tracking** | Compare scans over time with regression-aware exit codes, suitable for scheduled jobs |
| **Safety controls** | Refuses non-private targets without `--authorized`, host-count cap, throttling option |

---

## How It Works

```
Targets ──► Host discovery ──► TCP port scan ──► UDP probes
                                     │
                                     ▼
                  Banner grab ─► TLS check ─► HTTP check
                                     │
                                     ▼
              Findings engine (risky ports, TLS/HTTP issues, CVE rules)
                                     │
                                     ▼
                Console summary · JSON · HTML · CSV · Diff
```

1. **Discovery.** Each address is tested with ICMP and a handful of TCP ports. Any reply or refusal marks the host as up.
2. **Scanning.** Live hosts are scanned in parallel using TCP connect probes. If `--udp` is set, each supported UDP service gets a protocol-specific probe.
3. **Fingerprinting.** Open ports are banner-grabbed. TLS ports are inspected for protocol and certificate problems, and web ports are checked for security headers.
4. **Analysis.** Results are turned into findings with a severity and a recommendation. Detected software versions are matched against known-vulnerable releases.
5. **Reporting.** Output is printed to the console and optionally written to files.

---

## Requirements

- Python **3.8 or newer**
- No third-party packages. Everything uses the Python standard library.
- The system `ping` command for ICMP discovery. It is built into Linux, macOS and Windows. If it is missing, the tool falls back to TCP probes (or use `--no-ping`).
- Internet access only for the optional `--cve-online` feature.
- No root or administrator rights are needed for normal use.

---

## Installation

```bash
git clone https://github.com/AvirajShinde/Network-Discovery-Security-Assessment-Tool.git
cd Network-Discovery-Security-Assessment-Tool
python3 netaudit.py --help
```

Optionally make it executable on Linux/macOS:

```bash
chmod +x netaudit.py
./netaudit.py --help
```

On Windows, use `py netaudit.py --help`.

---

## Quick Start

```bash
# Scan your own machine
python3 netaudit.py 127.0.0.1

# Scan a home/lab subnet and save HTML, JSON and CSV reports (lan.html, lan.json, lan.csv)
python3 netaudit.py 192.168.1.0/24 -o lan
```

To find your subnet on Linux, run `ip a` and use the network part of your address. For example, `192.168.1.15/24` means the subnet is `192.168.1.0/24`.

> The prefix length is part of the target. Write `192.168.1.0/24` as **one** argument, with no spaces.

---

## Usage

```bash
# Standard scan of the quick port list
python3 netaudit.py 192.168.1.0/24

# Custom ports and a longer timeout for slow networks
python3 netaudit.py 10.0.0.5 -p 1-1024,8080,8443 --timeout 1.5 -t 200

# All 65535 ports on one host
python3 netaudit.py 10.0.0.5 -p full

# Include UDP services and online CVE lookups
python3 netaudit.py 192.168.1.10 --udp --cve-online

# Targets from a file (one per line, '#' for comments)
python3 netaudit.py -iL targets.txt -o weekly

# Skip host discovery (treat every target as up), useful for hosts that drop all probes
python3 netaudit.py 10.0.0.5 -Pn

# Throttle probes on fragile networks
python3 netaudit.py 192.168.1.0/24 -t 20 --delay 0.05

# Authorised scan of a public address (required flag)
python3 netaudit.py 203.0.113.10 --authorized -o client_scan

# Compare with an earlier scan
python3 netaudit.py 192.168.1.0/24 --baseline last_week.json -o today
python3 netaudit.py --diff last_week.json today.json
```

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `targets` | IP, hostname, CIDR or range (`10.0.0.1-50`). Multiple allowed |
| `-iL`, `--input-list FILE` | Read targets from a file, one per line |
| `-p`, `--ports SPEC` | `quick` (default), `full`, or a list such as `22,80,443` or `1-1024` |
| `-t`, `--threads N` | Worker threads (default 100) |
| `--timeout SEC` | Per-connection timeout in seconds (default 1.0) |
| `--delay SEC` | Delay before each probe, to throttle the scan |
| `-Pn`, `--skip-discovery` | Treat all targets as up |
| `--no-ping` | Use TCP probes only for discovery |
| `--no-banner` | Skip banner grabbing |
| `--no-tls` | Skip TLS inspection |
| `--no-http` | Skip HTTP header checks |
| `--udp` | Also probe UDP services (DNS, TFTP, NTP, NetBIOS, SNMP, SSDP, memcached) |
| `--udp-ports LIST` | Limit UDP probing to specific ports |
| `--cve-online` | Also query NVD for CVEs matching detected versions. Set the `NVD_API_KEY` environment variable for a higher rate limit |
| `--baseline FILE` | Compare this scan with a previous JSON report |
| `--diff OLD NEW` | Compare two JSON reports without scanning |
| `--max-hosts N` | Safety cap on addresses per CIDR (default 1024) |
| `-o`, `--output PREFIX` | Write reports using this file name prefix |
| `--format LIST` | Report formats: `json,html,csv` (default all three) |
| `--authorized` | Confirm permission to scan non-private targets |
| `--version` | Show the version |

---

## What It Checks

### Exposed services

Findings are raised for reachable services that are commonly risky when exposed, with a recommended fix for each:

| Severity | Examples |
|----------|----------|
| **Critical** | Docker API without TLS (2375) |
| **High** | Telnet, SMB / NetBIOS, RDP, VNC, Redis, Elasticsearch, Memcached, MongoDB |
| **Medium** | FTP, rpcbind, MSRPC, NFS, MySQL, PostgreSQL, MSSQL, Oracle, Kibana, WinRM |
| **Low** | Cleartext POP3 / IMAP / LDAP, PPTP |

### UDP probes

| Port | Service | Finding |
|------|---------|---------|
| 53 | DNS | Open recursive resolver (Medium) |
| 69 | TFTP | Unauthenticated service responding (Medium) |
| 123 | NTP | Service responds (Info) |
| 137 | NetBIOS-NS | Name service exposed (Low) |
| 161 | SNMP | Responds to community `public` (High) |
| 1900 | SSDP/UPnP | Responds to unicast discovery (Low) |
| 11211 | Memcached | Exposed over UDP (High) |

### TLS

- Expired certificate (High) or expiring within 30 days (Medium)
- Self-signed certificate (Medium)
- TLS 1.0 / 1.1 still enabled (Medium)

### HTTP

- Missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and (on HTTPS) `Strict-Transport-Security`
- Web service reachable over plain HTTP without a redirect
- Technology disclosure via `Server`, `X-Powered-By` and `X-AspNet-Version`

### CVE matching

Banners and HTTP headers are parsed for product versions and checked against built-in rules:

| Product | Rule |
|---------|------|
| vsftpd 2.3.4 | CVE-2011-2523 (backdoor) |
| Apache httpd 2.4.49 / 2.4.50 | CVE-2021-41773 / CVE-2021-42013 |
| OpenSSH 8.5 to 9.7 | CVE-2024-6387 (regreSSHion) |
| OpenSSH up to 7.7 | CVE-2018-15473 (user enumeration) |
| ProFTPD 1.3.5 | CVE-2015-3306 |
| Exim 4.87 to 4.91 | CVE-2019-10149 |
| nginx 0.6.18 to 1.20.0 | CVE-2021-23017 |
| OpenSSL 1.0.1 to 1.0.1f | CVE-2014-0160 (Heartbleed) |
| Microsoft IIS 6.0 | CVE-2017-7269 |

With `--cve-online`, the tool also asks the NVD for the highest-scoring CVEs that match each detected product and version.

> CVE matches are **version-based**. Linux distributions often backport security fixes without changing the version string, so treat these as leads to verify, not confirmed vulnerabilities.

---

## Sample Output

The following was produced against a deliberately vulnerable local test lab of fake services:

```
netaudit v1.1.0 - 1 target(s), 4 port(s) each
[*] Host discovery on 1 address(es)...
[+] 1 host(s) up
[*] Scanning 4 ip:port pair(s) with 100 threads...
[*] UDP probing 7 port(s) on 1 host(s)...
[*] Fingerprinting 4 open port(s)...

========================================================================

Host 127.0.0.1 (localhost)   [discovered via tcp/80-closed]
  PORT       SERVICE         DETAILS
  21/tcp     ftp             220 (vsFTPd 2.3.4)
  22/tcp     ssh             SSH-2.0-OpenSSH_9.6p1 Ubuntu-3
  6379/tcp   redis
  8080/tcp   http-proxy      HTTP/1.0 200 OK  Server: Apache/2.4.49 (Unix)
  53/udp     dns             recursion=True
  161/udp    snmp            community_public=True
  11211/udp  memcached       stats=True
  Findings:
    [CRITICAL] 127.0.0.1:21/tcp - CVE-2011-2523: vsftpd 2.3.4
    [CRITICAL] 127.0.0.1:8080/tcp - CVE-2021-41773: Apache httpd 2.4.49
    [HIGH] 127.0.0.1:22/tcp - CVE-2024-6387: OpenSSH 9.6
    [HIGH] 127.0.0.1:6379/tcp - Redis exposed (often unauthenticated)
    [HIGH] 127.0.0.1:161/udp - SNMP responds to default community string 'public'
    ...
========================================================================
Summary: Critical: 2, High: 4, Medium: 3, Low: 5, Info: 5
```

---

## Reports

When `-o PREFIX` is given, reports are written next to the script:

| File | Contents |
|------|----------|
| `PREFIX.json` | Complete machine-readable results (hosts, ports, TLS/HTTP details, findings, summary) |
| `PREFIX.html` | Self-contained, shareable report with severity colouring |
| `PREFIX.csv` | One row per finding, ready for spreadsheets or ticketing systems |

Choose formats with `--format json,html` (for example).

---

## Comparing Scans (Change Tracking)

Run the tool regularly and compare results to spot new exposure:

```bash
python3 netaudit.py 192.168.1.0/24 -o monday
python3 netaudit.py 192.168.1.0/24 --baseline monday.json -o friday
# or compare two existing reports
python3 netaudit.py --diff monday.json friday.json
```

The comparison lists:

- New hosts, and hosts no longer seen
- Ports opened or closed
- Services or TLS certificates that changed
- New and resolved findings

A **regression** is a new host, a newly opened port, or a new Medium-or-higher finding. It makes the tool exit with code `4`, so it can be used in cron jobs or CI pipelines.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Completed successfully (no regression) |
| `2` | Usage or input error (bad target, bad port list, unreadable file) |
| `3` | Non-private target given without `--authorized` |
| `4` | Regression found by `--baseline` or `--diff` |
| `130` | Interrupted by the user (Ctrl+C) |

---

## Limitations

- **TCP connect scanning only.** There is no raw-socket SYN scan, so scans are slower and more visible in logs than with tools like Nmap, but they need no elevated privileges.
- **UDP is best-effort.** Only ports that answer a probe are reported. A silent port could be open, filtered or closed and is not listed.
- **CVE results are indicative.** Version matching cannot see vendor backports. The built-in rule set is small and covers well-known issues only.
- **Certificate details** are decoded with a CPython-internal helper. If it is unavailable in your Python build, certificate expiry and self-signed checks are skipped, while protocol and cipher checks still work.
- **IPv4-focused.** Hostnames resolve to IPv4, and CIDR/range expansion is designed around IPv4.
- **Environment artefacts.** Networks where a firewall or proxy answers on behalf of other hosts can make dead addresses look alive.
- Findings come from non-intrusive checks. Always validate them manually before reporting.

---

## Legal & Ethical Use

Port scanning and security testing without permission may be illegal in your jurisdiction. This tool is provided for **education and authorised security assessments** on networks and systems you own or are explicitly permitted to test in writing.

- Targets outside private, loopback and link-local ranges are refused unless you pass `--authorized`. That flag is your confirmation that you hold written permission.
- The tool performs no exploitation, brute-forcing or denial-of-service activity.
- The authors accept no liability for misuse or damage.

---

## Roadmap

- Raw-socket SYN scanning (optional, with elevated privileges)
- Larger and regularly updated CVE rule set
- IPv6 target expansion
- HTML section for scan-to-scan diffs
- Additional service-specific checks (SSH algorithms, SMB signing, default web credentials pages)

---

## Contributing

Issues and pull requests are welcome. Please keep the tool dependency-free and non-intrusive.

## License

Add a `LICENSE` file of your choice (for example MIT) before publishing.
