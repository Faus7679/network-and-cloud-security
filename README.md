# network-and-cloud-security

A Python command-line tool that scans a network for open ports, running services, and known vulnerabilities.

## Features

- **Port scanning** – TCP SYN or connect scan across any port range using [Nmap](https://nmap.org/) via the `python-nmap` wrapper.
- **Service & version detection** – Identifies the software and version running on each open port.
- **Vulnerability checks** – Cross-references detected services and versions against a built-in table of known CVEs and insecure-service warnings.
- **OS fingerprinting** – Optional OS detection (`--os` flag).
- **ARP host discovery** – Uses [Scapy](https://scapy.net/) to discover live hosts on a local LAN segment before scanning.
- **Nmap vuln scripts** – Optionally runs Nmap's built-in `--script=vuln` suite for a deeper scan.
- **Text & JSON output** – Save the report to a file in human-readable or JSON format.

## Requirements

- Python 3.10+
- [Nmap](https://nmap.org/download.html) installed and on `PATH`
- Python packages listed in `requirements.txt`

```bash
pip install -r requirements.txt
```

> **Note:** SYN scanning (`-sS`) and OS detection (`-O`) require root/administrator privileges.
> ARP discovery also requires root and Scapy.

## Usage

```text
python network_scanner.py -t <target> [options]

Options:
  -t, --target TARGET   IP address, hostname, or CIDR range (required)
  -p, --ports PORTS     Port range or comma-separated list (default: 1-1024)
  --arp                 ARP host discovery before scanning (root + Scapy)
  --no-service          Disable service/version detection (faster)
  --os                  Enable OS detection (requires root)
  --vuln                Run nmap vulnerability scripts (slow but thorough)
  --output FILE         Save text report to FILE
  --json FILE           Save JSON results to FILE
```

### Examples

```bash
# Scan a single host (ports 1–1024, service detection on)
python network_scanner.py -t 192.168.1.1

# Scan a subnet, common ports only, save report
python network_scanner.py -t 192.168.1.0/24 --ports 22,80,443,3389 --output report.txt

# Full scan with OS detection, vuln scripts, and JSON output
sudo python network_scanner.py -t 192.168.1.5 --os --vuln --json results.json

# Scan all ports on a host
python network_scanner.py -t 10.0.0.1 --ports 1-65535
```

### Sample output

```
============================================================
  NETWORK SCANNER REPORT
  Generated: 2025-04-15 10:30:00
============================================================

Host: 192.168.1.1
  MAC Address : AA:BB:CC:DD:EE:FF
  State       : up
  Open Ports  : 3 found
  PORT       STATE      SERVICE              VERSION
  --------------------------------------------------------
  22/tcp     open       ssh                  OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
  80/tcp     open       http                 Apache httpd 2.4.49 (Debian)
    [VULN/CRITICAL] Apache 2.4.49 path traversal (CVE-2021-41773)
  23/tcp     open       telnet
    [VULN/HIGH] Telnet sends credentials in plaintext; use SSH instead.

============================================================
```

## Running Tests

```bash
python -m pytest test_network_scanner.py -v
```
