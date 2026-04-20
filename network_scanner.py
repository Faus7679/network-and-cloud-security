#!/usr/bin/env python3
"""
Network Scanner Tool
Scans a network for open ports, running services, and known vulnerabilities.

Usage:
    python network_scanner.py -t <target> [options]

Examples:
    python network_scanner.py -t 192.168.1.1
    python network_scanner.py -t 192.168.1.0/24 --ports 1-1024
    python network_scanner.py -t 192.168.1.1 --vuln
"""

import argparse
import sys
import socket
import ipaddress
import datetime
import json

try:
    import nmap
except ImportError:
    print("Error: python-nmap is required. Install it with: pip install python-nmap")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, IP, TCP, sr1, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Note: scapy is not available. ARP host discovery will be disabled.")


# Common vulnerability signatures mapped to service/version patterns.
# Each entry is (service_name_pattern, version_pattern, description, severity).
KNOWN_VULNERABILITIES = [
    ("ftp",      "vsftpd 2.3.4",    "vsftpd 2.3.4 backdoor (CVE-2011-2523)",              "CRITICAL"),
    ("ftp",      "ProFTPD 1.3.3",   "ProFTPD 1.3.3 remote code execution (CVE-2010-4221)", "HIGH"),
    ("ssh",      "OpenSSH 4.",      "OpenSSH < 5.0 multiple vulnerabilities",               "MEDIUM"),
    ("ssh",      "OpenSSH 5.",      "OpenSSH 5.x potential info disclosure",                "LOW"),
    ("http",     "Apache httpd 2.2",  "Apache 2.2.x end-of-life, multiple CVEs",             "HIGH"),
    ("http",     "Apache httpd 2.4.49", "Apache 2.4.49 path traversal (CVE-2021-41773)",    "CRITICAL"),
    ("http",     "Apache httpd 2.4.50", "Apache 2.4.50 path traversal (CVE-2021-42013)",    "CRITICAL"),
    ("http",     "nginx 1.14",       "nginx 1.14.x end-of-life",                            "MEDIUM"),
    ("http",     "Microsoft IIS 6.0", "IIS 6.0 end-of-life, multiple CVEs",                 "HIGH"),
    ("http",     "Microsoft IIS 7.5", "IIS 7.5 multiple vulnerabilities",                   "MEDIUM"),
    ("smb",      "Windows XP",      "SMBv1 EternalBlue (MS17-010)",                         "CRITICAL"),
    ("smb",      "Windows 7",       "SMBv1 EternalBlue (MS17-010) if unpatched",            "HIGH"),
    ("telnet",   "",                 "Telnet transmits data in plaintext",                   "HIGH"),
    ("smtp",     "Sendmail 8.11",    "Sendmail 8.11 heap overflow",                          "HIGH"),
    ("mysql",    "5.0",              "MySQL 5.0 end-of-life, multiple CVEs",                 "MEDIUM"),
    ("mysql",    "5.1",              "MySQL 5.1 end-of-life, multiple CVEs",                 "MEDIUM"),
    ("rdp",      "",                 "RDP exposed - ensure NLA is enabled",                  "MEDIUM"),
    ("vnc",      "",                 "VNC exposed - verify authentication is enabled",       "HIGH"),
    ("ms-wbt-server", "",            "RDP exposed - ensure NLA is enabled",                  "MEDIUM"),
]

# Services that are considered insecure when exposed publicly
INSECURE_SERVICES = {
    "telnet":   "Telnet sends credentials in plaintext; use SSH instead.",
    "ftp":      "FTP sends credentials in plaintext; use SFTP or FTPS instead.",
    "rsh":      "rsh is unauthenticated; replace with SSH.",
    "rlogin":   "rlogin is unauthenticated; replace with SSH.",
    "rexec":    "rexec is unauthenticated; replace with SSH.",
    "finger":   "finger exposes user information.",
    "tftp":     "TFTP has no authentication.",
    "snmp":     "SNMP v1/v2 use community strings sent in plaintext.",
}


def validate_target(target: str) -> bool:
    """Return True if *target* is a valid IP address, hostname, or CIDR range."""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False


def arp_scan(network: str) -> list[dict]:
    """
    Use ARP requests to discover live hosts on a local network segment.
    Requires scapy and root/administrator privileges.

    Returns a list of dicts with keys 'ip' and 'mac'.
    """
    if not SCAPY_AVAILABLE:
        print("  [!] Scapy not available – skipping ARP discovery.")
        return []

    conf.verb = 0  # suppress scapy output
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=2, verbose=False)

    hosts = []
    for _, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})
    return hosts


def icmp_ping(host: str, timeout: int = 1) -> bool:
    """
    Send a single ICMP echo request to *host*.
    Returns True if a reply is received.
    Requires scapy and root/administrator privileges.
    """
    if not SCAPY_AVAILABLE:
        return False
    conf.verb = 0
    packet = IP(dst=host) / ICMP()
    reply = sr1(packet, timeout=timeout, verbose=False)
    return reply is not None


def scan_with_nmap(
    target: str,
    ports: str = "1-1024",
    service_detection: bool = True,
    os_detection: bool = False,
    vuln_scripts: bool = False,
) -> dict:
    """
    Run an nmap scan against *target* using python-nmap.

    Parameters
    ----------
    target            : IP address, hostname, or CIDR range.
    ports             : Port range string, e.g. "1-1024" or "22,80,443".
    service_detection : Enable -sV (version detection) if True.
    os_detection      : Enable -O (OS detection) if True.
    vuln_scripts      : Enable --script=vuln if True.

    Returns the raw python-nmap scan data dictionary.
    """
    nm = nmap.PortScanner()

    args = "-sS"  # SYN scan (requires root) – falls back to TCP connect otherwise
    if service_detection:
        args += " -sV"
    if os_detection:
        args += " -O"
    if vuln_scripts:
        args += " --script=vuln"
    args += " --open"  # Only show open ports

    print(f"  Running nmap scan: nmap {args} -p {ports} {target}")
    nm.scan(hosts=target, ports=ports, arguments=args)
    return nm


def check_vulnerabilities(service: str, version: str) -> list[dict]:
    """
    Cross-reference a service/version string against KNOWN_VULNERABILITIES.

    Returns a list of matching vulnerability dicts with keys:
    'description' and 'severity'.
    """
    findings = []
    service_lower = service.lower()
    version_lower = version.lower()

    for svc_pattern, ver_pattern, description, severity in KNOWN_VULNERABILITIES:
        if svc_pattern and svc_pattern not in service_lower:
            continue
        if ver_pattern and ver_pattern.lower() not in version_lower:
            continue
        findings.append({"description": description, "severity": severity})

    # Flag known-insecure services regardless of version
    for insecure_svc, warning in INSECURE_SERVICES.items():
        if insecure_svc in service_lower:
            entry = {"description": warning, "severity": "HIGH"}
            if entry not in findings:
                findings.append(entry)

    return findings


def format_report(scan_results: dict, show_vulns: bool = True) -> str:
    """Build a human-readable report string from *scan_results*."""
    lines = []
    header = "=" * 60
    lines.append(header)
    lines.append("  NETWORK SCANNER REPORT")
    lines.append(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(header)

    if not scan_results.get("hosts"):
        lines.append("\n[!] No hosts found or scan returned no results.")
        return "\n".join(lines)

    for host_info in scan_results["hosts"]:
        ip = host_info["ip"]
        hostname = host_info.get("hostname", "")
        state = host_info.get("state", "unknown")
        mac = host_info.get("mac", "")
        os_guess = host_info.get("os", "")

        lines.append(f"\nHost: {ip}" + (f" ({hostname})" if hostname else ""))
        if mac:
            lines.append(f"  MAC Address : {mac}")
        lines.append(f"  State       : {state}")
        if os_guess:
            lines.append(f"  OS Guess    : {os_guess}")

        ports = host_info.get("ports", [])
        if not ports:
            lines.append("  Open Ports  : None found")
        else:
            lines.append(f"  Open Ports  : {len(ports)} found")
            lines.append(f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'VERSION'}")
            lines.append("  " + "-" * 56)
            for port_info in ports:
                port = port_info["port"]
                proto = port_info.get("protocol", "tcp")
                pstate = port_info.get("state", "")
                service = port_info.get("service", "")
                version = port_info.get("version", "")
                lines.append(f"  {str(port) + '/' + proto:<10} {pstate:<10} {service:<20} {version}")

                if show_vulns:
                    vulns = port_info.get("vulnerabilities", [])
                    for v in vulns:
                        sev = v["severity"]
                        desc = v["description"]
                        lines.append(f"    [VULN/{sev}] {desc}")

        # Nmap script output (vuln scripts)
        script_output = host_info.get("script_output", {})
        if script_output:
            lines.append("\n  [Nmap Script Results]")
            for script_name, output in script_output.items():
                lines.append(f"    {script_name}:")
                for line in output.strip().splitlines():
                    lines.append(f"      {line}")

    lines.append("\n" + header)
    return "\n".join(lines)


def build_results(nm: nmap.PortScanner) -> dict:
    """
    Parse python-nmap output into a normalized results dictionary.

    Returns a dict with key 'hosts' containing a list of host dicts.
    """
    results = {"hosts": []}

    for host in nm.all_hosts():
        host_data = nm[host]
        host_info: dict = {
            "ip": host,
            "hostname": "",
            "state": host_data.state(),
            "mac": "",
            "os": "",
            "ports": [],
            "script_output": {},
        }

        # Hostname
        hostnames = host_data.hostnames()
        if hostnames:
            host_info["hostname"] = hostnames[0].get("name", "")

        # MAC address
        if "addresses" in host_data:
            host_info["mac"] = host_data["addresses"].get("mac", "")

        # OS detection
        if "osmatch" in host_data and host_data["osmatch"]:
            best = host_data["osmatch"][0]
            host_info["os"] = f"{best.get('name', '')} ({best.get('accuracy', '')}%)"

        # Ports
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                port_data = host_data[proto][port]
                service_name = port_data.get("name", "")
                version_str = " ".join([
                    port_data.get("product", ""),
                    port_data.get("version", ""),
                    port_data.get("extrainfo", ""),
                ]).strip()

                port_info: dict = {
                    "port": port,
                    "protocol": proto,
                    "state": port_data.get("state", ""),
                    "service": service_name,
                    "version": version_str,
                    "vulnerabilities": check_vulnerabilities(service_name, version_str),
                }

                # Collect any nmap script output per port
                script = port_data.get("script", {})
                if script:
                    host_info["script_output"][f"port-{port}"] = "\n".join(
                        f"{k}: {v}" for k, v in script.items()
                    )

                host_info["ports"].append(port_info)

        results["hosts"].append(host_info)

    return results


def save_report(report_text: str, filename: str) -> None:
    """Write *report_text* to *filename*."""
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(report_text)
    print(f"  Report saved to: {filename}")


def save_json(data: dict, filename: str) -> None:
    """Serialise *data* as JSON and write to *filename*."""
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"  JSON results saved to: {filename}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and return CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Network Scanner – discover open ports, services, and vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address, hostname, or CIDR range (e.g. 192.168.1.0/24)",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port range or comma-separated list (default: 1-1024)",
    )
    parser.add_argument(
        "--arp",
        action="store_true",
        help="Perform ARP host discovery before port scanning (requires root/scapy)",
    )
    parser.add_argument(
        "--no-service",
        action="store_true",
        help="Disable service/version detection (faster scan)",
    )
    parser.add_argument(
        "--os",
        action="store_true",
        help="Enable OS detection (requires root)",
    )
    parser.add_argument(
        "--vuln",
        action="store_true",
        help="Run nmap vulnerability scripts (--script=vuln). Slow but thorough.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save the text report to FILE",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save results as JSON to FILE",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point.  Returns 0 on success, non-zero on error."""
    args = parse_args(argv)

    print("\n[*] Network Scanner")
    print(f"[*] Target  : {args.target}")
    print(f"[*] Ports   : {args.ports}")

    # Validate target
    if not validate_target(args.target):
        print(f"[!] Invalid target: {args.target}")
        return 1

    # Optional ARP discovery
    if args.arp:
        print("\n[*] Performing ARP host discovery …")
        live_hosts = arp_scan(args.target)
        if live_hosts:
            print(f"  Found {len(live_hosts)} live host(s):")
            for h in live_hosts:
                print(f"    {h['ip']}  {h['mac']}")
        else:
            print("  No live hosts found via ARP.")

    # Run nmap scan
    print("\n[*] Starting port scan …")
    nm = scan_with_nmap(
        target=args.target,
        ports=args.ports,
        service_detection=not args.no_service,
        os_detection=args.os,
        vuln_scripts=args.vuln,
    )

    # Parse results
    results = build_results(nm)

    # Print report
    report = format_report(results, show_vulns=True)
    print("\n" + report)

    # Optionally save outputs
    if args.output:
        save_report(report, args.output)
    if args.json:
        save_json(results, args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
