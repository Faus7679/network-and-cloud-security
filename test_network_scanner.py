"""
Unit tests for network_scanner.py

These tests exercise the pure-Python helper functions that do NOT require
a live network or root privileges, so they run reliably in any CI environment.
"""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Ensure the project root is on the path so we can import network_scanner
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import network_scanner


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------
class TestValidateTarget(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(network_scanner.validate_target("192.168.1.1"))

    def test_valid_cidr(self):
        self.assertTrue(network_scanner.validate_target("10.0.0.0/24"))

    def test_valid_ipv6(self):
        self.assertTrue(network_scanner.validate_target("::1"))

    def test_valid_loopback(self):
        self.assertTrue(network_scanner.validate_target("127.0.0.1"))

    def test_invalid_target(self):
        self.assertFalse(network_scanner.validate_target("not_a_valid_host_xyz_12345"))

    def test_valid_hostname_localhost(self):
        # 'localhost' should resolve on any system
        self.assertTrue(network_scanner.validate_target("localhost"))


# ---------------------------------------------------------------------------
# check_vulnerabilities
# ---------------------------------------------------------------------------
class TestCheckVulnerabilities(unittest.TestCase):
    def test_telnet_flagged_insecure(self):
        findings = network_scanner.check_vulnerabilities("telnet", "")
        descriptions = [f["description"] for f in findings]
        self.assertTrue(
            any("plaintext" in d.lower() or "telnet" in d.lower() for d in descriptions),
            f"Expected telnet warning, got: {descriptions}",
        )

    def test_ftp_vsftpd_backdoor(self):
        findings = network_scanner.check_vulnerabilities("ftp", "vsftpd 2.3.4")
        descriptions = [f["description"] for f in findings]
        self.assertTrue(
            any("vsftpd" in d.lower() for d in descriptions),
            f"Expected vsftpd backdoor, got: {descriptions}",
        )

    def test_apache_cve_2021_41773(self):
        # nmap reports product="Apache httpd" version="2.4.49" → combined string
        findings = network_scanner.check_vulnerabilities("http", "Apache httpd 2.4.49")
        descriptions = [f["description"] for f in findings]
        self.assertTrue(
            any("CVE-2021-41773" in d for d in descriptions),
            f"Expected Apache CVE-2021-41773, got: {descriptions}",
        )

    def test_no_vuln_for_safe_service(self):
        findings = network_scanner.check_vulnerabilities("dns", "BIND 9.16")
        # No known vuln pattern for this combination
        self.assertIsInstance(findings, list)

    def test_severity_values_are_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for svc, ver, _, severity in network_scanner.KNOWN_VULNERABILITIES:
            self.assertIn(severity, valid, f"Unexpected severity '{severity}'")

    def test_rdp_flagged(self):
        findings = network_scanner.check_vulnerabilities("rdp", "")
        self.assertTrue(len(findings) > 0, "RDP should produce at least one finding")


# ---------------------------------------------------------------------------
# build_results (with mocked nmap.PortScanner)
# ---------------------------------------------------------------------------
class TestBuildResults(unittest.TestCase):
    def _make_mock_nm(self, hosts_data: dict):
        """
        Create a mock nmap.PortScanner whose all_hosts() returns the keys of
        *hosts_data* and whose __getitem__ returns mock host objects.
        """
        nm = MagicMock()
        nm.all_hosts.return_value = list(hosts_data.keys())

        def getitem(host):
            return hosts_data[host]

        nm.__getitem__.side_effect = getitem
        return nm

    def _make_mock_host(self, state="up", protocols=None, hostnames=None,
                        addresses=None, osmatch=None):
        host = MagicMock()
        host.state.return_value = state
        host.hostnames.return_value = hostnames or []
        host.__contains__ = MagicMock(side_effect=lambda k: k in (addresses or {}))
        host.__getitem__ = MagicMock(side_effect=lambda k: (addresses or {})[k])
        host.all_protocols.return_value = list((protocols or {}).keys())

        def getitem_with_os(k):
            if k == "osmatch":
                return osmatch or []
            if k == "addresses":
                return addresses or {}
            return (protocols or {})[k]

        host.__getitem__ = MagicMock(side_effect=getitem_with_os)
        host.__contains__ = MagicMock(
            side_effect=lambda k: k in ({"osmatch": osmatch, "addresses": addresses})
        )

        def mock_contains(k):
            return k in {"osmatch": True, "addresses": True}

        host.__contains__ = MagicMock(side_effect=mock_contains)

        for proto, ports in (protocols or {}).items():
            host.__getitem__.side_effect = getitem_with_os

        return host

    def test_no_hosts(self):
        nm = self._make_mock_nm({})
        results = network_scanner.build_results(nm)
        self.assertEqual(results["hosts"], [])

    def test_host_with_open_port(self):
        port_data = {
            "state": "open",
            "name": "http",
            "product": "Apache httpd",
            "version": "2.4.49",
            "extrainfo": "",
            "script": {},
        }
        tcp_ports = {80: port_data}

        host_mock = MagicMock()
        host_mock.state.return_value = "up"
        host_mock.hostnames.return_value = [{"name": "example.com"}]
        host_mock.all_protocols.return_value = ["tcp"]
        host_mock["tcp"] = tcp_ports
        host_mock["addresses"] = {"mac": "AA:BB:CC:DD:EE:FF"}
        host_mock["osmatch"] = []
        host_mock.__contains__ = MagicMock(return_value=True)

        def side_effect(k):
            return {"tcp": tcp_ports, "addresses": {"mac": "AA:BB:CC:DD:EE:FF"}, "osmatch": []}[k]

        host_mock.__getitem__ = MagicMock(side_effect=side_effect)

        nm = self._make_mock_nm({"192.168.1.1": host_mock})
        results = network_scanner.build_results(nm)

        self.assertEqual(len(results["hosts"]), 1)
        host_info = results["hosts"][0]
        self.assertEqual(host_info["ip"], "192.168.1.1")
        self.assertEqual(host_info["hostname"], "example.com")
        self.assertEqual(len(host_info["ports"]), 1)
        self.assertEqual(host_info["ports"][0]["port"], 80)
        self.assertEqual(host_info["ports"][0]["service"], "http")
        # Apache/2.4.49 should flag CVE-2021-41773
        vuln_descs = [v["description"] for v in host_info["ports"][0]["vulnerabilities"]]
        self.assertTrue(any("CVE-2021-41773" in d for d in vuln_descs))


# ---------------------------------------------------------------------------
# format_report
# ---------------------------------------------------------------------------
class TestFormatReport(unittest.TestCase):
    def test_empty_results(self):
        report = network_scanner.format_report({"hosts": []})
        self.assertIn("No hosts found", report)

    def test_report_contains_host_ip(self):
        results = {
            "hosts": [
                {
                    "ip": "10.0.0.1",
                    "hostname": "",
                    "state": "up",
                    "mac": "",
                    "os": "",
                    "ports": [],
                    "script_output": {},
                }
            ]
        }
        report = network_scanner.format_report(results)
        self.assertIn("10.0.0.1", report)
        self.assertIn("NETWORK SCANNER REPORT", report)

    def test_report_shows_port_info(self):
        results = {
            "hosts": [
                {
                    "ip": "10.0.0.2",
                    "hostname": "test.local",
                    "state": "up",
                    "mac": "00:11:22:33:44:55",
                    "os": "Linux 5.x (90%)",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "version": "OpenSSH 8.9",
                            "vulnerabilities": [],
                        }
                    ],
                    "script_output": {},
                }
            ]
        }
        report = network_scanner.format_report(results)
        self.assertIn("22/tcp", report)
        self.assertIn("ssh", report)

    def test_report_shows_vulnerability(self):
        results = {
            "hosts": [
                {
                    "ip": "10.0.0.3",
                    "hostname": "",
                    "state": "up",
                    "mac": "",
                    "os": "",
                    "ports": [
                        {
                            "port": 23,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "telnet",
                            "version": "",
                            "vulnerabilities": [
                                {"description": "Telnet sends credentials in plaintext", "severity": "HIGH"}
                            ],
                        }
                    ],
                    "script_output": {},
                }
            ]
        }
        report = network_scanner.format_report(results, show_vulns=True)
        self.assertIn("VULN/HIGH", report)
        self.assertIn("plaintext", report)

    def test_report_hides_vulns_when_disabled(self):
        results = {
            "hosts": [
                {
                    "ip": "10.0.0.4",
                    "hostname": "",
                    "state": "up",
                    "mac": "",
                    "os": "",
                    "ports": [
                        {
                            "port": 23,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "telnet",
                            "version": "",
                            "vulnerabilities": [
                                {"description": "Telnet plaintext", "severity": "HIGH"}
                            ],
                        }
                    ],
                    "script_output": {},
                }
            ]
        }
        report = network_scanner.format_report(results, show_vulns=False)
        self.assertNotIn("VULN/", report)


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------
class TestParseArgs(unittest.TestCase):
    def test_required_target(self):
        args = network_scanner.parse_args(["-t", "192.168.1.1"])
        self.assertEqual(args.target, "192.168.1.1")

    def test_default_ports(self):
        args = network_scanner.parse_args(["-t", "10.0.0.1"])
        self.assertEqual(args.ports, "1-1024")

    def test_custom_ports(self):
        args = network_scanner.parse_args(["-t", "10.0.0.1", "-p", "80,443"])
        self.assertEqual(args.ports, "80,443")

    def test_vuln_flag(self):
        args = network_scanner.parse_args(["-t", "10.0.0.1", "--vuln"])
        self.assertTrue(args.vuln)

    def test_output_flag(self):
        args = network_scanner.parse_args(["-t", "10.0.0.1", "--output", "report.txt"])
        self.assertEqual(args.output, "report.txt")

    def test_json_flag(self):
        args = network_scanner.parse_args(["-t", "10.0.0.1", "--json", "out.json"])
        self.assertEqual(args.json, "out.json")


# ---------------------------------------------------------------------------
# main() integration smoke test (nmap mocked)
# ---------------------------------------------------------------------------
class TestMain(unittest.TestCase):
    @patch("network_scanner.scan_with_nmap")
    def test_main_returns_zero_on_success(self, mock_scan):
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []
        mock_scan.return_value = mock_nm

        result = network_scanner.main(["-t", "127.0.0.1"])
        self.assertEqual(result, 0)

    def test_main_returns_one_on_invalid_target(self):
        result = network_scanner.main(["-t", "not_a_valid_host_xyz_12345"])
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
