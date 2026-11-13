import json
import subprocess
import unittest
from unittest.mock import patch

from genitool.http_client import HTTPResponse, HttpRequestError
from genitool.scanners import _ENGINE, _SnapshotParser, _engine_check, parse_nmap_xml, scan_nmap, scan_technologies


XML = """<?xml version='1.0'?>
<!DOCTYPE nmaprun>
<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open"/>
<service name="http" product="nginx" version="1.24.0"><cpe>cpe:/a:nginx:nginx:1.24.0</cpe></service>
</port><port protocol="tcp" portid="22"><state state="closed"/></port></ports>
</host></nmaprun>"""


class NmapTests(unittest.TestCase):
    def test_realistic_xml_filters_closed_ports_and_preserves_cpes(self):
        services = parse_nmap_xml(XML)
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["host"], "127.0.0.1")
        self.assertEqual(services[0]["version"], "1.24.0")
        self.assertEqual(services[0]["port"], 8080)
        self.assertEqual(services[0]["cpes"], ["cpe:/a:nginx:nginx:1.24.0"])

    def test_entities_are_rejected_but_nmap_doctype_is_supported(self):
        with self.assertRaises(ValueError):
            parse_nmap_xml('<!DOCTYPE nmaprun [<!ENTITY secret "private">]><nmaprun/>')

    @patch("genitool.scanners.shutil.which", return_value="/usr/bin/nmap")
    @patch("genitool.scanners.subprocess.run")
    def test_bounded_connect_scan_uses_argv_and_not_shell(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, XML, "")
        result = scan_nmap("127.0.0.1", "22,80,8000-8080", 20)
        self.assertEqual(result.status, "completed")
        command = run.call_args.args[0]
        self.assertEqual(command[-1], "127.0.0.1")
        self.assertIn("-sT", command)
        self.assertNotIn("--script", command)
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["timeout"], 20)

    @patch("genitool.scanners.shutil.which", return_value="/usr/bin/nmap")
    @patch("genitool.scanners.subprocess.run")
    def test_ipv6_adds_address_family_flag(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, XML, "")
        scan_nmap("::1", "8080", 20)
        self.assertIn("-6", run.call_args.args[0])

    @patch("genitool.scanners.subprocess.run")
    def test_options_cidrs_ranges_and_invalid_ports_are_not_run(self, run):
        for host, ports in [("--help", "80"), ("127.0.0.1/24", "80"), ("127.0.0.1", "80;id"), ("localhost", "90-80"), ("localhost", "0"), ("localhost", "65536")]:
            self.assertEqual(scan_nmap(host, ports, 10).status, "error")
        run.assert_not_called()

    @patch("genitool.scanners.shutil.which", return_value=None)
    def test_absent_nmap_is_reported(self, _which):
        self.assertEqual(scan_nmap("localhost", "80", 10).status, "skipped")

    @patch("genitool.scanners.shutil.which", return_value="/usr/bin/nmap")
    @patch("genitool.scanners.subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 1))
    def test_timeout_is_an_explicit_error(self, _run, _which):
        self.assertEqual(scan_nmap("localhost", "80", 1).status, "error")

    @patch("genitool.scanners.shutil.which", return_value="/usr/bin/nmap")
    @patch("genitool.scanners.subprocess.run")
    def test_invalid_xml_is_not_silently_treated_as_no_services(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, "invalid", "")
        self.assertEqual(scan_nmap("localhost", "80", 1).status, "error")


class WappalyzerTests(unittest.TestCase):
    def test_snapshot_parser_collects_generator_and_scripts_without_fetching(self):
        parser = _SnapshotParser()
        parser.feed('<meta name="Generator" content="WordPress 6.4.2"><script src="/app.js"></script>')
        self.assertEqual(parser.meta, {"generator": ["WordPress 6.4.2"]})
        self.assertEqual(parser.scripts, ["/app.js"])

    @patch("genitool.scanners._engine_check", return_value=False)
    @patch("genitool.http_client.HttpClient")
    def test_missing_optional_engine_does_not_request_target(self, client, _check):
        self.assertEqual(scan_technologies("https://example.invalid", {}, 10).status, "skipped")
        client.assert_not_called()

    @patch("genitool.scanners._engine_check", return_value=True)
    @patch("genitool.scanners.subprocess.run")
    @patch("genitool.http_client.HttpClient")
    def test_snapshot_via_stdin_does_not_put_auth_in_argv(self, client, run, _check):
        client.return_value.get.return_value = HTTPResponse(
            "https://example.invalid", 200, {"server": "nginx/1.24.0"}, b"<html></html>", False,
        )
        run.return_value = subprocess.CompletedProcess([], 0, json.dumps({"technologies": [{"name": "Nginx", "version": "1.24.0", "confidence": 100, "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]}), "")
        result = scan_technologies("https://example.invalid", {"Authorization": "Bearer private"}, 10)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.data[0]["name"], "Nginx")
        self.assertEqual(client.call_args.kwargs["headers"], {"Authorization": "Bearer private"})
        self.assertNotIn("private", str(run.call_args))
        self.assertIn("nginx/1.24.0", run.call_args.kwargs["input"])

    @patch("genitool.scanners._engine_check", return_value=True)
    @patch("genitool.http_client.HttpClient", side_effect=HttpRequestError("private detail"))
    def test_http_error_is_explicit_and_does_not_echo_secrets(self, _client, _check):
        result = scan_technologies("https://example.invalid", {}, 10)
        self.assertEqual(result.status, "error")
        self.assertNotIn("private detail", str(result))

    @patch("genitool.scanners._engine_check", return_value=True)
    @patch("genitool.scanners.subprocess.run")
    @patch("genitool.http_client.HttpClient")
    def test_blocked_page_and_truncated_html_are_partial(self, client, run, _check):
        client.return_value.get.return_value = HTTPResponse("https://example.invalid", 403, {}, b"access denied", True)
        run.return_value = subprocess.CompletedProcess([], 0, '{"technologies":[]}', "")
        result = scan_technologies("https://example.invalid", {}, 10)
        self.assertEqual(result.status, "partial")
        self.assertTrue(any("403" in note for note in result.notes))

    def test_actual_optional_engine_on_static_fixture(self):
        if not _engine_check():
            self.skipTest("optional Wappalyzer engine not installed")
        payload = {
            "url": "https://fixture.invalid", "html": "<html>fixture</html>",
            "headers": {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2.1"},
            "meta": {"generator": ["WordPress 6.4.2"]},
        }
        result = subprocess.run(["node", str(_ENGINE)], input=json.dumps(payload), capture_output=True, text=True, timeout=10, check=True)
        technologies = {item["name"]: item for item in json.loads(result.stdout)["technologies"]}
        self.assertEqual(technologies["Nginx"]["version"], "1.24.0")
        self.assertEqual(technologies["PHP"]["version"], "8.2.1")
        self.assertEqual(technologies["WordPress"]["version"], "6.4.2")


if __name__ == "__main__":
    unittest.main()
