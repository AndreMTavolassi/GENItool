import contextlib
import argparse
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from genitool.cli import load_headers, main, normalize_target, save_report, validate_ports, verify_report
from genitool.models import StageResult


class TargetTests(unittest.TestCase):
    def test_host_and_ipv6_are_single_targets(self):
        self.assertEqual(normalize_target("Example.COM"), ("https://example.com/", "example.com"))
        self.assertEqual(normalize_target("http://[::1]:8080/base/"), ("http://[::1]:8080/base/", "::1"))

    def test_options_scope_expansion_and_credentials_are_rejected(self):
        for target in ("-oX", "127.0.0.1/24", "host1 host2", "file:///tmp/a", "https://user:pass@host/",
                       "https://host/?token=secret", "https://host/#frag", "https://host:0", "https://host\\@other"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_target(target)

    def test_invalid_ports_cannot_become_options(self):
        for ports in ("-sS", "0", "65536", "443-80", "80,,443", "80 --script vuln"):
            with self.subTest(ports=ports), self.assertRaises(argparse.ArgumentTypeError):
                validate_ports(ports)


class HeaderTests(unittest.TestCase):
    def test_file_and_environment_and_no_secret_in_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "headers.json"
            path.write_text(json.dumps({"authorization": "Bearer old", "Accept": "text/html"}))
            with patch.dict(os.environ, {"GENITOOL_TOKEN": "new", "GENITOOL_COOKIE": "session=abc"}, clear=True):
                headers = load_headers(path)
            self.assertEqual(headers["Authorization"], "Bearer new")
            self.assertNotIn("authorization", headers)
            self.assertEqual(headers["Cookie"], "session=abc")

    def test_scope_and_header_injection_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            path = Path(directory) / "headers.json"
            for headers in ({"Host": "other.test"}, {"Authorization": "secret\r\nX: injected"},
                            {"Cookie": 123}, {"x-token": "one", "X-Token": "two"}, ["not an object"]):
                path.write_text(json.dumps(headers))
                with self.subTest(headers=headers), self.assertRaises(ValueError):
                    load_headers(path)


class ReportTests(unittest.TestCase):
    def test_checksum_detects_tampering_and_restricts_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relatório.txt"
            save_report(path, "Evidências de teste\n")
            self.assertTrue(verify_report(path))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.write_text("alterado")
            self.assertFalse(verify_report(path))

    def test_failed_stage_preserves_report_and_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"GENITOOL_TOKEN": "sensitive-token"}, clear=True):
            path = Path(directory) / "report.txt"
            with patch("genitool.scanners.scan_nmap", return_value=StageResult("nmap", "error", notes=["timeout"])), \
                 patch("genitool.scanners.scan_technologies", return_value=StageResult("wappalyzer", "completed", notes=["Bearer sensitive-token"])), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main(["scan", "http://127.0.0.1", "--skip-fuzz", "--skip-cves", "-o", str(path)])
            self.assertEqual(code, 1)
            self.assertNotIn("sensitive-token", path.read_text())
            self.assertIn("timeout", path.read_text())
            self.assertTrue(verify_report(path))

    def test_interruption_preserves_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partial.txt"
            with patch("genitool.scanners.scan_nmap", side_effect=KeyboardInterrupt), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main(["scan", "http://127.0.0.1", "-o", str(path)])
            self.assertEqual(code, 130)
            self.assertTrue(verify_report(path))
            self.assertIn("Interrompido", path.read_text())

    def test_all_explicit_skips_are_successful(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "skip.txt"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main(["scan", "http://127.0.0.1", "--skip-nmap", "--skip-wappalyzer", "--skip-fuzz", "--skip-cves", "-o", str(path)])
            self.assertEqual(code, 0)
            self.assertTrue(verify_report(path))


if __name__ == "__main__":
    unittest.main()
