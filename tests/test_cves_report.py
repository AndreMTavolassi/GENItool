import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

from genitool.cves import lookup_cves, normalize_cpe
from genitool.models import StageResult
from genitool.report import render_report


def response(payload):
    return io.BytesIO(json.dumps(payload).encode("utf-8"))


def cve(identifier="CVE-2021-41773"):
    return {"cve": {
        "id": identifier,
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Published vulnerability description"}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": 7.5, "baseSeverity": "HIGH"}}]},
    }}


class CVETests(unittest.TestCase):
    def test_convert_nmap_cpe(self):
        self.assertEqual(normalize_cpe("cpe:/a:apache:http_server:2.4.49"),
                         "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

    def test_requires_versioned_unambiguous_cpe(self):
        for item in ("cpe:/a:apache:http_server", "cpe:/a:apache:http_server:*",
                     "cpe:/a:apache:http_server:2.4%3a49", "cpe:2.3:a:apache:http_server:2.4",
                     "cpe:/a:apache*:http_server:2.4.49", "cpe:/a:apache:http_server:2.4.49::~edition~"):
            with self.subTest(item=item):
                self.assertIsNone(normalize_cpe(item))

    @patch("genitool.cves.urlopen")
    def test_no_network_without_versions(self, open_mock):
        result = lookup_cves([{"product": "Apache", "version": ""}],
                             [{"name": "WordPress", "version": None}], 2)
        self.assertEqual(result.status, "skipped")
        open_mock.assert_not_called()

    @patch("genitool.cves.time.sleep")
    @patch("genitool.cves.urlopen")
    def test_exact_cpe_query_deduplicated_and_candidate_only(self, open_mock, sleep_mock):
        open_mock.return_value = response({"vulnerabilities": [cve()], "totalResults": 1})
        service = {"product": "Apache httpd", "version": "2.4.49",
                   "cpes": ["cpe:/a:apache:http_server:2.4.49"]}
        result = lookup_cves([service, service], [], 2, api_key="nvd-key")
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.data), 1)
        self.assertEqual(result.data[0]["status"], "candidate")
        self.assertEqual(result.data[0]["cvss"], 7.5)
        self.assertEqual(open_mock.call_count, 1)
        request = open_mock.call_args.args[0]
        params = parse_qs(urlsplit(request.full_url).query)
        self.assertIn("cpeName", params)
        self.assertNotIn("keywordSearch", params)
        self.assertEqual(request.get_header("Apikey"), "nvd-key")
        self.assertIsNone(request.get_header("Authorization"))
        sleep_mock.assert_not_called()

    @patch("genitool.cves.urlopen")
    def test_versioned_keyword_fallback_explicitly_unverified(self, open_mock):
        open_mock.return_value = response({"vulnerabilities": [cve()]})
        result = lookup_cves([], [{"name": "Apache", "version": "2.4.49", "cpes": None}], 2)
        params = parse_qs(urlsplit(open_mock.call_args.args[0].full_url).query)
        self.assertEqual(params["keywordSearch"], ["Apache 2.4.49"])
        self.assertIn("não verificada", result.data[0]["match_basis"])

    @patch("genitool.cves.urlopen")
    def test_wappalyzer_version_binds_to_wildcard_application_cpe(self, open_mock):
        open_mock.return_value = response({"vulnerabilities": [cve()]})
        technology = {"name": "WordPress", "version": "6.4.2",
                      "cpes": ["cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"]}
        result = lookup_cves([], [technology], 2)
        params = parse_qs(urlsplit(open_mock.call_args.args[0].full_url).query)
        self.assertEqual(params["cpeName"], ["cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*"])
        self.assertNotIn("keywordSearch", params)
        self.assertEqual(result.data[0]["matched_version"], "6.4.2")
        self.assertEqual(result.data[0]["status"], "candidate")

    @patch("genitool.cves.urlopen")
    def test_wildcard_technology_without_version_is_skipped(self, open_mock):
        technology = {"name": "WordPress", "version": "",
                      "cpes": ["cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"]}
        result = lookup_cves([], [technology], 2)
        self.assertEqual(result.status, "skipped")
        open_mock.assert_not_called()

    @patch("genitool.cves.time.sleep")
    @patch("genitool.cves.urlopen")
    def test_service_and_os_wildcards_never_inherit_observed_version(self, open_mock, sleep_mock):
        open_mock.side_effect = [response({"vulnerabilities": []}), response({"vulnerabilities": []})]
        service = {"product": "Apache", "version": "2.4.49", "cpes": [
            "cpe:/a:auxiliary:library:*", "cpe:/o:linux:linux_kernel:*"]}
        technology = {"name": "Linux", "version": "6.4.2", "cpes": [
            "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"]}
        lookup_cves([service], [technology], 2)
        self.assertEqual(open_mock.call_count, 2)
        for call in open_mock.call_args_list:
            params = parse_qs(urlsplit(call.args[0].full_url).query)
            self.assertNotIn("cpeName", params)
            self.assertIn("keywordSearch", params)

    @patch("genitool.cves.urlopen")
    def test_wappalyzer_binding_preserves_remaining_cpe_fields(self, open_mock):
        open_mock.return_value = response({"vulnerabilities": []})
        technology = {"name": "Nginx", "version": "1.24.0", "cpes": [
            "cpe:2.3:a:f5:nginx:*:rc1:community:en:edition:linux:x64:other"]}
        lookup_cves([], [technology], 2)
        params = parse_qs(urlsplit(open_mock.call_args.args[0].full_url).query)
        self.assertEqual(params["cpeName"], [
            "cpe:2.3:a:f5:nginx:1.24.0:rc1:community:en:edition:linux:x64:other"])

    @patch("genitool.cves.time.monotonic", return_value=0)
    @patch("genitool.cves.time.sleep")
    @patch("genitool.cves.urlopen")
    def test_rate_limit_spacing_and_query_budget(self, open_mock, sleep_mock, monotonic_mock):
        open_mock.side_effect = [response({"vulnerabilities": []}), response({"vulnerabilities": []})]
        technologies = [{"name": name, "version": "1.2.3"} for name in ("A", "B", "C")]
        result = lookup_cves([], technologies, 2, max_queries=2)
        self.assertEqual(open_mock.call_count, 2)
        self.assertEqual(result.status, "partial")
        sleep_mock.assert_called_with(6.1)

    @patch("genitool.cves.time.sleep")
    @patch("genitool.cves.urlopen")
    def test_429_retries_once_then_succeeds(self, open_mock, sleep_mock):
        open_mock.side_effect = [HTTPError("https://services.nvd.nist.gov", 429, "rate", {"Retry-After": "1"}, None),
                                 response({"vulnerabilities": []})]
        result = lookup_cves([], [{"name": "Apache", "version": "2.4.49"}], 2)
        self.assertEqual(result.status, "completed")
        self.assertEqual(open_mock.call_count, 2)
        self.assertTrue(any(call.args[0] >= 6.1 for call in sleep_mock.call_args_list))

    @patch("genitool.cves.time.sleep")
    @patch("genitool.cves.urlopen")
    def test_long_retry_after_stops_remaining_queries(self, open_mock, sleep_mock):
        open_mock.side_effect = HTTPError("https://services.nvd.nist.gov", 429, "rate", {"Retry-After": "120"}, None)
        result = lookup_cves([], [{"name": name, "version": "1.2.3"} for name in ("A", "B")], 2)
        self.assertEqual(result.status, "error")
        self.assertEqual(open_mock.call_count, 1)
        sleep_mock.assert_not_called()
        self.assertTrue(any("restantes interrompidas" in note for note in result.notes))

    @patch("genitool.cves.urlopen")
    def test_malformed_json_is_error(self, open_mock):
        open_mock.return_value = io.BytesIO(b"not json")
        result = lookup_cves([], [{"name": "Apache", "version": "2.4.49"}], 2)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.data, [])

    @patch("genitool.cves.urlopen")
    def test_network_error_does_not_leak_exception_secrets(self, open_mock):
        open_mock.side_effect = URLError("private-token")
        result = lookup_cves([], [{"name": "Apache", "version": "2.4.49"}], 2)
        self.assertEqual(result.status, "error")
        self.assertNotIn("private-token", " ".join(result.notes))

    @patch("genitool.cves.urlopen")
    def test_result_cap_and_rejected_filter(self, open_mock):
        rejected = cve("CVE-2021-9999")
        rejected["cve"]["vulnStatus"] = "Rejected"
        entries = [rejected] + [cve(f"CVE-2021-{10000 + number}") for number in range(25)]
        open_mock.return_value = response({"vulnerabilities": entries, "totalResults": 100})
        result = lookup_cves([], [{"name": "Apache", "version": "2.4.49"}], 2)
        self.assertEqual(result.status, "partial")
        self.assertEqual(len(result.data), 19)
        self.assertTrue(all(finding["id"] != "CVE-2021-9999" for finding in result.data))


class ReportTests(unittest.TestCase):
    def test_report_shows_stage_states_and_candidate_warning(self):
        report = render_report({"version": "0.1.0", "target": "https://example.test",
                                "stages": [StageResult("nmap", "skipped", notes=["Nmap indisponível"]),
                                           StageResult("cves", "partial", [{"id": "CVE-2021-41773", "status": "candidate"}])]})
        self.assertIn("ignorado", report)
        self.assertIn("parcial", report)
        self.assertIn("CANDIDATA, SEM CONFIRMAÇÃO", report)
        self.assertIn("não é assinatura", report)

    def test_report_strips_control_injection_and_secret_options(self):
        report = render_report({"target": "https://user:password@example.test/path?token=sensitive#secret",
                                "options": {"rate": 5, "headers": {"Authorization": "Bearer top-secret"},
                                            "api_key": "another-secret"},
                                "stages": [StageResult("nmap", "error", notes=["bad\x1b[31m\nforged\u202e"])]})
        for secret in ("password", "sensitive", "top-secret", "another-secret", "\x1b", "\u202e"):
            self.assertNotIn(secret, report)
        self.assertIn("rate: 5", report)
        self.assertIn("bad forged", report)
        self.assertNotIn("\nforged", report)

    def test_mapping_stages_supported_and_generic_secret_keys_omitted(self):
        report = render_report({"stages": [{"name": "other", "status": "completed", "data": [
            {"evidence": "observed", "Authorization": "top-secret", "detail": {"password": "secret"}}]}]})
        self.assertIn("observed", report)
        self.assertNotIn("top-secret", report)
        self.assertNotIn('"secret"', report)


if __name__ == "__main__":
    unittest.main()
