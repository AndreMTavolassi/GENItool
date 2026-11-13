import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from genitool.fuzz import _safe_path, _similar, fuzz_paths
from genitool.http_client import HTTPResponse, HttpClient, HttpRequestError


@contextlib.contextmanager
def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class Handler(BaseHTTPRequestHandler):
    records = []
    catch_all = False
    redirect = ""

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).records.append((self.path, dict(self.headers)))
        body = b"missing"
        status = 404
        if self.path == "/app/admin":
            status, body = 200, b"admin panel"
        elif self.path == "/app/private":
            status, body = 403, b"permission required"
        elif self.path == "/app/redirect":
            status, body = 302, b"redirect"
        elif self.path == "/app/large":
            status, body = 200, b"x" * 128
        elif type(self).catch_all:
            status, body = 200, f"No page at {self.path}".encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if status == 302:
            self.send_header("Location", type(self).redirect)
        self.end_headers()
        self.wfile.write(body)


class FuzzTests(unittest.TestCase):
    def setUp(self):
        Handler.records = []
        Handler.catch_all = False
        Handler.redirect = ""

    def run_fuzz(self, base, words, **options):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "paths.txt"
            wordlist.write_text(words, encoding="utf-8")
            arguments = dict(timeout=2, rate=1000, max_paths=10)
            arguments.update(options)
            return fuzz_paths(base + "/app", wordlist, {"Authorization": "Bearer test-secret"}, **arguments)

    def test_discovery_preserves_base_and_revalidates(self):
        with serve(Handler) as base:
            result = self.run_fuzz(base, "admin\nprivate\nabsent\n")
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.data), 2)
        by_url = {row["url"]: row for row in result.data}
        self.assertEqual(by_url[base + "/app/admin"]["validation"], "reproducible")
        self.assertEqual(by_url[base + "/app/private"]["validation"], "authentication_required")
        self.assertEqual(sum(path == "/app/admin" for path, _ in Handler.records), 2)
        self.assertEqual(len(Handler.records), 7)
        self.assertTrue(all(headers["Authorization"] == "Bearer test-secret" for _, headers in Handler.records))

    def test_reflected_soft_404_is_suppressed(self):
        Handler.catch_all = True
        with serve(Handler) as base:
            result = self.run_fuzz(base, "absent\nalso-absent\nadmin\n")
        self.assertEqual(result.status, "completed")
        self.assertEqual([item["url"] for item in result.data], [base + "/app/admin"])
        self.assertTrue(any("catch-all" in note for note in result.notes))

    def test_shared_large_template_does_not_hide_distinct_content(self):
        prefix = b"<!-- shared template -->" * 800
        missing = HTTPResponse("http://example.test/missing", 200, {}, prefix + b"Not Found: definitely missing")
        admin = HTTPResponse("http://example.test/admin", 200, {}, prefix + b"User admin: private dashboard")
        self.assertFalse(_similar(missing, admin))

    def test_truncated_bodies_never_establish_equivalence(self):
        first = HTTPResponse("http://example.test/a", 200, {}, b"same prefix", True)
        second = HTTPResponse("http://example.test/b", 200, {}, b"same prefix", True)
        self.assertFalse(_similar(first, second))

    def test_rejects_scope_escape_and_invalid_encodings(self):
        invalid = ["../secret", "%2e%2e/secret", "%252e%252e/secret", "http://example.com", "//elsewhere.test", "/absolute", "\\\\elsewhere", "path?query", "path#fragment", "%00", "./admin", "a/../b", "a/%2f../b", "a%", "//[", "\tadmin", "admin\x7f", "%ff"]
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(_safe_path(value))
        self.assertEqual(_safe_path("a/b/"), "a/b/")
        self.assertEqual(_safe_path("hello%20world"), "hello%20world")
        with serve(Handler) as base:
            result = self.run_fuzz(base, "\n".join(invalid) + "\nadmin\n")
        self.assertEqual(len(result.data), 1)
        self.assertTrue(all(path.startswith("/app/") for path, _ in Handler.records))

    def test_redirect_never_leaks_auth_or_reaches_second_origin(self):
        class Sink(Handler):
            records = []
        with serve(Sink) as second:
            Handler.redirect = second + "/stolen"
            with serve(Handler) as base:
                result = self.run_fuzz(base, "redirect\n")
                client = HttpClient({"Authorization": "Bearer secret"}, rate=1000)
                self.assertEqual(client.get(base + "/app/redirect").status_code, 302)
                with self.assertRaises(ValueError):
                    client.get(second + "/stolen")
        self.assertEqual(Sink.records, [])
        self.assertEqual(result.data[0]["status_code"], 302)

    def test_body_capture_is_bounded(self):
        with serve(Handler) as base:
            response = HttpClient(max_body_bytes=16).get(base + "/app/large")
        self.assertEqual(len(response.body), 16)
        self.assertTrue(response.truncated)

    def test_rate_applies_to_calibration_and_rechecks(self):
        with serve(Handler) as base:
            with patch("genitool.http_client.time.monotonic", return_value=0), patch("genitool.http_client.time.sleep") as sleep:
                result = self.run_fuzz(base, "admin\n", rate=2)
        self.assertEqual(result.status, "completed")
        self.assertEqual(sleep.call_count, 3)
        self.assertTrue(all(call.args == (0.5,) for call in sleep.call_args_list))

    def test_max_paths_bounds_requests(self):
        with serve(Handler) as base:
            result = self.run_fuzz(base, "admin\nprivate\nredirect\n", max_paths=1)
        self.assertEqual(len(Handler.records), 4)
        self.assertEqual(len(result.data), 1)

    def test_failed_calibration_is_error(self):
        with patch("genitool.fuzz.HttpClient.get", side_effect=HttpRequestError("unavailable")):
            result = self.run_fuzz("http://127.0.0.1:1", "admin\n")
        self.assertEqual(result.status, "error")
        self.assertFalse(result.data)

    def test_invalid_rate_and_header_are_rejected(self):
        for rate in (0, -1, float("nan"), float("inf")):
            with self.subTest(rate=rate):
                with self.assertRaises(ValueError):
                    HttpClient(rate=rate)
        with self.assertRaises(ValueError):
            HttpClient(headers={"Host": "another.test"})


if __name__ == "__main__":
    unittest.main()
