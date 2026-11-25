from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from account_enum_detector.cli import main  # noqa: E402
from account_enum_detector.errors import SafetyGateError  # noqa: E402
from account_enum_detector.normalize import normalize_body  # noqa: E402
from account_enum_detector.payload import BodyConfig, build_body  # noqa: E402
from account_enum_detector.runner import ScanConfig, build_plan  # noqa: E402


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class MockServerTestCase(unittest.TestCase):
    proc: subprocess.Popen | None = None
    port: int = 0

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "lab" / "mock_targets.py"), "--port", str(cls.port)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/health", timeout=1) as resp:
                    if resp.status == 200:
                        return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("mock lab server did not start")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.proc is not None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(timeout=5)
            if cls.proc.stdout is not None:
                cls.proc.stdout.close()
            if cls.proc.stderr is not None:
                cls.proc.stderr.close()

    def run_cli(self, *extra: str):
        with tempfile.TemporaryDirectory() as tmp:
            json_out = Path(tmp) / "report.json"
            code = main([
                "scan",
                *extra,
                "--confirm-known-accounts-safe",
                "--json-out",
                str(json_out),
                "--quiet",
            ])
            report = json.loads(json_out.read_text(encoding="utf-8")) if json_out.exists() else None
            return code, report

    def known_args(self) -> list[str]:
        args: list[str] = []
        for i in range(1, 6):
            args += ["--known", f"user{i}@example.test"]
        return args

    def test_body_message_oracle(self) -> None:
        code, report = self.run_cli(
            "--url",
            f"http://127.0.0.1:{self.port}/login-message",
            "--mode",
            "login",
            *self.known_args(),
            "--password",
            "invalid-test-password",
            "--samples-per-class",
            "5",
            "--delay",
            "0",
            "--jitter",
            "0",
            "--seed",
            "42",
            "--i-am-authorized",
        )
        self.assertEqual(code, 10)
        self.assertEqual(report["verdict"], "enumerable")
        self.assertTrue(any(f["kind"] == "body_message_oracle" for f in report["findings"]))

    def test_generic_same_response_is_not_detected(self) -> None:
        code, report = self.run_cli(
            "--url",
            f"http://127.0.0.1:{self.port}/reset-generic",
            "--mode",
            "password-reset",
            *self.known_args(),
            "--samples-per-class",
            "5",
            "--delay",
            "0",
            "--jitter",
            "0",
            "--seed",
            "43",
            "--i-am-authorized",
        )
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "no_reliable_evidence_detected")

    def test_cache_confounded_timing_is_not_called_enumerable(self) -> None:
        code, report = self.run_cli(
            "--url",
            f"http://127.0.0.1:{self.port}/cache-timing",
            "--mode",
            "generic",
            *self.known_args(),
            "--cached-nonexistent-account",
            "ae-cache-hot@example.test",
            "--samples-per-class",
            "5",
            "--delay",
            "0",
            "--jitter",
            "0",
            "--seed",
            "44",
            "--i-am-authorized",
        )
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "no_reliable_evidence_detected")
        timing_findings = [f for f in report["findings"] if f["kind"] == "timing_oracle"]
        self.assertTrue(timing_findings)
        self.assertIn("cache_confounder_warning", timing_findings[0]["evidence"])

    def test_timing_difference_is_statistically_detected(self) -> None:
        code, report = self.run_cli(
            "--url",
            f"http://127.0.0.1:{self.port}/timing",
            "--mode",
            "login",
            *self.known_args(),
            "--password",
            "invalid-test-password",
            "--samples-per-class",
            "5",
            "--delay",
            "0",
            "--jitter",
            "0",
            "--seed",
            "46",
            "--i-am-authorized",
        )
        self.assertEqual(code, 10)
        timing = next(f for f in report["findings"] if f["kind"] == "timing_oracle")
        primary = timing["evidence"]["existing_vs_unique_nonexisting"]
        self.assertEqual(primary["classification"], "strong_timing_oracle")
        self.assertEqual(primary["cliffs_delta"], 1.0)

    def test_rate_limit_stops(self) -> None:
        code, report = self.run_cli(
            "--url",
            f"http://127.0.0.1:{self.port}/rate-limit",
            "--mode",
            "generic",
            *self.known_args()[:4],  # two --known/value pairs
            "--samples-per-class",
            "2",
            "--delay",
            "0",
            "--jitter",
            "0",
            "--seed",
            "45",
            "--i-am-authorized",
        )
        self.assertEqual(code, 2)
        self.assertTrue(report["defense"]["blocked"])
        self.assertIn("rate_limit", report["defense"]["reason_counts"])


class NormalizationTest(unittest.TestCase):
    def test_dynamic_json_fields_and_account_reflection(self) -> None:
        accounts = ["alice@example.com", "nx@example.com"]
        a = normalize_body(
            '{"message":"ok","account":"alice@example.com","request_id":"abc123def456abc123def456","ts":"2026-01-01T10:00:00Z"}',
            accounts,
        )
        b = normalize_body(
            '{"message":"ok","account":"nx@example.com","request_id":"ffeeddccbbaa998877665544","ts":"2026-02-02T11:00:00Z"}',
            accounts,
        )
        self.assertEqual(a, b)

    def test_html_noise_is_stripped_to_visible_text(self) -> None:
        a = normalize_body(
            '<!doctype html><html><head><style>.x{color:red}</style></head>'
            '<body><h1>密码错误</h1><input type="hidden" name="csrf" value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"></body></html>',
            [],
        )
        b = normalize_body(
            '<!doctype html><html><head><style>.x{color:blue}</style></head>'
            '<body><h1>账号不存在</h1><input type="hidden" name="csrf" value="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"></body></html>',
            [],
        )
        self.assertIn("密码错误", a)
        self.assertIn("账号不存在", b)
        self.assertNotIn("<style", a.lower())
        self.assertNotIn("aaaaaaaaaaaaaaaa", a)

    def test_account_embedded_json_key_is_scrubbed(self) -> None:
        a = normalize_body('{"alice@example.com":{"ok":true}}', ["alice@example.com"])
        b = normalize_body('{"probe-uuid@example.com":{"ok":true}}', ["probe-uuid@example.com"])
        self.assertEqual(a, b)

    def test_json_template_can_be_form_encoded(self) -> None:
        body = build_body(
            "alice@example.com",
            1,
            BodyConfig(
                content_type="application/x-www-form-urlencoded",
                template='{"username":"{{account}}","password":"{{password}}"}',
                password="p&d",
            ),
        ).decode()
        self.assertIn("username=alice%40example.com", body)
        self.assertIn("password=p%26d", body)

    def test_negative_warmup_cannot_bypass_cap(self) -> None:
        config = ScanConfig(
            url="http://127.0.0.1:1",
            known_accounts=["a@example.com"],
            nonexistent_pattern="{{uuid}}",
            warmup_requests=-1,
        )
        with self.assertRaises(SafetyGateError):
            build_plan(config)


if __name__ == "__main__":
    unittest.main(verbosity=2)
