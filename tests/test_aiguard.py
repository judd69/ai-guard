"""Unit tests for AIGuard. Run with: python -m unittest discover tests"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aiguard import __version__, scan_file, scan_path  # noqa: E402
from aiguard.checks import check_risky_deps  # noqa: E402
from aiguard.report import Severity  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def findings_for(filename, check_id=None, min_severity=None):
    findings = scan_file(FIXTURES / filename, FIXTURES)
    if check_id:
        findings = [f for f in findings if f.check_id == check_id]
    if min_severity:
        findings = [f for f in findings if f.severity >= min_severity]
    return findings


class TestHallucinatedImports(unittest.TestCase):
    def test_flags_unresolvable_import(self):
        hits = findings_for("bad_code.py", "hallucinated-imports")
        names = [f.message for f in hits]
        self.assertTrue(any("fastjson" in m for m in names),
                        f"expected fastjson flagged, got: {names}")

    def test_stdlib_and_installed_not_flagged(self):
        hits = findings_for("good_code.py", "hallucinated-imports")
        self.assertEqual(hits, [])


class TestDangerousCalls(unittest.TestCase):
    def test_flags_eval_pickle_system(self):
        hits = findings_for("bad_code.py", "dangerous-calls")
        text = " ".join(f.message for f in hits)
        self.assertIn("eval()", text)
        self.assertIn("pickle.loads()", text)
        self.assertIn("os.system()", text)

    def test_eval_is_critical(self):
        hits = findings_for("bad_code.py", "dangerous-calls")
        eval_hits = [f for f in hits if "eval()" in f.message]
        self.assertTrue(eval_hits)
        self.assertEqual(eval_hits[0].severity, Severity.CRITICAL)

    def test_clean_code_passes(self):
        hits = findings_for("good_code.py", "dangerous-calls")
        self.assertEqual(hits, [])


class TestSecrets(unittest.TestCase):
    def test_flags_real_secrets(self):
        hits = findings_for("bad_code.py", "secrets")
        self.assertGreaterEqual(len(hits), 2)  # sk-... key + real AKIA key
        self.assertTrue(all(f.severity == Severity.CRITICAL for f in hits))

    def test_skips_placeholders(self):
        hits = findings_for("bad_code.py", "secrets")
        for f in hits:
            self.assertNotIn("EXAMPLE", f.snippet)
        good_hits = findings_for("good_code.py", "secrets")
        self.assertEqual(good_hits, [])


class TestWeakErrorHandling(unittest.TestCase):
    def test_flags_bare_except_and_swallowed_exception(self):
        hits = findings_for("bad_code.py", "weak-error-handling")
        self.assertEqual(len(hits), 2)
        text = " ".join(f.message for f in hits)
        self.assertIn("bare `except:`", text)
        self.assertIn("continue", text)

    def test_specific_except_ok(self):
        hits = findings_for("good_code.py", "weak-error-handling")
        self.assertEqual(hits, [])


class TestNetworkSafety(unittest.TestCase):
    def test_flags_missing_timeout_and_verify_false(self):
        hits = findings_for("bad_code.py", "network-safety")
        text = " ".join(f.message for f in hits)
        self.assertIn("without timeout=", text)
        self.assertIn("verify=False", text)

    def test_timeout_present_ok(self):
        hits = findings_for("good_code.py", "network-safety")
        self.assertEqual(hits, [])


class TestAiTells(unittest.TestCase):
    def test_flags_todo_comment_and_long_line(self):
        hits = findings_for("bad_code.py", "ai-tells")
        self.assertGreaterEqual(len(hits), 2)
        text = " ".join(f.message for f in hits)
        self.assertIn("placeholder comment", text)
        self.assertIn(">140", text)

    def test_clean_code_passes(self):
        hits = findings_for("good_code.py", "ai-tells")
        self.assertEqual(hits, [])


class TestRiskyDeps(unittest.TestCase):
    def test_typosquat_and_unpinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text(
                "requests==2.31.0\nrequets==2.31.0\nnumpy\n", encoding="utf-8"
            )
            hits = list(check_risky_deps(root))
        by_msg = [f.message for f in hits]
        self.assertTrue(any("requets" in m and "requests" in m for m in by_msg),
                        f"expected typosquat flag, got: {by_msg}")
        self.assertTrue(any("numpy" in m and "unpinned" in m for m in by_msg),
                        f"expected unpinned flag, got: {by_msg}")
        # exact popular package with pin -> no finding against itself
        self.assertFalse(any(m.startswith("dependency 'requests'") and "typosquat" in m
                             for m in by_msg))

    def test_pyproject_deps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "x"\ndependencies = [\n  "flask==3.0.0",\n'
                '  "djang>=4.0",\n]\n',
                encoding="utf-8",
            )
            hits = list(check_risky_deps(root))
        self.assertTrue(any("djang" in f.message and "django" in f.message for f in hits))


class TestCLI(unittest.TestCase):
    def test_scan_exit_codes_and_json(self):
        from aiguard.cli import main

        # bad fixtures -> exit 2 (high/critical findings present)
        rc = main(["scan", str(FIXTURES), "--min-severity", "low"])
        self.assertEqual(rc, 2)

        # good file only -> exit 0
        rc = main(["scan", str(FIXTURES / "good_code.py")])
        self.assertEqual(rc, 0)

        # --fail-on critical with only low findings -> still 2 here (criticals exist)
        rc = main(["scan", str(FIXTURES), "--fail-on", "critical"])
        self.assertEqual(rc, 2)

        # missing path -> exit 1
        rc = main(["scan", str(FIXTURES / "nope.py")])
        self.assertEqual(rc, 1)

    def test_version(self):
        self.assertEqual(__version__, "0.1.0")

    def test_json_output_is_valid(self):
        proc = subprocess.run(
            [sys.executable, "-m", "aiguard", "scan", str(FIXTURES / "good_code.py"),
             "--json"],
            capture_output=True, text=True, cwd=str(FIXTURES.parent.parent),
        )
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["tool"], "aiguard")
        self.assertIn("findings", payload)


if __name__ == "__main__":
    unittest.main()
