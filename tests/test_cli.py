import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from trailhound.cli import main

ROOT = Path(__file__).resolve().parent.parent
LOG = str(ROOT / "sample_data" / "cloudtrail_attack_scenario.json")
POLICIES = str(ROOT / "sample_data" / "policies")


def run(*args):
    """Run the CLI and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(args))
        except SystemExit as exc:  # argparse exits on bad arguments
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class DetectCommandTests(unittest.TestCase):
    def test_detect_reports_alerts_and_exits_1(self):
        code, out, _ = run("detect", LOG)
        self.assertEqual(code, 1)
        self.assertIn("12 alert(s)", out)
        self.assertIn("TH-004", out)

    def test_json_format_is_valid_json(self):
        code, out, _ = run("detect", LOG, "--format", "json")
        self.assertEqual(code, 1)
        alerts = json.loads(out)
        self.assertEqual(len(alerts), 12)
        self.assertIn("rule_id", alerts[0])

    def test_markdown_report_written_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.md"
            code, _, err = run("detect", LOG, "--format", "markdown", "-o", str(target))
            text = target.read_text(encoding="utf-8")
        self.assertEqual(code, 1)
        self.assertIn("# TrailHound detection report", text)
        self.assertIn("| Severity | Alerts |", text)
        self.assertIn("Report written to", err)

    def test_min_severity_can_hide_everything_and_exit_0(self):
        code, out, _ = run("detect", LOG, "--min-severity", "critical")
        self.assertEqual(code, 0)
        self.assertIn("No alerts.", out)

    def test_disable_rule(self):
        code, out, _ = run("detect", LOG, "--format", "json", "--disable", "TH-004")
        alerts = json.loads(out)
        self.assertNotIn("TH-004", {a["rule_id"] for a in alerts})

    def test_unknown_rule_id_is_an_error(self):
        code, _, err = run("detect", LOG, "--disable", "TH-999")
        self.assertEqual(code, 2)
        self.assertIn("unknown rule id", err)

    def test_missing_path_is_an_error(self):
        code, _, err = run("detect", "no-such-file.json")
        self.assertEqual(code, 2)
        self.assertIn("error:", err)


class AuditCommandTests(unittest.TestCase):
    def test_audit_reports_findings_and_exits_1(self):
        code, out, _ = run("audit-iam", POLICIES)
        self.assertEqual(code, 1)
        self.assertIn("7 finding(s)", out)

    def test_audit_clean_policy_exits_0(self):
        code, out, _ = run("audit-iam", str(Path(POLICIES) / "least_privilege.json"))
        self.assertEqual(code, 0)
        self.assertIn("No findings.", out)

    def test_audit_json_format(self):
        _, out, _ = run("audit-iam", POLICIES, "--format", "json")
        self.assertEqual(len(json.loads(out)), 7)

    def test_audit_markdown_format(self):
        _, out, _ = run("audit-iam", POLICIES, "--format", "markdown")
        self.assertIn("# TrailHound IAM policy audit", out)


class OtherCommandTests(unittest.TestCase):
    def test_rules_lists_all_rules(self):
        code, out, _ = run("rules")
        self.assertEqual(code, 0)
        for number in range(1, 12):
            self.assertIn(f"TH-{number:03d}", out)

    def test_no_command_is_a_usage_error(self):
        code, _, _ = run()
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
