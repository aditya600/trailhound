import json
import tempfile
import unittest
from pathlib import Path

from trailhound.iam_audit import audit_path, audit_policy

POLICIES = Path(__file__).resolve().parent.parent / "sample_data" / "policies"


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def check_ids(findings):
    return [f.check_id for f in findings]


class AuditPolicyTests(unittest.TestCase):
    def test_full_admin_is_critical(self):
        findings = audit_policy(policy({"Effect": "Allow", "Action": "*", "Resource": "*"}))
        self.assertEqual(check_ids(findings), ["IAM-001"])
        self.assertEqual(findings[0].severity, "critical")

    def test_service_wildcard(self):
        findings = audit_policy(policy({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}))
        self.assertEqual(check_ids(findings), ["IAM-002"])

    def test_service_wildcard_on_specific_resource_is_quiet(self):
        findings = audit_policy(policy(
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::my-bucket/*"}))
        self.assertEqual(findings, [])

    def test_passrole_on_all_resources(self):
        findings = audit_policy(policy(
            {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}))
        self.assertEqual(check_ids(findings), ["IAM-003"])

    def test_passrole_on_specific_role_is_quiet(self):
        findings = audit_policy(policy(
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::123456789012:role/app"}))
        self.assertEqual(findings, [])

    def test_iam_wildcard_covers_escalation_actions(self):
        findings = audit_policy(policy({"Effect": "Allow", "Action": "iam:*", "Resource": "*"}))
        self.assertIn("IAM-003", check_ids(findings))

    def test_sensitive_data_actions(self):
        findings = audit_policy(policy(
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}))
        self.assertEqual(check_ids(findings), ["IAM-004"])

    def test_not_action_is_flagged(self):
        findings = audit_policy(policy(
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
        self.assertEqual(check_ids(findings), ["IAM-005"])
        self.assertEqual(findings[0].severity, "high")

    def test_wildcard_principal(self):
        findings = audit_policy(policy(
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}))
        self.assertEqual(check_ids(findings), ["IAM-006"])

    def test_wildcard_principal_with_condition_is_quiet(self):
        findings = audit_policy(policy(
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::b/*",
             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}}))
        self.assertEqual(findings, [])

    def test_deny_statements_are_ignored(self):
        findings = audit_policy(policy({"Effect": "Deny", "Action": "*", "Resource": "*"}))
        self.assertEqual(findings, [])

    def test_single_statement_object_instead_of_list(self):
        document = {"Version": "2012-10-17",
                    "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
        self.assertEqual(check_ids(audit_policy(document)), ["IAM-001"])

    def test_policy_given_as_json_string(self):
        document = json.dumps(policy({"Effect": "Allow", "Action": "*", "Resource": "*"}))
        self.assertEqual(check_ids(audit_policy(document)), ["IAM-001"])

    def test_invalid_policy_returns_no_findings(self):
        self.assertEqual(audit_policy("not json"), [])
        self.assertEqual(audit_policy(None), [])

    def test_findings_are_sorted_most_severe_first(self):
        findings = audit_policy(policy(
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"},
            {"Effect": "Allow", "Action": "*", "Resource": "*"}))
        self.assertEqual(check_ids(findings), ["IAM-001", "IAM-004"])
        self.assertEqual([f.statement for f in findings], [2, 1])


class AuditPathTests(unittest.TestCase):
    def test_sample_policies_produce_expected_checks(self):
        findings, skipped = audit_path(str(POLICIES))
        by_file = {Path(f.file).name: set() for f in findings}
        for finding in findings:
            by_file[Path(finding.file).name].add(finding.check_id)
        self.assertEqual(skipped, [])
        self.assertEqual(by_file, {
            "admin_everything.json": {"IAM-001"},
            "wrapped_get_policy_version.json": {"IAM-001"},
            "s3_wide.json": {"IAM-002"},
            "dev_passrole.json": {"IAM-003"},
            "secrets_wide.json": {"IAM-004"},
            "not_action.json": {"IAM-005"},
            "trust_public.json": {"IAM-006"},
        })

    def test_least_privilege_policy_has_no_findings(self):
        findings, _ = audit_path(str(POLICIES / "least_privilege.json"))
        self.assertEqual(findings, [])

    def test_non_policy_json_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "other.json"
            path.write_text(json.dumps({"hello": "world"}))
            findings, skipped = audit_path(tmp)
        self.assertEqual(findings, [])
        self.assertEqual(len(skipped), 1)

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            audit_path("does-not-exist")


if __name__ == "__main__":
    unittest.main()
