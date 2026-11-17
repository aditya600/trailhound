import gzip
import json
import tempfile
import unittest
from pathlib import Path

from trailhound.engine import run_detections
from trailhound.loader import load_events

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "cloudtrail_attack_scenario.json"


def make_event(name, source, when="2026-11-02T10:00:00Z", identity=None, ip="203.0.113.9", **extra):
    event = {
        "eventTime": when,
        "eventSource": source,
        "eventName": name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "userIdentity": identity or {"type": "IAMUser", "userName": "tester"},
        "eventID": f"{name}-{when}",
    }
    event.update(extra)
    return event


def ids(alerts):
    return [a.rule_id for a in alerts]


class SimpleRuleTests(unittest.TestCase):
    def test_root_usage_fires(self):
        event = make_event("ListBuckets", "s3.amazonaws.com", identity={"type": "Root"})
        self.assertIn("TH-001", ids(run_detections([event])))

    def test_root_service_event_is_ignored(self):
        event = make_event("ListBuckets", "s3.amazonaws.com", identity={"type": "Root"},
                           eventType="AwsServiceEvent")
        self.assertNotIn("TH-001", ids(run_detections([event])))

    def test_console_login_without_mfa(self):
        event = make_event("ConsoleLogin", "signin.amazonaws.com",
                           responseElements={"ConsoleLogin": "Success"},
                           additionalEventData={"MFAUsed": "No"})
        alerts = run_detections([event])
        self.assertEqual(ids(alerts), ["TH-002"])
        self.assertEqual(alerts[0].severity, "medium")

    def test_root_login_without_mfa_is_high(self):
        event = make_event("ConsoleLogin", "signin.amazonaws.com", identity={"type": "Root"},
                           responseElements={"ConsoleLogin": "Success"},
                           additionalEventData={"MFAUsed": "No"})
        by_id = {a.rule_id: a for a in run_detections([event])}
        self.assertEqual(by_id["TH-002"].severity, "high")

    def test_login_with_mfa_is_quiet(self):
        event = make_event("ConsoleLogin", "signin.amazonaws.com",
                           responseElements={"ConsoleLogin": "Success"},
                           additionalEventData={"MFAUsed": "Yes"})
        self.assertEqual(run_detections([event]), [])

    def test_failed_login_is_not_a_no_mfa_alert(self):
        event = make_event("ConsoleLogin", "signin.amazonaws.com",
                           responseElements={"ConsoleLogin": "Failure"},
                           additionalEventData={"MFAUsed": "No"})
        self.assertNotIn("TH-002", ids(run_detections([event])))

    def test_trail_tampering(self):
        for name in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"):
            event = make_event(name, "cloudtrail.amazonaws.com", requestParameters={"name": "t"})
            self.assertEqual(ids(run_detections([event])), ["TH-004"], name)

    def test_other_cloudtrail_calls_are_quiet(self):
        event = make_event("DescribeTrails", "cloudtrail.amazonaws.com")
        self.assertEqual(run_detections([event]), [])

    def test_guardduty_delete_and_disable(self):
        delete = make_event("DeleteDetector", "guardduty.amazonaws.com")
        disable = make_event("UpdateDetector", "guardduty.amazonaws.com",
                             requestParameters={"detectorId": "d", "enable": False})
        keep = make_event("UpdateDetector", "guardduty.amazonaws.com",
                          requestParameters={"detectorId": "d", "enable": True})
        self.assertEqual(ids(run_detections([delete])), ["TH-005"])
        self.assertEqual(ids(run_detections([disable])), ["TH-005"])
        self.assertEqual(run_detections([keep]), [])

    def test_new_iam_user(self):
        event = make_event("CreateUser", "iam.amazonaws.com", requestParameters={"userName": "x"})
        self.assertEqual(ids(run_detections([event])), ["TH-006"])

    def test_access_key_for_self_is_medium(self):
        event = make_event("CreateAccessKey", "iam.amazonaws.com", requestParameters={})
        alerts = run_detections([event])
        self.assertEqual(ids(alerts), ["TH-007"])
        self.assertEqual(alerts[0].severity, "medium")

    def test_access_key_for_another_user_is_high(self):
        event = make_event("CreateAccessKey", "iam.amazonaws.com",
                           requestParameters={"userName": "someone-else"})
        alerts = run_detections([event])
        self.assertEqual(alerts[0].severity, "high")
        self.assertTrue(alerts[0].details["for_another_user"])

    def test_admin_policy_attached(self):
        event = make_event("AttachUserPolicy", "iam.amazonaws.com", requestParameters={
            "userName": "u", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        self.assertEqual(ids(run_detections([event])), ["TH-008"])

    def test_read_only_policy_attached_is_quiet(self):
        event = make_event("AttachUserPolicy", "iam.amazonaws.com", requestParameters={
            "userName": "u", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
        self.assertEqual(run_detections([event]), [])

    def test_inline_admin_policy_document(self):
        document = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        event = make_event("PutUserPolicy", "iam.amazonaws.com", requestParameters={
            "userName": "u", "policyName": "p", "policyDocument": document})
        self.assertEqual(ids(run_detections([event])), ["TH-008"])

    def test_s3_public_access_block(self):
        deleted = make_event("DeleteBucketPublicAccessBlock", "s3.amazonaws.com",
                             requestParameters={"bucketName": "b"})
        relaxed = make_event("PutBucketPublicAccessBlock", "s3.amazonaws.com", requestParameters={
            "bucketName": "b", "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}})
        strict = make_event("PutBucketPublicAccessBlock", "s3.amazonaws.com", requestParameters={
            "bucketName": "b", "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}})
        self.assertEqual(ids(run_detections([deleted])), ["TH-009"])
        self.assertEqual(ids(run_detections([relaxed])), ["TH-009"])
        self.assertEqual(run_detections([strict]), [])

    def _sg_event(self, cidr, port):
        return make_event("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", requestParameters={
            "groupId": "sg-1",
            "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": port, "toPort": port,
                                         "ipRanges": {"items": [{"cidrIp": cidr}]}}]}})

    def test_security_group_ssh_open_to_world(self):
        self.assertEqual(ids(run_detections([self._sg_event("0.0.0.0/0", 22)])), ["TH-010"])

    def test_security_group_web_port_open_is_quiet(self):
        self.assertEqual(run_detections([self._sg_event("0.0.0.0/0", 443)]), [])

    def test_security_group_ssh_from_private_range_is_quiet(self):
        self.assertEqual(run_detections([self._sg_event("10.0.0.0/8", 22)]), [])


class ThresholdRuleTests(unittest.TestCase):
    def _failure(self, seconds, ip="203.0.113.9"):
        when = f"2026-11-02T10:{seconds // 60:02d}:{seconds % 60:02d}Z"
        return make_event("ConsoleLogin", "signin.amazonaws.com", when=when, ip=ip,
                          responseElements={"ConsoleLogin": "Failure"})

    def test_five_failures_in_window_alert_once(self):
        alerts = run_detections([self._failure(s) for s in (0, 10, 20, 30, 40)])
        self.assertEqual(ids(alerts), ["TH-003"])
        self.assertEqual(alerts[0].details["count"], 5)

    def test_four_failures_do_not_alert(self):
        self.assertEqual(run_detections([self._failure(s) for s in (0, 10, 20, 30)]), [])

    def test_failures_spread_beyond_window_do_not_alert(self):
        # 5 failures but 11 minutes apart, so never 5 inside 10 minutes
        events = [make_event("ConsoleLogin", "signin.amazonaws.com",
                             when=f"2026-11-02T{10 + (s // 3600):02d}:{(s % 3600) // 60:02d}:00Z",
                             responseElements={"ConsoleLogin": "Failure"})
                  for s in (0, 660, 1320, 1980, 2640)]
        self.assertEqual(run_detections(events), [])

    def test_failures_from_different_ips_are_counted_separately(self):
        events = [self._failure(s, ip=f"203.0.113.{s}") for s in (1, 2, 3, 4, 5)]
        self.assertEqual(run_detections(events), [])

    def _secret_reads(self, count, identity="thief"):
        return [make_event("GetSecretValue", "secretsmanager.amazonaws.com",
                           when=f"2026-11-02T10:00:{i:02d}Z",
                           identity={"type": "IAMUser", "userName": identity})
                for i in range(count)]

    def test_ten_secret_reads_alert(self):
        self.assertEqual(ids(run_detections(self._secret_reads(10))), ["TH-011"])

    def test_nine_secret_reads_are_quiet(self):
        self.assertEqual(run_detections(self._secret_reads(9)), [])


class EngineTests(unittest.TestCase):
    def test_min_severity_filters_alerts(self):
        events = [
            make_event("CreateUser", "iam.amazonaws.com"),           # medium
            make_event("StopLogging", "cloudtrail.amazonaws.com"),   # high
        ]
        self.assertEqual(ids(run_detections(events, min_severity="high")), ["TH-004"])

    def test_disabled_rule_is_skipped(self):
        event = make_event("StopLogging", "cloudtrail.amazonaws.com")
        self.assertEqual(run_detections([event], disabled=["TH-004"]), [])

    def test_alerts_are_sorted_by_time(self):
        events = [
            make_event("StopLogging", "cloudtrail.amazonaws.com", when="2026-11-02T12:00:00Z"),
            make_event("CreateUser", "iam.amazonaws.com", when="2026-11-02T09:00:00Z"),
        ]
        self.assertEqual(ids(run_detections(events)), ["TH-006", "TH-004"])

    def test_sample_scenario_triggers_every_rule(self):
        alerts = run_detections(load_events(str(SAMPLE)))
        self.assertEqual({a.rule_id for a in alerts}, {f"TH-{n:03d}" for n in range(1, 12)})
        self.assertEqual(len(alerts), 12)

    def test_normal_activity_in_sample_is_not_flagged(self):
        alerts = run_detections(load_events(str(SAMPLE)))
        flagged_users = {a.identity for a in alerts}
        self.assertNotIn("alice", flagged_users)
        self.assertNotIn("bob", flagged_users)
        self.assertNotIn("admin-ops", flagged_users)


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.event = make_event("ListBuckets", "s3.amazonaws.com")

    def tearDown(self):
        self.tmp.cleanup()

    def test_records_file(self):
        path = self.dir / "a.json"
        path.write_text(json.dumps({"Records": [self.event]}))
        self.assertEqual(len(load_events(str(path))), 1)

    def test_plain_array(self):
        path = self.dir / "a.json"
        path.write_text(json.dumps([self.event, self.event]))
        self.assertEqual(len(load_events(str(path))), 2)

    def test_json_lines(self):
        path = self.dir / "a.jsonl"
        path.write_text(json.dumps(self.event) + "\n" + json.dumps(self.event) + "\n")
        self.assertEqual(len(load_events(str(path))), 2)

    def test_gzip_file(self):
        path = self.dir / "a.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump({"Records": [self.event]}, handle)
        self.assertEqual(len(load_events(str(path))), 1)

    def test_folder_is_searched_recursively(self):
        nested = self.dir / "AWSLogs" / "2026"
        nested.mkdir(parents=True)
        (nested / "a.json").write_text(json.dumps({"Records": [self.event]}))
        self.assertEqual(len(load_events(str(self.dir))), 1)

    def test_digest_style_files_without_events_are_skipped(self):
        path = self.dir / "digest.json"
        path.write_text(json.dumps({"digestPublicKeyFingerprint": "abc"}))
        (self.dir / "a.json").write_text(json.dumps({"Records": [self.event]}))
        self.assertEqual(len(load_events(str(self.dir))), 1)

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_events(str(self.dir / "nope"))

    def test_empty_folder_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_events(str(self.dir))

    def test_invalid_json_raises_clear_error(self):
        path = self.dir / "bad.json"
        path.write_text("{not json\nstill not json")
        with self.assertRaises(ValueError):
            load_events(str(path))


if __name__ == "__main__":
    unittest.main()
