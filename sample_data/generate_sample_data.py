#!/usr/bin/env python3
"""Generate a SYNTHETIC CloudTrail log containing a staged attack.

Nothing here comes from a real account. IP addresses use the reserved
documentation ranges (203.0.113.0/24 and 198.51.100.0/24) and the account ID
is the standard AWS example value.

Run:  python sample_data/generate_sample_data.py
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACCOUNT = "123456789012"
NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")
BASE = datetime(2026, 11, 2, 0, 0, 0, tzinfo=timezone.utc)
ATTACKER_IP = "203.0.113.50"
OFFICE_IP = "198.51.100.10"

_counter = 0


def at(hours: int, minutes: int, seconds: int = 0) -> str:
    moment = BASE + timedelta(hours=hours, minutes=minutes, seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def user(name: str) -> dict:
    return {
        "type": "IAMUser",
        "principalId": f"AIDAEXAMPLE{name.upper()}",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "userName": name,
    }


ROOT = {"type": "Root", "principalId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:root", "accountId": ACCOUNT}


def event(when, name, source, identity, ip, params=None, response=None,
          extra=None, event_type="AwsApiCall", error=None):
    global _counter
    _counter += 1
    item = {
        "eventVersion": "1.08",
        "userIdentity": identity,
        "eventTime": when,
        "eventSource": source,
        "eventName": name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.15.0",
        "requestParameters": params,
        "responseElements": response,
        "requestID": str(uuid.uuid5(NAMESPACE, f"request-{_counter}")),
        "eventID": str(uuid.uuid5(NAMESPACE, f"event-{_counter}")),
        "eventType": event_type,
        "recipientAccountId": ACCOUNT,
    }
    if extra:
        item["additionalEventData"] = extra
    if error:
        item["errorCode"] = error
    return item


def console_login(when, identity, ip, success, mfa):
    return event(
        when, "ConsoleLogin", "signin.amazonaws.com", identity, ip,
        response={"ConsoleLogin": "Success" if success else "Failure"},
        extra={"MFAUsed": "Yes" if mfa else "No"},
        event_type="AwsConsoleSignIn",
    )


def build_events() -> list:
    events = []

    # ---- Normal activity that should NOT raise alerts -------------------
    events.append(console_login(at(1, 30), user("alice"), OFFICE_IP, True, True))
    events.append(event(at(1, 31), "DescribeInstances", "ec2.amazonaws.com", user("alice"), OFFICE_IP))
    events.append(event(at(1, 40), "ListBuckets", "s3.amazonaws.com", user("bob"), OFFICE_IP))
    events.append(event(at(1, 45), "AttachUserPolicy", "iam.amazonaws.com", user("admin-ops"), OFFICE_IP,
                        params={"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}))
    events.append(event(at(1, 50), "GetObject", "s3.amazonaws.com", user("bob"), OFFICE_IP,
                        params={"bucketName": "corp-reports-demo", "key": "q3/summary.pdf"}))

    # ---- The staged attack ----------------------------------------------
    # 01:05 Root login from a strange IP, no MFA (TH-001, TH-002)
    events.append(console_login(at(1, 5), ROOT, "198.51.100.77", True, False))

    # 02:14-02:16 password guessing against svc-backup (TH-003)
    for i in range(6):
        events.append(console_login(at(2, 14, i * 25), user("svc-backup"), ATTACKER_IP, False, False))

    # 02:17 the attacker gets in without MFA (TH-002)
    events.append(console_login(at(2, 17), user("svc-backup"), ATTACKER_IP, True, False))

    # 02:20 persistence: new user, access key, admin rights (TH-006, TH-007, TH-008)
    events.append(event(at(2, 20), "CreateUser", "iam.amazonaws.com", user("svc-backup"), ATTACKER_IP,
                        params={"userName": "backup-helper"}))
    events.append(event(at(2, 21), "CreateAccessKey", "iam.amazonaws.com", user("svc-backup"), ATTACKER_IP,
                        params={"userName": "backup-helper"},
                        response={"accessKey": {"userName": "backup-helper", "status": "Active"}}))
    events.append(event(at(2, 22), "AttachUserPolicy", "iam.amazonaws.com", user("svc-backup"), ATTACKER_IP,
                        params={"userName": "backup-helper",
                                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))

    # 02:25 defense evasion (TH-004, TH-005)
    events.append(event(at(2, 25), "StopLogging", "cloudtrail.amazonaws.com", user("backup-helper"), ATTACKER_IP,
                        params={"name": "corp-trail"}))
    events.append(event(at(2, 26), "UpdateDetector", "guardduty.amazonaws.com", user("backup-helper"), ATTACKER_IP,
                        params={"detectorId": "12abc34d567e8fa901bc2d34e56789f0", "enable": False}))

    # 02:28 open SSH to the world (TH-010)
    events.append(event(at(2, 28), "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com",
                        user("backup-helper"), ATTACKER_IP,
                        params={"groupId": "sg-0abc1234def567890",
                                "ipPermissions": {"items": [{
                                    "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}))

    # 02:30 bulk secret theft: 12 reads, 10 seconds apart (TH-011)
    for i in range(12):
        events.append(event(at(2, 30, i * 10), "GetSecretValue", "secretsmanager.amazonaws.com",
                            user("backup-helper"), ATTACKER_IP,
                            params={"secretId": f"prod/app/secret-{i + 1}"}))

    # 02:35 make data exposure possible (TH-009)
    events.append(event(at(2, 35), "DeleteBucketPublicAccessBlock", "s3.amazonaws.com",
                        user("backup-helper"), ATTACKER_IP,
                        params={"bucketName": "corp-reports-demo"}))

    events.sort(key=lambda e: e["eventTime"])
    return events


def main() -> None:
    target = Path(__file__).resolve().parent / "cloudtrail_attack_scenario.json"
    target.write_text(json.dumps({"Records": build_events()}, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {target}")


if __name__ == "__main__":
    main()
