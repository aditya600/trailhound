"""Detection rules.

A rule is a small function that takes ONE CloudTrail event and returns either
None (no match) or a dict of details (match).

* A rule can raise or lower its severity for one specific event by putting
  "_severity" in the details it returns.
* A threshold rule only fires when the same group (for example one source IP)
  matches `threshold` times within `window_seconds`.

MITRE ATT&CK IDs are a best-effort mapping. Check them on attack.mitre.org.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .events import get_path, identity_name
from .policy_utils import grants_full_admin, statements

Details = Optional[Dict[str, Any]]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    mitre: str
    description: str
    match: Callable[[dict], Details]
    threshold: Optional[int] = None
    window_seconds: int = 0
    group_by: Callable[[dict], str] = lambda e: e.get("sourceIPAddress", "unknown")


# --------------------------------------------------------------------------
# Rule functions
# --------------------------------------------------------------------------

def _root_usage(event: dict) -> Details:
    identity = event.get("userIdentity") or {}
    if identity.get("type") == "Root" and event.get("eventType") != "AwsServiceEvent":
        return {"api_call": event.get("eventName")}
    return None


def _console_login_no_mfa(event: dict) -> Details:
    if event.get("eventName") != "ConsoleLogin":
        return None
    if get_path(event, "responseElements", "ConsoleLogin") != "Success":
        return None
    if get_path(event, "additionalEventData", "MFAUsed") != "No":
        return None
    user_type = get_path(event, "userIdentity", "type")
    details: Dict[str, Any] = {
        "user_type": user_type,
        "note": "SSO or federated logins can report MFAUsed=No; check with your identity provider.",
    }
    if user_type == "Root":
        details["_severity"] = "high"
    return details


def _console_login_failure(event: dict) -> Details:
    if event.get("eventName") == "ConsoleLogin" and (
        get_path(event, "responseElements", "ConsoleLogin") == "Failure"
    ):
        return {}
    return None


def _trail_tampering(event: dict) -> Details:
    if event.get("eventSource") != "cloudtrail.amazonaws.com":
        return None
    if event.get("eventName") in {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}:
        return {
            "trail": get_path(event, "requestParameters", "name"),
            "error": event.get("errorCode"),
        }
    return None


def _guardduty_tampering(event: dict) -> Details:
    if event.get("eventSource") != "guardduty.amazonaws.com":
        return None
    name = event.get("eventName")
    if name in {
        "DeleteDetector",
        "StopMonitoringMembers",
        "DisassociateFromMasterAccount",
        "DisassociateFromAdministratorAccount",
    }:
        return {"detector": get_path(event, "requestParameters", "detectorId")}
    if name == "UpdateDetector" and get_path(event, "requestParameters", "enable") is False:
        return {"detector": get_path(event, "requestParameters", "detectorId"), "enable": False}
    return None


def _new_iam_user(event: dict) -> Details:
    if event.get("eventSource") != "iam.amazonaws.com":
        return None
    if event.get("eventName") in {"CreateUser", "CreateLoginProfile"}:
        return {"target_user": get_path(event, "requestParameters", "userName")}
    return None


def _access_key_created(event: dict) -> Details:
    if event.get("eventSource") != "iam.amazonaws.com" or event.get("eventName") != "CreateAccessKey":
        return None
    target = get_path(event, "requestParameters", "userName")
    caller = get_path(event, "userIdentity", "userName")
    details: Dict[str, Any] = {"target_user": target or caller, "created_by": caller}
    if target and caller and target != caller:
        details["for_another_user"] = True
        details["_severity"] = "high"
    return details


def _admin_granted(event: dict) -> Details:
    if event.get("eventSource") != "iam.amazonaws.com":
        return None
    name = event.get("eventName")
    if name in {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}:
        arn = get_path(event, "requestParameters", "policyArn", default="")
        if arn.endswith("/AdministratorAccess") or arn.endswith("/IAMFullAccess"):
            target = (
                get_path(event, "requestParameters", "userName")
                or get_path(event, "requestParameters", "roleName")
                or get_path(event, "requestParameters", "groupName")
            )
            return {"policy_arn": arn, "target": target}
    if name in {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"}:
        document = get_path(event, "requestParameters", "policyDocument")
        if any(grants_full_admin(s) for s in statements(document)):
            return {"policy_name": get_path(event, "requestParameters", "policyName"), "grants": "Allow * on *"}
    return None


def _s3_public_access_block_removed(event: dict) -> Details:
    if event.get("eventSource") != "s3.amazonaws.com":
        return None
    name = event.get("eventName")
    bucket = get_path(event, "requestParameters", "bucketName")
    if name == "DeleteBucketPublicAccessBlock":
        return {"bucket": bucket}
    if name == "PutBucketPublicAccessBlock":
        config = get_path(event, "requestParameters", "PublicAccessBlockConfiguration", default={})
        if isinstance(config, dict) and any(value is False for value in config.values()):
            return {"bucket": bucket, "configuration": config}
    return None


SENSITIVE_PORTS = (22, 3389)


def _security_group_open_to_world(event: dict) -> Details:
    if event.get("eventSource") != "ec2.amazonaws.com":
        return None
    if event.get("eventName") != "AuthorizeSecurityGroupIngress":
        return None
    permissions = get_path(event, "requestParameters", "ipPermissions", "items", default=[])
    exposed = []
    for permission in permissions:
        cidrs = [r.get("cidrIp") for r in get_path(permission, "ipRanges", "items", default=[])]
        cidrs += [r.get("cidrIpv6") for r in get_path(permission, "ipv6Ranges", "items", default=[])]
        if "0.0.0.0/0" not in cidrs and "::/0" not in cidrs:
            continue
        protocol = permission.get("ipProtocol")
        low = permission.get("fromPort")
        high = permission.get("toPort", low)
        all_ports = str(protocol) == "-1" or low is None
        if all_ports or any(low <= port <= high for port in SENSITIVE_PORTS):
            exposed.append({"protocol": protocol, "from_port": low, "to_port": high})
    if exposed:
        return {"group_id": get_path(event, "requestParameters", "groupId"), "exposed": exposed}
    return None


SECRET_READS = {
    ("secretsmanager.amazonaws.com", "GetSecretValue"),
    ("ssm.amazonaws.com", "GetParameter"),
    ("ssm.amazonaws.com", "GetParameters"),
    ("ssm.amazonaws.com", "GetParametersByPath"),
}


def _secret_read(event: dict) -> Details:
    if (event.get("eventSource"), event.get("eventName")) in SECRET_READS:
        return {}
    return None


# --------------------------------------------------------------------------
# The rule catalogue
# --------------------------------------------------------------------------

def _config_recorder_stopped(event: dict) -> Details:
    if event.get("eventSource") != "config.amazonaws.com":
        return None
    if event.get("eventName") in {"StopConfigurationRecorder", "DeleteConfigurationRecorder"}:
        return {"recorder": get_path(event, "requestParameters", "configurationRecorderName")}
    return None

RULES: List[Rule] = [

    Rule("TH-001", "Root account activity", "high", "T1078.004",
         "The AWS root user made a call. Root should be used almost never.",
         _root_usage),
    Rule("TH-002", "Console login without MFA", "medium", "T1078.004",
         "A successful console sign-in did not use multi-factor authentication.",
         _console_login_no_mfa),
    Rule("TH-003", "Burst of failed console logins", "medium", "T1110",
         "Five or more failed console logins from one IP within 10 minutes (possible password guessing).",
         _console_login_failure, threshold=5, window_seconds=600),
    Rule("TH-004", "CloudTrail logging tampered with", "high", "T1562.008",
         "Someone stopped, deleted or changed a trail. Attackers do this to hide their activity.",
         _trail_tampering),
    Rule("TH-005", "GuardDuty disabled or weakened", "high", "T1562.001",
         "GuardDuty threat detection was turned off or detached from its administrator.",
         _guardduty_tampering),
    Rule("TH-006", "New IAM user or login profile", "medium", "T1136.003",
         "A new IAM user or console password was created, a common persistence step.",
         _new_iam_user),
    Rule("TH-007", "IAM access key created", "medium", "T1098.001",
         "A new access key was created. It is high severity when made for a different user.",
         _access_key_created),
    Rule("TH-008", "Administrator privileges granted", "high", "T1098.003",
         "AdministratorAccess (or an equivalent policy) was attached to a user, role or group.",
         _admin_granted),
    Rule("TH-009", "S3 Block Public Access removed", "medium", "T1562",
         "A bucket's Block Public Access protection was removed or relaxed.",
         _s3_public_access_block_removed),
    Rule("TH-010", "Security group opened to the internet", "high", "T1562.007",
         "A security group rule now allows the whole internet to reach SSH, RDP or all ports.",
         _security_group_open_to_world),
    Rule("TH-011", "Bulk secret or parameter reads", "medium", "T1555.006",
         "One identity read 10 or more secrets or parameters within 5 minutes.",
         _secret_read, threshold=10, window_seconds=300,
         group_by=identity_name),

    Rule("TH-012", "AWS Config recording stopped", "high", "T1562.008",
         "AWS Config stopped recording resource changes, which hides configuration drift.",
         _config_recorder_stopped),
]


def get_rule(rule_id: str) -> Rule:
    for rule in RULES:
        if rule.rule_id == rule_id:
            return rule
    raise KeyError(rule_id)
