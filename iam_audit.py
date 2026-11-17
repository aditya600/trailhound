"""Static analysis of IAM policy documents (no AWS access needed)."""

import json
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .models import Finding, severity_rank
from .policy_utils import action_matches, as_list, grants_full_admin, statements

# Permissions that let a user raise their own privileges when granted on "*".
PRIV_ESC_ACTIONS = [
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
]

# Actions that read sensitive data. Granting them on "*" is rarely needed.
DATA_ACTIONS = [
    "s3:GetObject",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "ssm:GetParameter",
    "dynamodb:Scan",
]


def _strings(value: Any) -> List[str]:
    return [v for v in as_list(value) if isinstance(v, str)]


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in _strings(principal.get("AWS"))
    return False


def audit_policy(document: Any, source: str = "<policy>") -> List[Finding]:
    """Return findings for every risky Allow statement in a policy."""
    findings: List[Finding] = []

    for index, statement in enumerate(statements(document), start=1):
        if statement.get("Effect") != "Allow":
            continue

        actions = _strings(statement.get("Action"))
        resources = _strings(statement.get("Resource"))
        has_condition = bool(statement.get("Condition"))
        note = " The statement has a Condition; check that it really limits access." if has_condition else ""

        def add(check_id: str, title: str, severity: str, description: str, fix: str) -> None:
            findings.append(
                Finding(check_id, title, severity, source, index, description + note, fix)
            )

        # IAM-006: anyone can use this statement (trust and resource policies).
        if "Principal" in statement and _principal_is_public(statement["Principal"]) and not has_condition:
            add("IAM-006", "Wildcard principal", "high",
                "Principal is '*', so any AWS account (or anyone) can use this statement.",
                "Name the exact accounts or roles, or add a Condition such as aws:PrincipalOrgID.")

        # IAM-001: full administrator.
        if grants_full_admin(statement):
            add("IAM-001", "Full administrator access", "critical",
                "Allows every action on every resource.",
                "Replace with the specific actions and resources this identity needs.")
            continue

        # IAM-005: Allow + NotAction grants everything except the listed actions.
        if "NotAction" in statement:
            severity = "high" if "*" in resources else "medium"
            add("IAM-005", "Allow with NotAction", severity,
                "Allow with NotAction grants all actions except the ones listed, which is usually far broader than intended.",
                "List the allowed actions explicitly with Action instead of excluding some with NotAction.")

        service_wildcard = False
        if "*" in resources:
            # IAM-002: a whole service on all resources, like s3:*
            wildcards = [a for a in actions if a != "*" and a.endswith(":*")]
            if wildcards:
                service_wildcard = True
                add("IAM-002", "Service-wide wildcard on all resources", "high",
                    f"Allows every action of {', '.join(wildcards)} on all resources.",
                    "Limit the actions to those needed and the resource to specific ARNs.")

            # IAM-003: privilege escalation permissions on all resources.
            risky = [a for a in PRIV_ESC_ACTIONS if any(action_matches(p, a) for p in actions)]
            if risky:
                add("IAM-003", "Privilege escalation permissions on all resources", "high",
                    f"Can be used to gain more access: {', '.join(risky)}.",
                    "Restrict these to specific role or policy ARNs, and add conditions such as iam:PassedToService.")

            # IAM-004: sensitive data access on all resources.
            if not service_wildcard:
                data = [a for a in DATA_ACTIONS if any(action_matches(p, a) for p in actions)]
                if data:
                    add("IAM-004", "Sensitive data access on all resources", "medium",
                        f"Can read data across the whole account: {', '.join(data)}.",
                        "Scope the resource to the specific buckets, secrets or keys that are needed.")

    findings.sort(key=lambda f: (-severity_rank(f.severity), f.statement))
    return findings


def _find_policy(data: Any, depth: int = 0) -> Optional[dict]:
    """Find the policy document even when it is wrapped in AWS CLI output."""
    if depth > 4:
        return None
    if isinstance(data, dict):
        if "Statement" in data:
            return data
        for value in data.values():
            found = _find_policy(value, depth + 1)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _find_policy(item, depth + 1)
            if found is not None:
                return found
    return None


def audit_path(path: str) -> Tuple[List[Finding], List[str]]:
    """Audit one policy file or every .json file in a folder.

    Returns (findings, skipped_files). Files without a policy are skipped.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")
    files = [root] if root.is_file() else sorted(root.rglob("*.json"))
    if not files:
        raise FileNotFoundError(f"no .json policy files found in: {root}")

    findings: List[Finding] = []
    skipped: List[str] = []
    for file in files:
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            skipped.append(str(file))
            continue
        policy = _find_policy(data)
        if policy is None:
            skipped.append(str(file))
            continue
        findings.extend(audit_policy(policy, source=str(file)))

    findings.sort(key=lambda f: (-severity_rank(f.severity), f.file, f.statement))
    return findings, skipped
