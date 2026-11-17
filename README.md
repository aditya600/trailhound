# TrailHound

A small, dependency-free command-line toolkit for AWS security work:

- **`detect`** scans AWS CloudTrail logs for attacker behavior using 11 detection rules mapped to MITRE ATT&CK.
- **`audit-iam`** statically audits IAM policy JSON files for dangerous permissions (6 checks).
- **Reports** in text, JSON, or Markdown, with exit codes that make it easy to use in CI pipelines.

It needs only Python 3.11+ and nothing else. It never connects to AWS, so it is safe to run on exported logs and policy files.

## Quick start

```bash
git clone https://github.com/aditya600/trailhound.git
cd trailhound

python -m trailhound rules
python -m trailhound detect sample_data/cloudtrail_attack_scenario.json
python -m trailhound detect sample_data/cloudtrail_attack_scenario.json --format markdown -o report.md
python -m trailhound audit-iam sample_data/policies
python -m unittest discover -s tests -v
```

Optional: `pip install -e .` gives you a `trailhound` command.

The sample data is **synthetic** (reserved documentation IP ranges, example account ID). It tells the story of an attacker who guesses a password, creates a backdoor admin user, turns off logging and GuardDuty, opens SSH to the internet, steals secrets, and weakens S3 protection. Normal activity from other users is mixed in, and it should not raise alerts.

## Using it on real logs

Download your CloudTrail logs and point TrailHound at the folder. It reads `.json`, `.jsonl`, and `.gz` files recursively:

```bash
aws s3 sync s3://YOUR-TRAIL-BUCKET/AWSLogs/ ./logs/
python -m trailhound detect ./logs --min-severity medium --format markdown -o report.md
```

Export an IAM policy and audit it:

```bash
aws iam get-policy-version --policy-arn <arn> --version-id v1 > policy.json
python -m trailhound audit-iam policy.json
```

## Detection rules

| ID | Severity | ATT&CK | What it detects |
| --- | --- | --- | --- |
| TH-001 | high | T1078.004 | Root account activity |
| TH-002 | medium (high for root) | T1078.004 | Console login without MFA |
| TH-003 | medium | T1110 | 5+ failed console logins from one IP in 10 minutes |
| TH-004 | high | T1562.008 | CloudTrail stopped, deleted or changed |
| TH-005 | high | T1562.001 | GuardDuty disabled or detached |
| TH-006 | medium | T1136.003 | New IAM user or console password |
| TH-007 | medium (high if for another user) | T1098.001 | IAM access key created |
| TH-008 | high | T1098.003 | AdministratorAccess granted |
| TH-009 | medium | T1562 | S3 Block Public Access removed or relaxed |
| TH-010 | high | T1562.007 | Security group opened to the internet on SSH, RDP or all ports |
| TH-011 | medium | T1555.006 | 10+ secret or parameter reads in 5 minutes by one identity |

ATT&CK mappings are best effort. Check them against attack.mitre.org before relying on them.

## IAM audit checks

| ID | Severity | What it flags |
| --- | --- | --- |
| IAM-001 | critical | `Allow *` on `*` |
| IAM-002 | high | A whole service on all resources (for example `s3:*`) |
| IAM-003 | high | Privilege-escalation permissions on all resources (for example `iam:PassRole`) |
| IAM-004 | medium | Sensitive data actions on all resources (secrets, KMS decrypt, S3 reads) |
| IAM-005 | medium / high | `Allow` combined with `NotAction` |
| IAM-006 | high | Wildcard principal with no condition |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Nothing to report |
| 1 | Alerts or findings were reported |
| 2 | Error (bad path, bad arguments, unreadable file) |

This makes it usable as a pipeline gate: a non-zero exit fails the build.

## How it works

```
trailhound/
  loader.py        reads files and folders (json, jsonl, gz) and sorts events by time
  rules.py         one small function per detection plus the rule catalogue
  engine.py        runs rules over events and handles sliding-window thresholds
  iam_audit.py     checks policy statements for risky permissions
  policy_utils.py  helpers for reading IAM policy documents
  report.py        text, JSON and Markdown output
  cli.py           command-line interface
tests/             71 unit and end-to-end tests
```

A rule takes one event and returns `None` or a dict of details. Threshold rules count matches per group (for example per source IP) inside a time window and fire once when the count is reached.

## Limitations

- Rules are intentionally simple and event-based. They do not use baselines or machine learning, so expect some false positives (for example, SSO logins can report `MFAUsed=No`).
- Resource matching in the IAM audit looks for the literal `*`. Broad but non-wildcard ARNs are not flagged.
- It analyzes exported files. It does not stream logs or call AWS.
- Mappings, thresholds, and severities are starting points. Tune them to your environment.

## Ideas for extending it

- Export detections to Splunk SPL or Sigma format
- Read logs directly from S3 with `boto3` (optional dependency)
- Add a rule for unusual regions based on an allowlist
- Send alerts to Slack or email
- Add a baseline mode that learns which users normally create access keys

## License

MIT. See `LICENSE`.
