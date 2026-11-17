# TrailHound Walkthrough

This guide takes you from "I downloaded it" to "I understand it, I extended it, and I can explain it in an interview." Do the steps in order. Plan for about 3 to 4 hours spread over two or three days.

The goal is that **you** understand every line. If something here is unclear, that is the part to study before an interview.

## Step 1: Run it (15 minutes)

1. Check Python: `python --version` (3.9 or newer).
2. Run the tests: `python -m unittest discover -s tests -v`. You should see `OK`.
3. Run the detector on the sample attack:
   `python -m trailhound detect sample_data/cloudtrail_attack_scenario.json`
4. Run the IAM audit: `python -m trailhound audit-iam sample_data/policies`
5. Make a Markdown report: `python -m trailhound detect sample_data/cloudtrail_attack_scenario.json --format markdown -o report.md` and open `report.md`.

**Check yourself:** Can you say, in one sentence, what the attacker did between 02:14 and 02:35 in the sample data?

## Step 2: Read the code in this order (60 to 90 minutes)

Read each file fully before moving on. Open the sample log next to you and look at what a real event looks like.

1. **`sample_data/cloudtrail_attack_scenario.json`**: skim one `ConsoleLogin` event and one `AttachUserPolicy` event. Notice `userIdentity`, `eventSource`, `eventName`, `requestParameters`.
2. **`trailhound/models.py`**: two small data classes, `Alert` and `Finding`.
3. **`trailhound/events.py`**: why `get_path` exists (CloudTrail fields are often missing, and this avoids crashes).
4. **`trailhound/loader.py`**: how it handles `{"Records": [...]}`, JSON Lines, and `.gz`.
5. **`trailhound/rules.py`**: the heart of the project. Read `_trail_tampering` (simple), then `_access_key_created` (changes its own severity), then the `RULES` list at the bottom.
6. **`trailhound/engine.py`**: the loop. Focus on the sliding window for threshold rules.
7. **`trailhound/iam_audit.py`**: how each check looks at one statement.
8. **`tests/`**: read two or three tests per file. Tests show what each rule is supposed to do.

**Check yourself (write the answers down):**
- Why does TH-003 count failures per source IP while TH-011 counts per identity?
- Why does the engine call `window.clear()` after raising a threshold alert?
- Why can TH-002 produce false positives?
- Why does `IAM-004` skip statements that already got `IAM-002`?

## Step 3: Make it yours (60 to 90 minutes)

You are going to add a detection yourself. This is what turns a project you received into a project you own.

### Exercise A: add rule TH-012, "AWS Config recording stopped"

Attackers sometimes stop AWS Config so changes stop being recorded. The CloudTrail events are `StopConfigurationRecorder` and `DeleteConfigurationRecorder` from `config.amazonaws.com`. The recorder name is in `requestParameters.configurationRecorderName`.

1. Write a function in `rules.py` that returns `None` or a details dict. Model it on `_trail_tampering`.
2. Add a `Rule("TH-012", ...)` entry to the `RULES` list. Use severity `high` and ATT&CK `T1562.008`. Check that technique on attack.mitre.org yourself.
3. Write two tests in `tests/test_rules.py`: one event that should alert, one (`StartConfigurationRecorder`) that should not.
4. Run `python -m unittest discover -s tests -v`.
5. Run `python -m trailhound rules` and confirm TH-012 appears.

Try it before reading the hint below.

<details>
<summary>Hint (open only after you tried)</summary>

```python
def _config_recorder_stopped(event: dict) -> Details:
    if event.get("eventSource") != "config.amazonaws.com":
        return None
    if event.get("eventName") in {"StopConfigurationRecorder", "DeleteConfigurationRecorder"}:
        return {"recorder": get_path(event, "requestParameters", "configurationRecorderName")}
    return None
```

and in `RULES`:

```python
Rule("TH-012", "AWS Config recording stopped", "high", "T1562.008",
     "AWS Config stopped recording resource changes, which hides configuration drift.",
     _config_recorder_stopped),
```
</details>

### Exercise B: add a real event to the sample data

Edit `sample_data/generate_sample_data.py` so the attacker also stops the Config recorder at 02:27. Run it, run `detect` again, and confirm your new alert shows up. Update the count in `test_sample_scenario_triggers_every_rule` and `tests/test_cli.py` (they currently expect 12 alerts) and make the tests pass again. Fixing broken tests is a real engineering skill.

### Exercise C (optional): a new IAM check

Add `IAM-007`: flag `sts:AssumeRole` allowed on `Resource: "*"`. Add a sample policy file and a test.

## Step 4: Put it on GitHub (20 minutes)

```bash
cd trailhound
git init
git add .
git commit -m "Initial commit: TrailHound CloudTrail detection and IAM audit toolkit"
git branch -M main
git remote add origin https://github.com/<your-handle>/trailhound.git
git push -u origin main
```

Create the empty repository on GitHub first (no README, since you already have one). Then:

1. Replace `<your-handle>` in `README.md`.
2. Make your Exercise A change a **separate commit** with a clear message, for example `Add TH-012: detect AWS Config recorder stopped`. A commit history that shows you adding something is better than one big upload.
3. Confirm the GitHub Actions tab shows the tests passing (the workflow is already in `.github/workflows/ci.yml`).
4. Add a short description and topics to the repo: `aws`, `cloudtrail`, `detection-engineering`, `mitre-attack`, `python`.

## Step 5: Use it on real data (30 minutes, optional but strong)

If you have an AWS account (even your lab one), download real CloudTrail logs and run the tool on them. Write down what it found, what was a false positive, and what you would tune. A short "what I learned running it on real logs" note in the README is excellent evidence of real analysis. Do not commit real logs or real account IDs to GitHub.

## Step 6: Put it on your resume honestly

Only add this after you have done Steps 1 to 4. Use only what is true. A realistic entry:

> **TrailHound: AWS CloudTrail Detection and IAM Audit Toolkit** | Python | github.com/&lt;your-handle&gt;/trailhound
> - Built a Python CLI that detects attacker behavior in CloudTrail logs using 11 rules mapped to MITRE ATT&CK (root use, MFA bypass, log tampering, privilege escalation, secret theft).
> - Added an IAM policy auditor with 6 checks for over-permissive access, and CI-friendly exit codes.
> - Wrote 70+ unit and end-to-end tests and a synthetic attack dataset to validate every rule.

If you added your own rules or ran it on real logs, add that line too (for example, "Extended with additional rules for AWS Config tampering").

**Be honest about how it was made.** This project was scaffolded with AI assistance, and if an interviewer asks, say so plainly, then talk about what you did: ran it, read it, extended it, tested it. Employers care that you understand and can maintain the work.

## Step 7: Interview talking points

Be able to answer these in your own words:

- **What problem does it solve?** It finds common attacker steps in AWS logs and risky IAM permissions without needing a SIEM.
- **Why these detections?** Each maps to an attacker goal: initial access, persistence, privilege escalation, defense evasion, credential access.
- **How does a threshold rule work?** It keeps a sliding window of matching events per group and alerts when the count is reached, then resets so it does not spam.
- **What are the false positives?** SSO logins that report no MFA, legitimate admin activity, and automation that creates access keys. A real deployment would add allowlists.
- **What are the limits?** No baselines, event-based only, literal wildcard matching in IAM checks.
- **How would you scale it?** Read from S3 or a streaming source, store alerts, add allowlists and tuning, export rules to a SIEM format such as Splunk or Sigma.
- **How did you test it?** Unit tests for each rule, negative tests so normal activity stays quiet, and an end-to-end test on a synthetic attack.

## Step 8: Next upgrades (pick one when you have time)

1. Export every rule as a Splunk SPL search, so the project connects to your Splunk experience.
2. Add an `--allowlist` file so known users and IPs are ignored.
3. Add an optional `boto3` mode that reads logs straight from S3.
4. Add a rule for activity in regions you never use.
5. Send high-severity alerts to a Slack webhook.

Each upgrade is a good new commit, a good new line on your resume, and a good interview story.
