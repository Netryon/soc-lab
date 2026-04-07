# SIEM Lab - Milestone 3 (Failed Logons by Source)

## Executive summary

In this milestone, I implemented and validated a source-centric failed-logon detection in Splunk to identify brute-force-like authentication bursts.
The rule groups failed logons by source IP and host in 5-minute buckets, then alerts when volume exceeds a threshold.

---

## Objective

Build a reproducible detection that highlights repeated failed Windows logons from the same source in a short interval, then document analyst interpretation with real lab evidence.

---

## Detection use case

- Repeated failed logons from one source can indicate password guessing, spray behavior, or automation.
- Focus: group by `src_ip` and `host` to make suspicious sources obvious.
- Data source: `index=main`, `sourcetype="WinEventLog:Security"`.

---

## SPL query

```spl
index=main sourcetype="WinEventLog:Security" "An account failed to log on"
| rex field=Message "Source Network Address:\s+(?<src_ip>[^\r\n]+)"
| rex field=Message "Account Name:\s+(?<failed_account>[^\r\n]+)"
| bin _time span=5m
| stats count as failed_attempts values(failed_account) as failed_accounts by _time, host, src_ip
| where failed_attempts >= 5
| sort - failed_attempts
```

### Logic summary

- Filter failed-logon Security events by canonical message text.
- Extract `src_ip` and `failed_account` from `Message`.
- Aggregate into 5-minute windows by `_time`, `host`, `src_ip`.
- Keep rows where `failed_attempts >= 5` for analyst triage.

---

## Validation run (observed)

Test run used **Last 24 hours** and returned multiple rows above threshold.

Observed sample evidence from captured run:
- `src_ip`: `127.0.0.1`
- `host`: `DESKTOP-QKE3NI0`
- `failed_attempts`: observed up to `130` in one 5-minute bucket
- `failed_accounts`: included machine account values (for example `DESKTOP-QKE3NI0$`)

This confirms the query and threshold are functioning as expected in the rebuilt lab.

---

## Analyst interpretation (TP/FP)

- **Likely malicious pattern:** high failed-auth volume from one non-loopback source across accounts/hosts in short windows.
- **Likely benign in this run:** loopback source (`127.0.0.1`) and intentional lab test behavior.
- **Decision for captured data:** likely benign test activity, detection behavior validated.
- **Tuning idea:** treat loopback/local system authentication separately to reduce noisy benign hits.

---

## Evidence

Required run evidence:
- `assets/m3-gate-index-main-head5.png`
- `assets/m3-gate-security-ingest.png`
- `assets/m3-failed-logons-by-source.png`

Related closure evidence for rebuild sign-off:
- `assets/m2-alert-config-verify.png`
- `assets/m2-alert-config-verify-details.png`
- `assets/m2-alert-fire-test.png`
- `assets/m2-alert-fire-test-job-evidence.png`

---

## Milestone outcome

Milestone 3 is complete for this scope:
- source-centric failed-logon detection implemented and validated,
- reproducible SPL documented,
- evidence captured from live lab output,
- analyst TP/FP judgement recorded.
