# SIEM Lab Plan

## Goal

Build a practical SOC homelab with reliable log ingestion, at least one detection alert, and clear milestone documentation.

## Stack choice

- [x] Splunk
- [ ] ELK
Chosen: Splunk

---

## Lab environment

- Host machine: Lenovo m720q running Proxmox (bare metal)
- VM(s): Ubuntu Server VM (Splunk) + Windows 10 VM (log source)
- Log sources:
  - Windows Event Logs (Security/System/Application)
  - Sysmon (operational and ingested)

---

## Milestone status

### Milestone 1 - SIEM ingestion foundation (Completed)

- [x] Install/prepare Proxmox on m720q
- [x] Create Ubuntu Server VM (Splunk VM)
- [x] Install Splunk and confirm web UI works
- [x] Create Windows VM (log source)
- [x] Install Splunk Universal Forwarder on Windows
- [x] Ingest Windows Event Logs into Splunk
- [x] Verify logs are searchable
- [x] Capture proof screenshot(s)

Deliverable: `siem-lab-milestone1.md` plus screenshot evidence in `assets/`.

### Milestone 2 - Failed logon detection alert (Completed)

- [x] Validate/restore Security log forwarding path
- [x] Generate failed-login test events
- [x] Build SPL for repeated failed logons with threshold logic
- [x] Save alert: `M2 - Excessive Failed Logons (4625 text match)`
- [x] Configure scheduled run (every 5 minutes) and trigger condition
- [x] Capture detection and alert evidence screenshots
- [x] Document implementation and validation in milestone writeup

Deliverable: `siem-lab-milestone2.md` plus screenshots:
- `assets/m2-failed-logons-results.png`
- `assets/m2-alert-configured.png`

---

## Milestone 3 - Failed-logons by source (Completed)

### Objective

Implement and validate a source-centric failed-logon detection using Windows Security events in Splunk.

### Completed tasks

- [x] Run baseline ingestion gate checks (`index=main`, Security sourcetype)
- [x] Build and run M3 SPL grouped by source (`src_ip`) and host
- [x] Validate threshold logic (`failed_attempts >= 5`) with live test data
- [x] Capture evidence screenshot(s)
- [x] Finalize `siem-lab-milestone3.md`

Evidence:
- `assets/m3-gate-index-main-head5.png`
- `assets/m3-gate-security-ingest.png`
- `assets/m3-failed-logons-by-source.png`

---

## Milestone 4 - Sysmon + process-based detection (Completed)

### Objective

Onboard Sysmon telemetry and operationalize one process-based PowerShell detection.

### Completed tasks

- [x] Install Sysmon on Windows endpoint
- [x] Apply baseline Sysmon config (community baseline)
- [x] Confirm Sysmon events are ingested in Splunk
- [x] Validate key event types (`event_id=1` and `event_id=3`)
- [x] Build process-based detection (suspicious PowerShell execution)
- [x] Save/schedule detection object in Splunk
- [x] Capture proof screenshot(s)
- [x] Write `siem-lab-milestone4.md`

Evidence:
- `assets/m4-gate-index-main-head5.png`
- `assets/m4-sysmon-service-running.png`
- `assets/m4-sysmon-config-applied.png`
- `assets/m4-sysmon-ingest-confirmed.png`
- `assets/m4-sysmon-key-events.png`
- `assets/m4-detection-results-powershell.png`
- `assets/m4-alert-config-verify.png`

---

## Next milestone (Milestone 5 - Planned)

### Objective

Raise detection fidelity with behavior correlation and reduced false positives.

### Planned tasks

- [ ] Tune PowerShell detection to suppress known benign UF/internal activity
- [ ] Add parent/child process context fields and exclusions
- [ ] Add one additional endpoint detection (for example: suspicious script download or LOLBin abuse)
- [ ] Build a compact triage dashboard for endpoint detections
- [ ] Capture evidence and write `siem-lab-milestone5.md`

---

## Current definition of done (project-level)

- [x] Milestone 1 completed and documented
- [x] Milestone 2 completed and documented
- [x] Milestone 3 completed and documented
- [x] Milestone 4 completed and documented
- [x] At least 3 solid SOC-ready detection examples across milestones

---

## Notes

- Keep all screenshots under `siem-lab/assets/`
- Keep milestone files concise, reproducible, and evidence-based
- Do not store credentials, tokens, or secrets in repository files
