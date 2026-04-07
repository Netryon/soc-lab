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
  - Sysmon (planned next)

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

## Next milestone (Milestone 4 - Planned)

### Objective

Add Sysmon telemetry and create one process-based detection.

### Planned tasks

- [ ] Install Sysmon on Windows endpoint
- [ ] Apply baseline Sysmon config (community baseline)
- [ ] Confirm Sysmon events are ingested in Splunk
- [ ] Validate key event types (process create, network connect, image load)
- [ ] Build one simple detection (example: suspicious PowerShell execution)
- [ ] Save as scheduled alert with threshold/logic
- [ ] Capture proof screenshot(s)
- [ ] Write `siem-lab-milestone4.md`

---

## Current definition of done (project-level)

- [x] Milestone 1 completed and documented
- [x] Milestone 2 completed and documented
- [x] Milestone 3 completed and documented
- [ ] At least 3 solid SOC-ready detection examples across milestones

---

## Notes

- Keep all screenshots under `siem-lab/assets/`
- Keep milestone files concise, reproducible, and evidence-based
- Do not store credentials, tokens, or secrets in repository files
