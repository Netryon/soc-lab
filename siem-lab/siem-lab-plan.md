# SIEM Lab – Milestone 1 Plan

## Goal
Build a basic SIEM lab to ingest logs and detect at least one suspicious activity.

## Stack choice
- [X] Splunk
- [ ] ELK
Chosen: Splunk

## Lab environment
- Host machine: Lenovo m720q running Proxmox (bare metal)
- VM(s): Ubuntu Server VM (Splunk) + Windows 10 VM (log source)
- Log source(s): Windows Event Logs + Sysmon

## Milestone 1 tasks (today)
- [X] Install/prepare Proxmox on m720q
- [X] Create Ubuntu Server VM (Splunk VM)
- [X] Install Splunk and confirm web UI works
- [X] Create Windows VM (log source)
- [X] Ingest at least one Windows log source into Splunk
- [X] Verify logs are searchable
- [X] Take 1–2 screenshots as proof (Splunk UI + ingested logs)

## Definition of done
I can search logs in the SIEM and show one screenshot as proof.
