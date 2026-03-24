# SIEM Lab – Milestone 1 (complete)

Homelab SIEM proof: Splunk Enterprise ingesting Windows Event Logs from a dedicated log-source VM.

## Architecture

| Component | Role |
|-----------|------|
| **Proxmox** (Lenovo m720q) | Hypervisor |
| **Ubuntu Server VM** (`siem-ubuntu-splunk`) | Splunk indexer + web UI |
| **Windows 10 VM** (`DESKTOP-RRL1N14` or your hostname) | Log source + Splunk Universal Forwarder |
| **Network** | Same LAN bridge (`vmbr0`), indexer reachable at Splunk VM IP |

## What was built

1. Splunk Enterprise installed on Ubuntu (web UI on port **8000**).
2. Receiving enabled on port **9997** (forwarded data from Universal Forwarder).
3. Splunk Universal Forwarder on Windows, forwarding to indexer.
4. Windows Event Logs monitored: **Security**, **System**, **Application** (via `.evtx` monitors or equivalent inputs).

## Proof (Splunk search)

Example search used to verify ingestion:

```spl
index=main sourcetype="WinEventLog:*"
| stats count by host, sourcetype
| sort -count
```

Expected: host = Windows VM name; sourcetypes `WinEventLog:Security`, `WinEventLog:System`, `WinEventLog:Application` with non-zero counts.

## Screenshot

Place your proof screenshot in **`assets/splunk-windows-events.png`** (or update the path below).

![Splunk: Windows Event Log ingestion](siem-lab/asset/splunk-windows-events.png)

## Next (Milestone 2 – optional)

- Sysmon on Windows + forward Sysmon events or dedicated sourcetype.
- At least one simple detection rule or saved search (e.g. failed logins, suspicious process).
- Short writeup in `security-writeups` repo linking to this lab.

---

*No secrets or Splunk admin credentials are stored in this repository.*
