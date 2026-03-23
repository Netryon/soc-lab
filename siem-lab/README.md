# SOC Lab

Homelab for security operations practice: virtualization, SIEM, log forwarding, and (later) detection experiments.

## How this repo is organized

Everything lives under the **repo root** (same level as this `README.md`). Each **major lab** gets its **own folder** — they are **siblings**, not nested inside each other.

```text
soc-lab/                    ← this GitHub repo (root)
├── README.md               ← you are here
├── siem-lab/               ← ONLY the Splunk / UF / Windows logs lab
│   ├── siem-lab-plan.md
│   ├── siem-lab-milestone1.md
│   └── assets/
├── wireshark-lab/          ← example: create when you start that lab (not inside siem-lab)
└── …                       ← other top-level folders later, same idea
```

- **`siem-lab/`** = one project: your SIEM stack and related notes only.  
- **Wireshark, AD, etc.** = **separate folders next to** `siem-lab/`, not inside it. The table below is a **roadmap** of future **top-level** folders, not subfolders of `siem-lab/`.

| Folder (at repo root) | What it is |
|----------------------|------------|
| **[`siem-lab/`](siem-lab/)** | Splunk, Universal Forwarder, Windows logs, milestones |
| *(later)* `wireshark-lab/` | Packet capture / analysis (when you add it) |
| *(later)* `active-directory-lab/` | AD / identity lab (when you add it) |

## Related repos

- TryHackMe / investigation writeups: separate repo **`security-writeups`** (link it from your GitHub profile or paste full URL here).
- ChronoVault: link your public repo if you want it listed here.
