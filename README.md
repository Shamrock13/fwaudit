# 🔥 Flintlock

**Flintlock** is a firewall configuration auditing tool with a web UI and CLI. It detects common security misconfigurations, generates scored severity reports, compares configs across time, connects directly to live devices via SSH, and runs automated scheduled audits. Deployable in minutes via Docker Compose.

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20Flintlock-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/shamrock13)

---

## Supported Vendors

| Vendor | Config Format | Notes |
|---|---|---|
| AWS Security Groups | JSON | `aws ec2 describe-security-groups` export |
| Azure NSG | JSON | `az network nsg show` / `nsg list` export |
| Cisco ASA | Text | Running config (`show running-config`) |
| Cisco FTD | Text | LINA running config; auto-detected from ASA uploads |
| Fortinet FortiGate | Text | Running config (`show full-configuration`) |
| Palo Alto Networks | XML | Candidate or running config export |
| pfSense | XML | Full config export (`config.xml`) |

---

## Features

### Free (Open Source)

**Core audit**
- **Auto-detect vendor** — identifies vendor from file content; no manual selection required
- **Security scoring** — 0–100 score per audit: `100 − (HIGH × 10) − (MEDIUM × 3)`
- **Category badges** — findings tagged by type: Exposure, Protocol, Logging, Hygiene, Redundancy
- **Remediation guidance** — every finding includes a plain-English fix recommendation
- **Hostname extraction** — device hostname auto-populated from the config file into the Device Tag field

**Audit modes**
- **Single file audit** — upload one config, get instant results with filterable findings
- **Bulk audit** — upload multiple configs at once; each is audited independently with per-file score and expandable findings
- **Live SSH connection** — connect directly to a Cisco, Fortinet, or Palo Alto device to pull and audit its running config in real time
- **Scheduled audits** — set up recurring SSH audits (hourly, daily, or weekly) with full CRUD management; results auto-save to Audit History

**History & reporting**
- **Audit History** — save, browse, filter (vendor/date/tag), and search past audits
- **Score Trends chart** — visualize security score over time per device, with vendor and device tag filters
- **Archival comparisons** — select any two saved audits to see resolved issues, new issues, and HIGH/MEDIUM/Total deltas
- **Activity Log** — complete record of every audit, SSH attempt, diff, and scheduled run — including failures
- **PDF report export** — download or view inline a color-coded findings report with score, category labels, and remediation text
- **Device tag system** — name devices (e.g. `ASA01`, `FortiGate-HQ`) for auto-versioned history and trend tracking

**Platform**
- **Settings** — global defaults for auto-PDF, auto-archive, and default compliance framework
- **Rule change diff** — upload two configs of the same vendor to see added, removed, and unchanged rules
- Light / dark / auto theme (saved automatically)
- CLI with audit summary output
- Docker Compose deployment

**Vendor-specific checks (free)**
- Cisco (ASA & FTD): Telnet management, unrestricted ICMP, any/any permits, missing deny-all, missing logging, shadowed rules
- Fortinet: disabled policies, all-service rules, insecure services (Telnet/HTTP/FTP), unnamed policies, internet-facing policies missing UTM
- Palo Alto: any-application rules, missing security profiles, missing descriptions
- pfSense: WAN-facing any-source pass rules, missing descriptions
- AWS: open ingress to `0.0.0.0/0`, default SG with active rules, wide port ranges (>100 ports)
- Azure: inbound Any rules, overly permissive NSG rules, broad port ranges (>100 ports)

### Paid (License Required)

Compliance checks are gated behind a license key and map findings to specific control references.

| Framework | Coverage | Example Reference |
|---|---|---|
| CIS Benchmark | HIGH / MEDIUM | CIS Control 9.2, 12.4 |
| HIPAA Security Rule | HIGH / MEDIUM | 45 CFR §164.312(a)(1), §164.312(e)(1) |
| NIST SP 800-41 | HIGH / MEDIUM | NIST AC-6, SC-7, AU-2 |
| PCI-DSS | HIGH / MEDIUM | PCI Req 1.2, 1.3, 10.2 |

All four frameworks are available for: Cisco ASA, Cisco FTD, Fortinet, Palo Alto Networks, and pfSense.

> 💳 **Purchase a license at [Gumroad](https://shamrock13.gumroad.com/l/flintlock)**

---

## Installation

### Option 1 — Docker Compose (Recommended)

No Python environment setup required.

**Requirements:** Docker Desktop or OrbStack

```bash
git clone https://github.com/Shamrock13/flintlock.git
cd flintlock
docker compose up --build
```

Open **http://localhost:8080** in your browser.

Reports, audit history, activity log, schedules, and your license key are all persisted in a Docker volume across restarts. To set a custom secret, create a `.env` file in the project root:

```
FWAUDIT_SECRET=your-secret-here
```

To stop:
```bash
docker compose down
```

---

### Option 2 — Local Python

**Requirements:** Python 3.11+

```bash
git clone https://github.com/Shamrock13/flintlock.git
cd flintlock
pip install -r requirements.txt
```

**Run the web UI:**
```bash
PYTHONPATH=src python -m flask --app src/flintlock/web.py run
```
Open **http://localhost:5000**

**Run the CLI:**
```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa
```

---

## Web UI

The web interface is organized into six tabs.

### Audit
Toggle between **Single File** and **Bulk** mode using the buttons at the top of the tab.

**Single File:**
1. Enter a **Device Tag** — used for versioned history and trend tracking (auto-filled from the config hostname when possible)
2. Upload a firewall config (text, XML, or JSON)
3. Select a vendor or leave on **Auto-detect**
4. Optionally select a compliance framework (license required)
5. Check **Generate PDF Report** and/or **Save to Audit History** as needed
6. Click **Run Audit**

Results show a security score, severity counts, category-tagged findings with remediation guidance, and optional PDF links. Click summary boxes to filter findings by severity.

**Bulk:**
Upload multiple config files at once. Each file is audited independently. Results show a per-file score, severity badges, and an expandable findings list.

### Compare
Upload two configs of the same vendor to see a diff of what changed — rules added, removed, and unchanged. Vendor is auto-detected from the baseline file.

### Live Connect
Connect to a device over SSH to pull and audit its running configuration without touching a file.

- Supported vendors: **Cisco** (ASA/FTD), **Fortinet**, **Palo Alto Networks**
- Credentials are used only for the single connection and are never stored
- Successful audits are automatically saved to Audit History
- Failed connections are recorded in the Activity Log only

### Schedules
Set up recurring SSH audits on a cron-style schedule. Each schedule supports:

- **Frequency:** Hourly, Daily, or Weekly
- **Compliance framework** (license required)
- **Enable / Disable** toggle
- **Run Now** — trigger an immediate on-demand audit
- Results are auto-saved to Audit History

### History
Two sub-tabs:

**Audit History** — browse all saved audits. Filter by vendor, sort by date or issue count, search by device tag or filename. Select any two entries and click **Compare Selected** to see a full diff — resolved findings, new issues, and delta scores. The **Score Trends** chart below plots each device's security score over time.

**Activity Log** — a complete record of every file audit, SSH connection, config diff, and scheduled run — including failures. Entries can be deleted individually or cleared in bulk.

### Settings
Configure global defaults applied to every audit:
- Always generate a PDF report
- Always save to Audit History
- Default compliance framework

Individual audit options always override these defaults.

---

## CLI Usage

### Basic audit

```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa
```

### With compliance checks (license required)

```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa --compliance pci
```

### Export PDF report

```bash
PYTHONPATH=src python -m flintlock.main --file config.txt --vendor asa --report
```

### Supported vendors

```
--vendor asa        Cisco ASA
--vendor ftd        Cisco FTD (Firepower Threat Defense)
--vendor fortinet   Fortinet FortiGate
--vendor paloalto   Palo Alto Networks
--vendor pfsense    pfSense
```

### Supported compliance frameworks

```
--compliance cis     CIS Benchmark
--compliance hipaa   HIPAA Security Rule
--compliance nist    NIST SP 800-41
--compliance pci     PCI-DSS
```

### License activation

```bash
# Activate
PYTHONPATH=src python -m flintlock.main --activate YOUR-LICENSE-KEY

# Deactivate
PYTHONPATH=src python -m flintlock.main --deactivate
```

---

## Example CLI Output

```
Flintlock — Starting audit of firewall.xml (paloalto)

[HIGH] Overly permissive rule 'Allow-Any-Any': source=any destination=any
[HIGH] No explicit deny-all rule found
[MEDIUM] Permit rule 'Allow-Any-Any' missing logging
[MEDIUM] Redundant rule detected: 'Allow-Web-Duplicate'

--- PCI Compliance Checks ---
[PCI-HIGH] PCI Req 1.3: Rule 'Allow-Any-Any' - direct routes to cardholder data prohibited
[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found
[PCI-MEDIUM] PCI Req 10.2: Rule 'Allow-Any-Any' missing audit logging

--- Audit Summary ---
High Severity:         2
Medium Severity:       2
PCI Compliance High:   2
PCI Compliance Medium: 1
Total Issues:          7
Score:                 54/100
---------------------

📄 Report saved to: report.pdf
```

---

## Checks Performed

### Free Checks

| Check | Severity | Vendors |
|---|---|---|
| Any/any permit rules | HIGH | All |
| Inbound Any rules | HIGH | Azure |
| Any-application rules | HIGH | Palo Alto |
| Internet-facing policy missing UTM | HIGH | Fortinet |
| Missing deny-all rule | HIGH | Cisco, Palo Alto, pfSense |
| Open ingress to 0.0.0.0/0 | HIGH | AWS |
| WAN-facing any-source pass rule | HIGH | pfSense |
| All-service rules | MEDIUM | Fortinet |
| Default SG with active rules | MEDIUM | AWS |
| Disabled policies | MEDIUM | Fortinet |
| Insecure services (Telnet/HTTP/FTP) | MEDIUM | Fortinet |
| Overly permissive NSG rules | MEDIUM | Azure |
| Permit rules missing logging | MEDIUM | Cisco, Palo Alto |
| Redundant/shadowed rules | MEDIUM | All |
| Rules missing description | MEDIUM | Palo Alto, pfSense |
| Rules missing security profile | MEDIUM | Palo Alto |
| Telnet management enabled | MEDIUM | Cisco |
| Unnamed policies | MEDIUM | Fortinet |
| Unrestricted ICMP permit | MEDIUM | Cisco |
| Wide port range (>100 ports) | MEDIUM | AWS, Azure |

### Paid Compliance Checks

| Framework | Severity | Vendors |
|---|---|---|
| CIS Benchmark | HIGH / MEDIUM | Cisco, Fortinet, Palo Alto, pfSense |
| HIPAA Security Rule (45 CFR §164) | HIGH / MEDIUM | Cisco, Fortinet, Palo Alto, pfSense |
| NIST SP 800-41 | HIGH / MEDIUM | Cisco, Fortinet, Palo Alto, pfSense |
| PCI-DSS | HIGH / MEDIUM | Cisco, Fortinet, Palo Alto, pfSense |

---

## Roadmap

- [x] Activity Log (usage monitoring)
- [x] Archival reviews (compare historical audits)
- [x] Auto vendor detection
- [x] AWS Security Group support
- [x] Azure NSG support
- [x] Bulk multi-device audit
- [x] Category badges and remediation guidance
- [x] Cisco FTD (Firepower Threat Defense) support
- [x] Clickable severity filters
- [x] Device tag system with auto-versioning
- [x] Docker Compose deployment
- [x] Fortinet v2 checks
- [x] Hostname auto-extraction from config files
- [x] HIPAA Security Rule compliance framework
- [x] Light / dark / auto theme
- [x] Live SSH connection mode
- [x] PDF report (score box, categories, remediation, inline view)
- [x] Rule change diff (compare two configs)
- [x] Scheduled automated SSH audits (APScheduler)
- [x] Score Trends chart with device tag and vendor filters
- [x] Security scoring (0–100 per audit)
- [x] Settings tab (global defaults)
- [x] Web UI with file upload and inline results
- [ ] Email / webhook notifications for scheduled audit findings
- [ ] Multi-factor SSH authentication (key-based)
- [ ] REST API for CI/CD pipeline integration

---

## Support the Project

Flintlock is free and open source. If it's saved you time or caught something in your configs, consider buying me a coffee — it goes directly toward keeping this maintained and adding new features.

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white&style=for-the-badge)](https://github.com/sponsors/Shamrock13)
[![Ko-fi](https://img.shields.io/badge/Buy%20me%20a%20coffee-Ko--fi-FF5E5B?logo=ko-fi&logoColor=white&style=for-the-badge)](https://ko-fi.com/shamrock13)

---

## License

The core tool is open source under the MIT License. The compliance module requires a paid license key.

---

## Author

Built by a network security engineer for network security engineers.
