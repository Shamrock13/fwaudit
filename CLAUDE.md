# Flintlock — Claude Code Guide

Flintlock is a firewall configuration auditing tool with a CLI and Flask web UI. It parses configs from 11 firewall vendors, scores them, and checks compliance against frameworks like SOC2, DISA STIG, PCI-DSS, HIPAA, CIS, and NIST SP 800-41.

## Project Structure

```
src/flintlock/          # Main package
  main.py               # CLI entry point (typer)
  web.py                # Flask web UI
  audit_engine.py       # Core scoring and findings logic
  compliance.py         # All compliance framework checks (paid feature)
  reporter.py           # PDF report generation (fpdf2)
  export.py             # JSON / CSV / SARIF export
  diff.py               # Config diff / comparison
  rule_quality.py       # Shadow and duplicate rule detection
  notify.py             # Slack / Teams / Email alerts
  syslog_handler.py     # Syslog forwarding
  ssh_connector.py      # Paramiko SSH connections
  scheduler_runner.py   # APScheduler recurring audits
  schedule_store.py     # Persists scheduled audit config
  activity_log.py       # Audit history
  archive.py            # Historical audit storage
  settings.py           # User settings management
  license.py            # License key validation (compliance gate)
  # Vendor parsers:
  iptables.py           # iptables-save and nftables
  juniper.py            # Juniper SRX (set-style and hierarchical)
  paloalto.py           # Palo Alto (XML)
  fortinet.py           # Fortinet FortiGate
  ftd.py                # Cisco FTD (Firepower)
  pfsense.py            # pfSense (XML)
  aws.py                # AWS Security Groups (JSON)
  azure.py              # Azure NSG (JSON)
  gcp.py                # GCP VPC Firewall (JSON)
tests/                  # Test suite — run as plain Python scripts
```

## Running Tests

Tests use the standard library `unittest` and are run directly (no pytest required):

```bash
# Run a single test file
python3 tests/test_iptables.py
python3 tests/test_juniper.py
python3 tests/test_gcp.py
python3 tests/test_export.py
python3 tests/test_notify.py
python3 tests/test_rule_quality.py
python3 tests/test_soc2_stig.py

# Run all tests at once (if pytest is installed)
python -m pytest tests/ -v
```

Each test file inserts `src/` into `sys.path` at the top — no install required.

## Test Fixtures

Vendor config fixtures live in `tests/`:
- `test_asa.txt` — Cisco ASA ACL config
- `test_forti.txt` — Fortinet FortiGate policy config
- `test_pa.xml` — Palo Alto XML config
- `test_pfsense.xml` — pfSense XML config

## Test Coverage Gaps

The following modules have fixtures or implementations but **no test file yet**:

| Module | Fixture | Missing Test |
|---|---|---|
| `fortinet.py` | `test_forti.txt` | `test_fortinet.py` |
| `paloalto.py` | `test_pa.xml` | `test_paloalto.py` |
| `pfsense.py` | `test_pfsense.xml` | `test_pfsense.py` |
| `ftd.py` | — | `test_ftd.py` |
| `aws.py` | — | `test_aws.py` |
| `azure.py` | — | `test_azure.py` |
| `audit_engine.py` | — | `test_audit_engine.py` |
| `diff.py` | — | `test_diff.py` |
| `compliance.py` | — | Expand `test_soc2_stig.py` for CIS/NIST/PCI/HIPAA |

## Roadmap (Pending Items)

- [ ] API key authentication with session management
- [ ] Fernet encryption for stored credentials
- [ ] CSRF protection (Flask-WTF)
- [ ] Multi-factor SSH authentication (key-based)
- [ ] REST API for CI/CD pipeline integration

## Architecture Notes

- **Compliance features are gated** by a license key checked in `license.py`. The `keygen.py` utility (gitignored) generates keys via SHA256 hash.
- **Vendor parsers** follow a consistent pattern: `parse_<vendor>()` → returns a list of rule dicts, then `audit_<vendor>()` → calls individual `check_*()` functions and returns findings.
- **Findings** are dicts with keys: `id`, `title`, `severity` (`critical`/`high`/`medium`/`low`/`info`), `description`, `remediation`, `category`.
- **`audit_engine.py`** computes the 0–100 security score from findings and is vendor-agnostic.
- **`web.py`** is large (~1,600 lines). Flask routes handle file upload, SSH, scheduling, diff, export, and settings.
- **XML parsing** always uses `defusedxml` (never `xml.etree`) for XXE protection.

## Code Style

- Python 3.8+ compatible
- Linting: `ruff` (see commit history for fixes)
- No type annotations required, but keep existing ones consistent
- Avoid `xml.etree` — always use `defusedxml.ElementTree`

## Installation (Development)

```bash
pip install -e .
# or
pip install -r requirements.txt
```

**Note:** `requirements.txt` is missing `defusedxml>=0.7` — use `pyproject.toml` as the source of truth for dependencies.
