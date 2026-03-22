# Flintlock — Project Plan

Internal working document. Not the public roadmap (see README.md).

---

## Active: README Roadmap Items

These map 1-to-1 with the `[ ]` items in README.md and will be checked off there when done.

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | API key authentication with session management | **Done** | Web UI login + API key for CLI/programmatic access |
| 2 | Fernet encryption for stored credentials | **Next** | SSH passwords, SMTP password in schedule_store |
| 3 | CSRF protection (Flask-WTF) | Pending | All state-changing POST routes |
| 4 | Multi-factor SSH authentication (key-based) | Pending | PEM/passphrase support in ssh_connector.py |
| 5 | REST API for CI/CD pipeline integration | Pending | JSON API wrapping existing audit_engine |

---

## Engineering / Internal Work

These are **not** public roadmap items and should not appear in README.md.

### Testing & CI
- [ ] **Scheduled CI (GitHub Actions)** — on PR: ruff + mypy + pytest; on merge/main: full suite + secret scan; nightly: pip-audit
- [ ] **pip-audit nightly job** — automate dependency CVE scanning; alert on new critical/high vulns
- [ ] **Integration tests** — Docker Compose test environment with mock SSH server (paramiko stub or sshesame); test full audit flow end-to-end
- [ ] **APScheduler tests** — use `freezegun` to test scheduled job firing, cron intervals, and missed-run behavior without wall-clock waiting
- [ ] **Compliance test expansion** — `test_soc2_stig.py` only covers SOC2/STIG; need CIS, NIST, PCI-DSS, HIPAA checks in `compliance.py`
- [ ] **Address pytest warnings** — 3 test functions in `test_rule_quality.py` return values instead of asserting (PytestReturnNotNoneWarning)

### Code Quality
- [ ] **main.py refactor** — summary block duplicated 4× (one per vendor); doesn't use `audit_engine.run_vendor_audit`; vendors added to `audit_engine` but not wired in CLI
- [ ] **web.py decomposition** — ~1,600 lines; split into blueprints (audit, ssh, schedule, history, settings, export)
- [ ] **mypy strictness** — currently `--no-strict-optional`; tighten incrementally as annotations are added
- [ ] **Python 3.8 compat** — `pyproject.toml` says `>=3.8` but code uses `list[dict]` annotations (3.9+); either drop 3.8 support or use `from __future__ import annotations`

### Security
- [ ] **Rate limiting** — Flask-Limiter on audit upload and SSH endpoints; prevent abuse of compute-heavy routes
- [ ] **Content Security Policy (CSP) header** — currently missing from HTTP security headers set in web.py
- [ ] **Input size limits** — cap uploaded config file size server-side (not just client-side); prevent memory exhaustion on huge uploads
- [ ] **SSRF review** — webhook allowlist covers Slack/Teams/Discord; verify no other outbound HTTP calls are user-influenced

### Infrastructure
- [ ] **Docker image hardening** — run as non-root user in Dockerfile; pin base image digest
- [ ] **Health endpoint** — `GET /health` returning scheduler status, last audit time, and uptime; needed for container orchestration
- [ ] **Structured logging** — replace `print()` calls in vendor parsers with Python `logging` module; enables log-level control and SIEM routing

---

## Decisions Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-03-22 | All new features developed in `claude/` branches before merge to main | Keeps main stable; reviewed before merge |
| 2026-03-22 | Test files run as plain Python scripts (no pytest dependency at runtime) | Zero extra deps for contributors; pytest still works for CI |
| 2026-03-22 | defusedxml required everywhere XML is parsed | XXE protection; enforced by xml.etree safety check in Stop hook |
| 2026-03-22 | Pre-merge validation runs 6 checks: ruff, mypy, xml-safety, dep-sync, CLI contracts, pytest | Catches linting, type, security, and functional regressions before push |
