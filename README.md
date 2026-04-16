# RHEL/Rocky 9 OS Hardening

Automated CIS benchmark audit and hardening framework for **RHEL 9 / Rocky Linux 9**.

This project helps system administrators audit, remediate, and validate server hardening settings based on CIS-aligned best practices.

---

## Features

- Modular shell-based hardening checks
- Python orchestrator for execution and scoring
- Auto-remediation for supported controls
- Timestamped logging
- Dry-run support
- Selective module execution
- PASS / FAIL / SKIP summary scoring
- Safe service reload validation

---

## Project Structure

```bash
.
├── master_harden.py
├── modules/
│   ├── 01_gpg_check.sh
│   ├── 02_ssh.sh
│   ├── 03_aide.sh
│   ├── 04_remove_packages.sh
│   ├── 05_restrict_core_dumps.sh
│   ├── 06_aslr.sh
│   ├── 07_disable_legacy_sockets.sh
│   ├── 08_ntp.sh
│   ├── 09_sysctl_network.sh
│   ├── 10_cron_anacron.sh
│   ├── 11_sshd_config.sh
│   └── 12_password_policy.sh
├── logs/
└── README.md
