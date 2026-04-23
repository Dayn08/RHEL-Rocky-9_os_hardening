#!/usr/bin/env python3
"""
CIS Benchmark Level 1 Hardening Checklist - Python Edition
===========================================================
Usage: sudo python3 cis_benchmark_check.py [--fix] [--json] [--html]
Options:
  --fix   Auto-remediate failed checks where possible
  --json  Save results in JSON format
  --html  Save a standalone HTML report
"""

import subprocess
import os
import sys
import json
import stat
import pwd
import grp
import argparse
import datetime
import socket
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional

# ── ANSI Colors ───────────────────────────────────────────────
class C:
    RED    = "\033[0;31m"
    GREEN  = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE   = "\033[0;34m"
    CYAN   = "\033[0;36m"
    BOLD   = "\033[1m"
    NC     = "\033[0m"

# ── Data Structures ───────────────────────────────────────────
@dataclass
class CheckResult:
    id: str
    description: str
    status: str          # PASS | FAIL | WARN | SKIP
    detail: str
    section: str = ""
    remediation: str = ""

@dataclass
class Report:
    hostname: str = socket.gethostname()
    timestamp: str = datetime.datetime.utcnow().isoformat() + "Z"
    checks: List[CheckResult] = field(default_factory=list)

    @property
    def total(self):  return len(self.checks)
    @property
    def passed(self): return sum(1 for c in self.checks if c.status == "PASS")
    @property
    def failed(self): return sum(1 for c in self.checks if c.status == "FAIL")
    @property
    def warned(self): return sum(1 for c in self.checks if c.status == "WARN")
    @property
    def skipped(self): return sum(1 for c in self.checks if c.status == "SKIP")
    @property
    def score(self):
        return int((self.passed / self.total) * 100) if self.total > 0 else 0

# ── Checker Base ──────────────────────────────────────────────
class CISChecker:
    def __init__(self, fix_mode: bool = False):
        self.fix_mode = fix_mode
        self.report = Report()
        self.current_section = ""

    def run_cmd(self, cmd: str, shell: bool = True) -> tuple[int, str, str]:
        """Run shell command, return (returncode, stdout, stderr)."""
        try:
            r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=15)
            return r.returncode, r.stdout.strip(), r.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def add(self, id_: str, desc: str, status: str, detail: str, remediation: str = "") -> CheckResult:
        cr = CheckResult(
            id=id_, description=desc, status=status,
            detail=detail, section=self.current_section,
            remediation=remediation
        )
        self.report.checks.append(cr)
        STATUS_COLOR = {
            "PASS": C.GREEN, "FAIL": C.RED,
            "WARN": C.YELLOW, "SKIP": C.CYAN
        }.get(status, C.NC)
        print(f"{C.BOLD}[{id_:^7}]{C.NC} {STATUS_COLOR}{status:<4}{C.NC}  {C.BOLD}{desc}{C.NC} — {detail}")
        return cr

    def section(self, name: str):
        self.current_section = name
        print(f"\n{C.BLUE}{C.BOLD}{'═'*52}{C.NC}")
        print(f"{C.BLUE}{C.BOLD}  {name}{C.NC}")
        print(f"{C.BLUE}{C.BOLD}{'═'*52}{C.NC}")

    def sysctl_get(self, key: str) -> Optional[str]:
        rc, out, _ = self.run_cmd(f"sysctl {key}")
        if rc == 0 and "=" in out:
            return out.split("=")[-1].strip()
        return None

    def file_perm(self, path: str) -> Optional[str]:
        try:
            return oct(stat.S_IMODE(os.stat(path).st_mode))[2:]
        except (FileNotFoundError, PermissionError):
            return None

    def pkg_installed(self, pkg: str) -> bool:
        rc, _, _ = self.run_cmd(f"dpkg -s {pkg} 2>/dev/null | grep -q 'Status: install ok installed'")
        if rc == 0:
            return True
        rc2, _, _ = self.run_cmd(f"rpm -q {pkg} 2>/dev/null")
        return rc2 == 0

    # ── Section 1: Filesystem ─────────────────────────────────
    def check_filesystem(self):
        self.section("1. Filesystem Configuration")

        # 1.1 /tmp partition
        rc, out, _ = self.run_cmd("mount | grep ' on /tmp '")
        if rc == 0:
            self.add("1.1.1", "/tmp is a separate partition", "PASS", "Separate partition found")
            for opt in ("nodev", "nosuid", "noexec"):
                st = "PASS" if opt in out else "FAIL"
                self.add(f"1.1.{2 + ['nodev','nosuid','noexec'].index(opt)}",
                         f"/tmp mounted with {opt}", st,
                         f"{opt} {'set' if st=='PASS' else 'NOT set'}",
                         f"Add {opt} to /tmp in /etc/fstab" if st == "FAIL" else "")
        else:
            self.add("1.1.1", "/tmp is a separate partition", "WARN",
                     "Not a separate partition", "Add tmpfs /tmp mount in /etc/fstab")

        # 1.2 Sticky bit
        rc, out, _ = self.run_cmd(
            "df --local -P 2>/dev/null | awk 'NR!=1 {print $6}' | "
            "xargs -I'{}' find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null"
        )
        if out.strip():
            self.add("1.2.1", "Sticky bit on world-writable dirs", "FAIL",
                     f"Dirs without sticky bit found", "Run: chmod a+t <dir>")
            if self.fix_mode:
                self.run_cmd("df --local -P | awk 'NR!=1 {print $6}' | "
                             "xargs -I'{}' find '{}' -xdev -type d -perm -0002 "
                             "2>/dev/null | xargs chmod a+t")
                print("  → Fixed: sticky bit applied")
        else:
            self.add("1.2.1", "Sticky bit on world-writable dirs", "PASS",
                     "All world-writable dirs have sticky bit")

        # 1.3 /dev/shm
        rc, shm_out, _ = self.run_cmd("mount | grep ' on /dev/shm '")
        for opt in ("nodev", "nosuid", "noexec"):
            st = "PASS" if rc == 0 and opt in shm_out else "FAIL"
            self.add("1.3.1", f"/dev/shm {opt}", st,
                     f"{opt} {'set' if st=='PASS' else 'not set'} on /dev/shm")

    # ── Section 2: Updates ────────────────────────────────────
    def check_updates(self):
        self.section("2. Software Updates")

        if self.pkg_installed("unattended-upgrades"):
            self.add("2.1.1", "Unattended upgrades installed", "PASS",
                     "Package present")
        else:
            self.add("2.1.1", "Unattended upgrades installed", "FAIL",
                     "Not installed", "apt install unattended-upgrades")
            if self.fix_mode:
                self.run_cmd("apt-get install -y unattended-upgrades")
                print("  → Fixed: unattended-upgrades installed")

    # ── Section 3: Filesystem Integrity ───────────────────────
    def check_integrity(self):
        self.section("3. Filesystem Integrity")

        rc, _, _ = self.run_cmd("command -v aide")
        if rc == 0 or self.pkg_installed("aide"):
            self.add("3.1.1", "AIDE installed", "PASS", "File integrity tool present")
        else:
            self.add("3.1.1", "AIDE installed", "FAIL", "Not installed",
                     "apt install aide && aide --init")

        rc, _, _ = self.run_cmd("crontab -l 2>/dev/null | grep -qi aide || "
                                "grep -rl aide /etc/cron* 2>/dev/null | grep -q .")
        self.add("3.2.1", "AIDE cron job", "PASS" if rc == 0 else "FAIL",
                 "Scheduled check found" if rc == 0 else "Configure AIDE cron job")

    # ── Section 4: Secure Boot ────────────────────────────────
    def check_secure_boot(self):
        self.section("4. Secure Boot Settings")

        grub_cfg = Path("/boot/grub/grub.cfg")
        if grub_cfg.exists():
            content = grub_cfg.read_text(errors="ignore")
            if "set superusers" in content or "password_pbkdf2" in content:
                self.add("4.1.1", "GRUB bootloader password", "PASS",
                         "Password configured")
            else:
                self.add("4.1.1", "GRUB bootloader password", "FAIL",
                         "No bootloader password set",
                         "Use grub-mkpasswd-pbkdf2 to set GRUB password")

            perm = self.file_perm("/boot/grub/grub.cfg")
            if perm in ("400", "600"):
                self.add("4.2.1", "GRUB config permissions", "PASS",
                         f"Permissions: {perm}")
            else:
                self.add("4.2.1", "GRUB config permissions", "FAIL",
                         f"Permissions: {perm} (expected 600)",
                         "chmod og-rwx /boot/grub/grub.cfg")
                if self.fix_mode:
                    os.chmod("/boot/grub/grub.cfg", 0o600)
                    print("  → Fixed: GRUB permissions set")
        else:
            self.add("4.1.1", "GRUB config", "SKIP", "grub.cfg not found")

    # ── Section 5: Process Hardening ──────────────────────────
    def check_process_hardening(self):
        self.section("5. Additional Process Hardening")

        checks = [
            ("kernel.randomize_va_space", "2",  "5.1.1", "ASLR enabled"),
            ("fs.suid_dumpable",          "0",  "5.2.1", "Core dumps restricted"),
            ("kernel.dmesg_restrict",     "1",  "5.3.1", "dmesg restricted"),
        ]
        for param, expected, id_, desc in checks:
            val = self.sysctl_get(param)
            if val == expected:
                self.add(id_, desc, "PASS", f"{param} = {val}")
            else:
                self.add(id_, desc, "FAIL",
                         f"Got: {val or 'N/A'}, expected: {expected}",
                         f"sysctl -w {param}={expected}")
                if self.fix_mode:
                    self.run_cmd(f"sysctl -w {param}={expected}")
                    print(f"  → Fixed: {param}={expected}")

        rc, _, _ = self.run_cmd("command -v prelink")
        if rc == 0:
            self.add("5.4.1", "Prelink disabled", "FAIL",
                     "Prelink is installed", "apt remove prelink")
            if self.fix_mode:
                self.run_cmd("apt-get remove -y prelink")
                print("  → Fixed: prelink removed")
        else:
            self.add("5.4.1", "Prelink disabled", "PASS", "Not installed")

    # ── Section 6: Network Hardening ──────────────────────────
    def check_network(self):
        self.section("6. Network Configuration Hardening")

        sysctl_checks = [
            ("net.ipv4.ip_forward",                        "0", "6.1.1"),
            ("net.ipv4.conf.all.send_redirects",           "0", "6.1.2"),
            ("net.ipv4.conf.default.send_redirects",       "0", "6.1.3"),
            ("net.ipv4.conf.all.accept_source_route",      "0", "6.2.1"),
            ("net.ipv4.conf.all.accept_redirects",         "0", "6.2.2"),
            ("net.ipv4.conf.all.secure_redirects",         "0", "6.2.3"),
            ("net.ipv4.conf.all.log_martians",             "1", "6.2.4"),
            ("net.ipv4.icmp_echo_ignore_broadcasts",       "1", "6.3.1"),
            ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "6.3.2"),
            ("net.ipv4.tcp_syncookies",                    "1", "6.3.3"),
            ("net.ipv6.conf.all.accept_ra",                "0", "6.4.1"),
            ("net.ipv6.conf.all.accept_redirects",         "0", "6.4.2"),
        ]
        for param, expected, id_ in sysctl_checks:
            val = self.sysctl_get(param)
            if val == expected:
                self.add(id_, param, "PASS", f"Value: {val}")
            else:
                self.add(id_, param, "FAIL",
                         f"Got: {val or 'N/A'}, expected: {expected}",
                         f"sysctl -w {param}={expected}")
                if self.fix_mode:
                    self.run_cmd(f"sysctl -w {param}={expected}")

    # ── Section 7: Logging ────────────────────────────────────
    def check_logging(self):
        self.section("7. Logging and Auditing")

        for svc, id_ in [("auditd", "7.1"), ("rsyslog", "7.2")]:
            if self.pkg_installed(svc):
                self.add(f"{id_}.1", f"{svc} installed", "PASS", "Package present")
                rc, _, _ = self.run_cmd(f"systemctl is-active {svc}")
                if rc == 0:
                    self.add(f"{id_}.2", f"{svc} running", "PASS", "Service active")
                else:
                    self.add(f"{id_}.2", f"{svc} running", "FAIL",
                             "Service not active", f"systemctl enable --now {svc}")
                    if self.fix_mode:
                        self.run_cmd(f"systemctl enable --now {svc}")
            else:
                self.add(f"{id_}.1", f"{svc} installed", "FAIL",
                         "Not installed", f"apt install {svc}")

        perm = self.file_perm("/var/log/syslog") or self.file_perm("/var/log/messages")
        if perm:
            int_perm = int(perm, 8)
            st = "PASS" if int_perm <= 0o640 else "FAIL"
            self.add("7.3.1", "Log file permissions ≤ 640", st,
                     f"Permissions: {perm}")
        else:
            self.add("7.3.1", "Log file permissions", "SKIP", "Log file not found")

        self.add("7.4.1", "logrotate configured", 
                 "PASS" if Path("/etc/logrotate.conf").exists() else "FAIL",
                 "/etc/logrotate.conf present" if Path("/etc/logrotate.conf").exists()
                 else "Configure logrotate")

    # ── Section 8: Access Control ─────────────────────────────
    def check_access_control(self):
        self.section("8. Access, Authentication & Authorization")

        # SSH checks
        sshd_cfg = Path("/etc/ssh/sshd_config")
        if sshd_cfg.exists():
            content = sshd_cfg.read_text(errors="ignore").lower()

            def get_ssh(key):
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == key.lower():
                        return parts[1]
                return None

            ssh_checks = [
                ("PermitRootLogin",         "no",  "8.1.1"),
                ("PermitEmptyPasswords",    "no",  "8.1.2"),
                ("Protocol",               "2",   "8.1.3"),
                ("MaxAuthTries",           "4",   "8.1.4"),
                ("IgnoreRhosts",           "yes", "8.1.5"),
                ("HostbasedAuthentication","no",  "8.1.6"),
                ("X11Forwarding",          "no",  "8.1.7"),
                ("ClientAliveCountMax",    "0",   "8.1.8"),
            ]
            for key, expected, id_ in ssh_checks:
                val = get_ssh(key)
                st = "PASS" if val == expected else "FAIL"
                self.add(id_, f"SSH: {key}", st,
                         f"Got: '{val or 'unset'}', expected: '{expected}'",
                         f"Set '{key} {expected}' in /etc/ssh/sshd_config")
        else:
            self.add("8.1.0", "SSH configuration", "SKIP",
                     "sshd_config not found")

        # Password policy
        pam_file = Path("/etc/pam.d/common-password")
        if not pam_file.exists():
            pam_file = Path("/etc/pam.d/system-auth")
        if pam_file.exists():
            pam_content = pam_file.read_text(errors="ignore")
            if "pam_pwquality" in pam_content or "pam_cracklib" in pam_content:
                self.add("8.2.1", "Password complexity module", "PASS",
                         "pam_pwquality/cracklib configured")
            else:
                self.add("8.2.1", "Password complexity module", "FAIL",
                         "Not configured", "Install libpam-pwquality")

        # /etc/login.defs
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            cfg = {}
            for line in login_defs.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) == 2:
                        cfg[parts[0]] = parts[1]

            checks = [
                ("PASS_MAX_DAYS", 365, "le", "8.3.1", "PASS_MAX_DAYS ≤ 365"),
                ("PASS_MIN_DAYS",   1, "ge", "8.3.2", "PASS_MIN_DAYS ≥ 1"),
                ("PASS_WARN_AGE",   7, "ge", "8.3.3", "PASS_WARN_AGE ≥ 7"),
            ]
            for key, threshold, op, id_, desc in checks:
                val = cfg.get(key)
                try:
                    ival = int(val)
                    passed = (ival <= threshold) if op == "le" else (ival >= threshold)
                    self.add(id_, desc, "PASS" if passed else "FAIL",
                             f"{key}={val}")
                except (TypeError, ValueError):
                    self.add(id_, desc, "FAIL", f"{key} not set in login.defs")

        # Critical file permissions
        file_checks = [
            ("/etc/passwd",  "644", "8.4.1", "/etc/passwd permissions (644)"),
            ("/etc/shadow",  "640", "8.4.2", "/etc/shadow permissions (640)"),
            ("/etc/group",   "644", "8.4.3", "/etc/group permissions (644)"),
            ("/etc/gshadow", "640", "8.4.4", "/etc/gshadow permissions (640)"),
        ]
        for filepath, expected_perm, id_, desc in file_checks:
            perm = self.file_perm(filepath)
            if perm and int(perm, 8) <= int(expected_perm, 8):
                self.add(id_, desc, "PASS", f"Permissions: {perm}")
            else:
                self.add(id_, desc, "FAIL",
                         f"Permissions: {perm or 'N/A'} (expected ≤ {expected_perm})",
                         f"chmod {expected_perm} {filepath}")
                if self.fix_mode and perm:
                    os.chmod(filepath, int(expected_perm, 8))
                    print(f"  → Fixed: {filepath} permissions")

        # Empty passwords
        rc, out, _ = self.run_cmd("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
        if not out.strip():
            self.add("8.5.1", "No accounts with empty passwords", "PASS",
                     "No empty passwords found")
        else:
            self.add("8.5.1", "No accounts with empty passwords", "FAIL",
                     f"Accounts: {out.strip()}", "Set passwords: passwd <user>")

        # UID 0 check
        rc, out, _ = self.run_cmd("awk -F: '($3 == 0) {print $1}' /etc/passwd")
        uid0_users = [u for u in out.splitlines() if u != "root"]
        if not uid0_users:
            self.add("8.6.1", "Only root has UID 0", "PASS",
                     "No non-root UID 0 accounts")
        else:
            self.add("8.6.1", "Only root has UID 0", "FAIL",
                     f"Extra UID 0 accounts: {', '.join(uid0_users)}")

    # ── Section 9: System Maintenance ─────────────────────────
    def check_system_maintenance(self):
        self.section("9. System Maintenance")

        # World-writable files
        rc, out, _ = self.run_cmd(
            "df --local -P 2>/dev/null | awk 'NR!=1 {print $6}' | "
            "xargs -I'{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | head -3"
        )
        if out.strip():
            self.add("9.1.1", "No world-writable files", "FAIL",
                     f"Found: {out[:100]}", "Remove write permission for others")
        else:
            self.add("9.1.1", "No world-writable files", "PASS",
                     "No world-writable files found")

        # Unowned files
        rc, out, _ = self.run_cmd(
            "df --local -P 2>/dev/null | awk 'NR!=1 {print $6}' | "
            "xargs -I'{}' find '{}' -xdev -nouser 2>/dev/null | wc -l"
        )
        count = int(out.strip() or "0")
        self.add("9.2.1", "No unowned files", "PASS" if count == 0 else "FAIL",
                 f"{count} unowned files found" if count > 0 else "No unowned files")

        # Ungrouped files
        rc, out, _ = self.run_cmd(
            "df --local -P 2>/dev/null | awk 'NR!=1 {print $6}' | "
            "xargs -I'{}' find '{}' -xdev -nogroup 2>/dev/null | wc -l"
        )
        count = int(out.strip() or "0")
        self.add("9.3.1", "No ungrouped files", "PASS" if count == 0 else "FAIL",
                 f"{count} ungrouped files" if count > 0 else "No ungrouped files")

        # SUID executables
        rc, out, _ = self.run_cmd(
            "df --local -P 2>/dev/null | awk 'NR!=1 {print $6}' | "
            "xargs -I'{}' find '{}' -xdev -type f -perm -4000 2>/dev/null | wc -l"
        )
        count = int(out.strip() or "0")
        self.add("9.4.1", "SUID executables audit",
                 "PASS" if count < 20 else "WARN",
                 f"{count} SUID files found{'  (review manually)' if count >= 20 else ''}")

        # crontab permissions
        for cronpath in ["/etc/crontab", "/etc/cron.d"]:
            perm = self.file_perm(cronpath)
            if perm:
                ok = int(perm, 8) <= 0o700
                self.add("9.5.1", f"{cronpath} permissions ≤ 700",
                         "PASS" if ok else "FAIL",
                         f"Permissions: {perm}",
                         f"chmod og-rwx {cronpath}")
                if not ok and self.fix_mode:
                    os.chmod(cronpath, 0o600)
                    print(f"  → Fixed: {cronpath} permissions")

    # ── Section 10: Network Services ──────────────────────────
    def check_network_services(self):
        self.section("10. Unnecessary Network Services")

        unwanted = [
            "telnet", "rsh", "rlogin", "rexec", "tftp",
            "talk", "ntalk", "finger", "chargen", "xinetd"
        ]
        for svc in unwanted:
            rc, _, _ = self.run_cmd(f"systemctl is-active {svc} 2>/dev/null")
            if rc == 0:
                self.add("10.x", f"{svc} disabled", "FAIL",
                         f"{svc} is running", f"systemctl disable --now {svc}")
                if self.fix_mode:
                    self.run_cmd(f"systemctl disable --now {svc}")
                    print(f"  → Fixed: {svc} disabled")
            else:
                rc2, _, _ = self.run_cmd(f"command -v {svc}")
                st = "WARN" if rc2 == 0 else "PASS"
                self.add("10.x", f"{svc} not running", st,
                         "Binary exists but inactive" if st == "WARN" else "Not installed")

        # Firewall check
        rc, out, _ = self.run_cmd("ufw status 2>/dev/null | head -1")
        if rc == 0 and "active" in out.lower():
            self.add("10.99", "Firewall (ufw) active", "PASS", "ufw is active")
        else:
            rc2, _, _ = self.run_cmd("firewall-cmd --state 2>/dev/null")
            if rc2 == 0:
                self.add("10.99", "Firewall (firewalld) active", "PASS", "Running")
            else:
                rc3, rules, _ = self.run_cmd(
                    "iptables -L 2>/dev/null | grep -v '^Chain\\|^target\\|^$' | wc -l"
                )
                count = int(rules.strip() or "0")
                if count > 0:
                    self.add("10.99", "Firewall (iptables)", "PASS",
                             f"{count} rules configured")
                else:
                    self.add("10.99", "Firewall active", "FAIL",
                             "No active firewall found", "Enable ufw: ufw enable")

    # ── Summary ───────────────────────────────────────────────
    def print_summary(self):
        r = self.report
        print(f"\n{C.BOLD}╔{'═'*50}╗{C.NC}")
        print(f"{C.BOLD}║{'CIS BENCHMARK LEVEL 1 — SUMMARY':^50}║{C.NC}")
        print(f"{C.BOLD}╠{'═'*50}╣{C.NC}")
        print(f"{C.BOLD}║  Host    : {r.hostname:<38}║{C.NC}")
        print(f"{C.BOLD}║  Date    : {r.timestamp[:19]:<38}║{C.NC}")
        print(f"{C.BOLD}╠{'═'*50}╣{C.NC}")
        print(f"{C.BOLD}║  Total   : {C.NC}{r.total:<38}{C.BOLD}║{C.NC}")
        print(f"{C.BOLD}║  {C.GREEN}PASS    : {r.passed:<38}{C.NC}{C.BOLD}║{C.NC}")
        print(f"{C.BOLD}║  {C.RED}FAIL    : {r.failed:<38}{C.NC}{C.BOLD}║{C.NC}")
        print(f"{C.BOLD}║  {C.YELLOW}WARN    : {r.warned:<38}{C.NC}{C.BOLD}║{C.NC}")
        print(f"{C.BOLD}║  {C.CYAN}SKIP    : {r.skipped:<38}{C.NC}{C.BOLD}║{C.NC}")
        print(f"{C.BOLD}╠{'═'*50}╣{C.NC}")

        score = r.score
        if r.failed == 0:
            grade = f"{C.GREEN}EXCELLENT — All checks passed!"
        elif score >= 80:
            grade = f"{C.YELLOW}GOOD — Minor issues to address"
        elif score >= 60:
            grade = f"{C.YELLOW}FAIR — Several issues need attention"
        else:
            grade = f"{C.RED}POOR — Critical hardening required"

        print(f"{C.BOLD}║  Score   : {score}%{C.NC}")
        print(f"{C.BOLD}║  Status  : {grade}{C.NC}")
        print(f"{C.BOLD}╚{'═'*50}╝{C.NC}")

        if r.failed > 0:
            print(f"\n{C.BOLD}{C.RED}Failed Checks:{C.NC}")
            for c in r.checks:
                if c.status == "FAIL":
                    print(f"  [{c.id}] {c.description}")
                    if c.remediation:
                        print(f"        {C.CYAN}→ {c.remediation}{C.NC}")

    def save_json(self, path: str):
        data = {
            "timestamp": self.report.timestamp,
            "hostname": self.report.hostname,
            "score": self.report.score,
            "summary": {
                "total": self.report.total, "pass": self.report.passed,
                "fail": self.report.failed, "warn": self.report.warned,
                "skip": self.report.skipped
            },
            "checks": [asdict(c) for c in self.report.checks]
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n{C.CYAN}JSON report saved: {path}{C.NC}")

    def save_html(self, path: str):
        r = self.report
        color_map = {"PASS":"#2e7d32","FAIL":"#c62828","WARN":"#e65100","SKIP":"#0277bd"}
        bg_map    = {"PASS":"#f1f8e9","FAIL":"#ffebee","WARN":"#fff3e0","SKIP":"#e3f2fd"}
        row_parts = []
        for c in r.checks:
            fg  = color_map.get(c.status, "")
            bg  = bg_map.get(c.status, "")
            rem = c.remediation if c.remediation else "\u2014"
            row_parts.append(
                "<tr style='background:{bg}'>"
                "<td>{id}</td><td>{sec}</td><td>{desc}</td>"
                "<td style='color:{fg};font-weight:bold'>{st}</td>"
                "<td>{detail}</td><td>{rem}</td></tr>".format(
                    bg=bg, fg=fg, id=c.id, sec=c.section,
                    desc=c.description, st=c.status,
                    detail=c.detail, rem=rem
                )
            )
        rows = "\n".join(row_parts)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CIS Benchmark Report</title>
<style>
  body{{font-family:sans-serif;margin:2rem;background:#f5f5f5}}
  h1{{color:#1a237e}} .summary{{display:flex;gap:1rem;margin:1rem 0}}
  .card{{background:#fff;border-radius:8px;padding:1rem 1.5rem;box-shadow:0 1px 4px rgba(0,0,0,.15);min-width:100px;text-align:center}}
  .card .num{{font-size:2rem;font-weight:bold}}
  .card .lbl{{font-size:.8rem;color:#666}}
  .pass{{color:#2e7d32}} .fail{{color:#c62828}} .warn{{color:#e65100}} .skip{{color:#0277bd}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
  th{{background:#1a237e;color:#fff;padding:.6rem .8rem;text-align:left;font-size:.85rem}}
  td{{padding:.5rem .8rem;border-bottom:1px solid #eee;font-size:.85rem}}
</style></head>
<body>
<h1>CIS Benchmark Level 1 — Hardening Report</h1>
<p><strong>Host:</strong> {r.hostname} &nbsp; <strong>Date:</strong> {r.timestamp[:19]} &nbsp; <strong>Score:</strong> {r.score}%</p>
<div class="summary">
  <div class="card"><div class="num">{r.total}</div><div class="lbl">Total</div></div>
  <div class="card"><div class="num pass">{r.passed}</div><div class="lbl">Pass</div></div>
  <div class="card"><div class="num fail">{r.failed}</div><div class="lbl">Fail</div></div>
  <div class="card"><div class="num warn">{r.warned}</div><div class="lbl">Warn</div></div>
  <div class="card"><div class="num skip">{r.skipped}</div><div class="lbl">Skip</div></div>
</div>
<table><thead><tr><th>ID</th><th>Section</th><th>Check</th><th>Status</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""
        with open(path, "w") as f:
            f.write(html)
        print(f"{C.CYAN}HTML report saved: {path}{C.NC}")

    def run_all(self):
        if os.geteuid() != 0:
            print(f"{C.RED}[ERROR] This script must be run as root (sudo).{C.NC}")
            sys.exit(1)

        print(f"\n{C.BOLD}{C.CYAN}  CIS Benchmark Level 1 Hardening Checklist — Python{C.NC}")
        print(f"{C.BOLD}{C.CYAN}  Host: {self.report.hostname} | {self.report.timestamp[:19]}{C.NC}")
        if self.fix_mode:
            print(f"{C.YELLOW}  FIX MODE ENABLED — auto-remediation active{C.NC}")

        self.check_filesystem()
        self.check_updates()
        self.check_integrity()
        self.check_secure_boot()
        self.check_process_hardening()
        self.check_network()
        self.check_logging()
        self.check_access_control()
        self.check_system_maintenance()
        self.check_network_services()
        self.print_summary()


# ── Entry Point ───────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CIS Benchmark Level 1 Hardening Checklist"
    )
    parser.add_argument("--fix",  action="store_true", help="Auto-remediate failures where safe")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument("--html", action="store_true", help="Save HTML report")
    args = parser.parse_args()

    checker = CISChecker(fix_mode=args.fix)
    checker.run_all()

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.json:
        checker.save_json(f"/tmp/cis_report_{ts}.json")
    if args.html:
        checker.save_html(f"/tmp/cis_report_{ts}.html")


if __name__ == "__main__":
    main()
