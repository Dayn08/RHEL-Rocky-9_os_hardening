#!/usr/bin/env bash
# =============================================================================
# MODULE  : 02_ssh.sh
# TITLE   : SSH Server Hardening
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 5.2 (SSH Server Configuration)
#
# CHECKS  :
#   1.  SSH package installed and sshd service enabled
#   2.  Protocol version (SSHv2 only)
#   3.  PermitRootLogin disabled
#   4.  PasswordAuthentication configured
#   5.  PermitEmptyPasswords disabled
#   6.  X11Forwarding disabled
#   7.  MaxAuthTries <= 4
#   8.  IgnoreRhosts enabled
#   9.  HostbasedAuthentication disabled
#   10. LoginGraceTime <= 60
#   11. ClientAliveInterval and ClientAliveCountMax set
#   12. AllowTcpForwarding disabled
#   13. Banner configured
#   14. Ciphers restricted to approved list
#   15. MACs restricted to approved list
#
# EXIT CODES:
#   0 — All checks passed (or remediated successfully)
#   1 — One or more checks failed
#   2 — Skipped (sshd not present / unsupported OS)
#
# USAGE   : sudo bash 02_ssh.sh
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${RESET}  $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET}  $*"; }
info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
hdr()   { echo -e "\n${BOLD}── $* ──${RESET}"; }

OVERALL=0
mark_fail() { OVERALL=1; }

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"

# ── Helper: get effective sshd_config value (main + drop-ins) ─────────────────
sshd_get() {
    # Returns the effective value for a keyword (case-insensitive, last-wins).
    local keyword="${1}"
    local value=""
    # Main config
    value=$(grep -iE "^${keyword}[[:space:]]" "${SSHD_CONFIG}" 2>/dev/null \
            | tail -1 | awk '{print $2}' || true)
    # Drop-in directory (if present)
    if [[ -d "${SSHD_CONFIG_DIR}" ]]; then
        local dropin
        dropin=$(grep -rihE "^${keyword}[[:space:]]" "${SSHD_CONFIG_DIR}"/ 2>/dev/null \
                 | tail -1 | awk '{print $2}' || true)
        [[ -n "${dropin}" ]] && value="${dropin}"
    fi
    echo "${value}"
}

# ── Helper: set or update a value in sshd_config ─────────────────────────────
sshd_set() {
    local keyword="${1}"
    local desired="${2}"

    # Backup on first write of this run
    if [[ ! -f "${SSHD_CONFIG}.bak" ]]; then
        cp "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
        info "Backup created : ${SSHD_CONFIG}.bak.*"
    fi

    if grep -iqE "^#?[[:space:]]*${keyword}[[:space:]]" "${SSHD_CONFIG}"; then
        # Uncomment and replace
        sed -i "s/^#\?[[:space:]]*${keyword}[[:space:]].*/$(echo "${keyword} ${desired}" | sed 's/[\/&]/\\&/g')/" \
            "${SSHD_CONFIG}"
    else
        echo "${keyword} ${desired}" >> "${SSHD_CONFIG}"
    fi
}

# ── OS Detection ─────────────────────────────────────────────────────────────
hdr "OS Detection"

if [[ ! -f /etc/os-release ]]; then
    warn "Cannot detect OS. Skipping module."
    exit 2
fi

source /etc/os-release
MAJOR_VER="${VERSION_ID%%.*}"

if [[ "${ID}" != "rhel" && "${ID}" != "rocky" ]] || [[ "${MAJOR_VER}" != "9" ]]; then
    warn "Unsupported OS: ${ID} ${VERSION_ID}. This module targets RHEL/Rocky Linux 9."
    exit 2
fi

info "Detected OS : ${PRETTY_NAME}"

# =============================================================================
# CHECK 1 — OpenSSH installed and service running
# =============================================================================
hdr "Check 1 — OpenSSH Server Installed & Enabled"

if ! rpm -q openssh-server &>/dev/null; then
    fail "openssh-server package is NOT installed."
    info "Remediation: dnf install -y openssh-server"
    mark_fail
else
    pass "openssh-server package is installed."
fi

if ! systemctl is-enabled sshd &>/dev/null; then
    warn "sshd service is not enabled. Enabling now..."
    systemctl enable sshd &>/dev/null && pass "sshd enabled." || { fail "Could not enable sshd."; mark_fail; }
else
    pass "sshd service is enabled."
fi

if ! systemctl is-active sshd &>/dev/null; then
    warn "sshd is not currently active (it may be intentionally stopped pre-provisioning)."
else
    pass "sshd service is active."
fi

# =============================================================================
# CHECK 2 — Protocol (SSHv2 only — implied in OpenSSH 7+ but still best practice)
# =============================================================================
hdr "Check 2 — SSH Protocol Version"
info "Audit: grep -i '^Protocol' ${SSHD_CONFIG}"

PROTO_VAL=$(sshd_get "Protocol")

if [[ -z "${PROTO_VAL}" ]]; then
    info "Protocol keyword not set (OpenSSH 7+ defaults to 2 only — acceptable)."
    pass "SSHv2 enforced by default in this version of OpenSSH."
elif [[ "${PROTO_VAL}" == "2" ]]; then
    pass "Protocol is explicitly set to 2."
else
    fail "Protocol is set to '${PROTO_VAL}' — must be 2."
    info "Remediation: Setting Protocol 2 ..."
    sshd_set "Protocol" "2"
    pass "Protocol set to 2."
fi

# =============================================================================
# CHECK 3 — PermitRootLogin
# =============================================================================
hdr "Check 3 — PermitRootLogin Disabled"
info "Audit: sshd -T | grep -i permitrootlogin"

PRL=$(sshd_get "PermitRootLogin")
PRL_LOWER="${PRL,,}"

if [[ "${PRL_LOWER}" == "no" || "${PRL_LOWER}" == "prohibit-password" ]]; then
    pass "PermitRootLogin is '${PRL}' — root cannot log in with password."
else
    fail "PermitRootLogin is '${PRL:-not set (defaults to prohibit-password)}' — should be 'no'."
    info "Remediation: Setting PermitRootLogin no ..."
    sshd_set "PermitRootLogin" "no"
    pass "PermitRootLogin set to no."
fi

# =============================================================================
# CHECK 4 — PasswordAuthentication
# =============================================================================
hdr "Check 4 — PasswordAuthentication"
info "Audit: grep -i '^PasswordAuthentication' ${SSHD_CONFIG}"

PA=$(sshd_get "PasswordAuthentication")

if [[ "${PA,,}" == "no" ]]; then
    pass "PasswordAuthentication is no (key-based auth only)."
elif [[ -z "${PA}" || "${PA,,}" == "yes" ]]; then
    warn "PasswordAuthentication is '${PA:-yes (default)}' — consider disabling once keys are deployed."
    info "Skipping auto-remediation (may lock you out if keys are not configured)."
else
    warn "PasswordAuthentication has unexpected value: '${PA}'"
fi

# =============================================================================
# CHECK 5 — PermitEmptyPasswords
# =============================================================================
hdr "Check 5 — PermitEmptyPasswords Disabled"
info "Audit: grep -i '^PermitEmptyPasswords' ${SSHD_CONFIG}"

PEP=$(sshd_get "PermitEmptyPasswords")

if [[ -z "${PEP}" || "${PEP,,}" == "no" ]]; then
    pass "PermitEmptyPasswords is 'no' (default or explicit)."
else
    fail "PermitEmptyPasswords is '${PEP}' — must be 'no'."
    info "Remediation: Setting PermitEmptyPasswords no ..."
    sshd_set "PermitEmptyPasswords" "no"
    pass "PermitEmptyPasswords set to no."
fi

# =============================================================================
# CHECK 6 — X11Forwarding Disabled
# =============================================================================
hdr "Check 6 — X11Forwarding Disabled"
info "Audit: grep -i '^X11Forwarding' ${SSHD_CONFIG}"

X11=$(sshd_get "X11Forwarding")

if [[ -z "${X11}" || "${X11,,}" == "no" ]]; then
    pass "X11Forwarding is 'no'."
else
    fail "X11Forwarding is '${X11}' — must be 'no'."
    info "Remediation: Setting X11Forwarding no ..."
    sshd_set "X11Forwarding" "no"
    pass "X11Forwarding set to no."
fi

# =============================================================================
# CHECK 7 — MaxAuthTries <= 4
# =============================================================================
hdr "Check 7 — MaxAuthTries <= 4"
info "Audit: grep -i '^MaxAuthTries' ${SSHD_CONFIG}"

MAT=$(sshd_get "MaxAuthTries")
MAT="${MAT:-6}"   # OpenSSH default is 6

if [[ "${MAT}" -le 4 ]] 2>/dev/null; then
    pass "MaxAuthTries is ${MAT}."
else
    fail "MaxAuthTries is ${MAT} — must be 4 or less."
    info "Remediation: Setting MaxAuthTries 4 ..."
    sshd_set "MaxAuthTries" "4"
    pass "MaxAuthTries set to 4."
fi

# =============================================================================
# CHECK 8 — IgnoreRhosts Enabled
# =============================================================================
hdr "Check 8 — IgnoreRhosts Enabled"
info "Audit: grep -i '^IgnoreRhosts' ${SSHD_CONFIG}"

IR=$(sshd_get "IgnoreRhosts")

if [[ -z "${IR}" || "${IR,,}" == "yes" ]]; then
    pass "IgnoreRhosts is 'yes' (default or explicit)."
else
    fail "IgnoreRhosts is '${IR}' — must be 'yes'."
    info "Remediation: Setting IgnoreRhosts yes ..."
    sshd_set "IgnoreRhosts" "yes"
    pass "IgnoreRhosts set to yes."
fi

# =============================================================================
# CHECK 9 — HostbasedAuthentication Disabled
# =============================================================================
hdr "Check 9 — HostbasedAuthentication Disabled"
info "Audit: grep -i '^HostbasedAuthentication' ${SSHD_CONFIG}"

HBA=$(sshd_get "HostbasedAuthentication")

if [[ -z "${HBA}" || "${HBA,,}" == "no" ]]; then
    pass "HostbasedAuthentication is 'no'."
else
    fail "HostbasedAuthentication is '${HBA}' — must be 'no'."
    info "Remediation: Setting HostbasedAuthentication no ..."
    sshd_set "HostbasedAuthentication" "no"
    pass "HostbasedAuthentication set to no."
fi

# =============================================================================
# CHECK 10 — LoginGraceTime <= 60
# =============================================================================
hdr "Check 10 — LoginGraceTime <= 60 seconds"
info "Audit: grep -i '^LoginGraceTime' ${SSHD_CONFIG}"

LGT=$(sshd_get "LoginGraceTime")
LGT="${LGT:-120}"  # OpenSSH default is 120

# Strip trailing 's' if present
LGT_INT="${LGT%s}"

if [[ "${LGT_INT}" -le 60 ]] 2>/dev/null; then
    pass "LoginGraceTime is ${LGT}."
else
    fail "LoginGraceTime is ${LGT} — must be 60 or less."
    info "Remediation: Setting LoginGraceTime 60 ..."
    sshd_set "LoginGraceTime" "60"
    pass "LoginGraceTime set to 60."
fi

# =============================================================================
# CHECK 11 — ClientAlive settings (idle timeout)
# =============================================================================
hdr "Check 11 — Client Idle Timeout (ClientAlive)"
info "Audit: grep -i 'ClientAlive' ${SSHD_CONFIG}"

CAI=$(sshd_get "ClientAliveInterval")
CAC=$(sshd_get "ClientAliveCountMax")
CAI="${CAI:-0}"
CAC="${CAC:-3}"

TIMEOUT_ISSUE=0

if [[ "${CAI}" -gt 0 && "${CAI}" -le 300 ]] 2>/dev/null; then
    pass "ClientAliveInterval is ${CAI}s."
else
    fail "ClientAliveInterval is '${CAI}' — recommend setting to 300 (5 min)."
    info "Remediation: Setting ClientAliveInterval 300 ..."
    sshd_set "ClientAliveInterval" "300"
    pass "ClientAliveInterval set to 300."
    TIMEOUT_ISSUE=1
fi

if [[ "${CAC}" -le 3 ]] 2>/dev/null; then
    pass "ClientAliveCountMax is ${CAC}."
else
    fail "ClientAliveCountMax is '${CAC}' — recommend 3 or less."
    info "Remediation: Setting ClientAliveCountMax 3 ..."
    sshd_set "ClientAliveCountMax" "3"
    pass "ClientAliveCountMax set to 3."
    TIMEOUT_ISSUE=1
fi

# =============================================================================
# CHECK 12 — AllowTcpForwarding Disabled
# =============================================================================
hdr "Check 12 — AllowTcpForwarding Disabled"
info "Audit: grep -i '^AllowTcpForwarding' ${SSHD_CONFIG}"

ATF=$(sshd_get "AllowTcpForwarding")

if [[ -z "${ATF}" || "${ATF,,}" == "no" ]]; then
    pass "AllowTcpForwarding is 'no'."
else
    fail "AllowTcpForwarding is '${ATF}' — should be 'no' unless tunnelling is required."
    info "Remediation: Setting AllowTcpForwarding no ..."
    sshd_set "AllowTcpForwarding" "no"
    pass "AllowTcpForwarding set to no."
fi

# =============================================================================
# CHECK 13 — Banner Configured
# =============================================================================
hdr "Check 13 — Warning Banner Configured"
info "Audit: grep -i '^Banner' ${SSHD_CONFIG}"

BANNER_FILE="/etc/issue.net"
BNR=$(sshd_get "Banner")

if [[ "${BNR}" == "${BANNER_FILE}" && -s "${BANNER_FILE}" ]]; then
    pass "Banner is set to ${BANNER_FILE} and file is non-empty."
else
    fail "Banner is '${BNR:-not set}' or ${BANNER_FILE} is empty."
    info "Remediation: Writing default banner to ${BANNER_FILE} ..."

    cat > "${BANNER_FILE}" << 'BANNER'
*******************************************************************************
                            AUTHORISED ACCESS ONLY
This system is for authorised users only. All activity may be monitored and
reported. Unauthorised access is strictly prohibited and may be subject to
civil and/or criminal penalties.
*******************************************************************************
BANNER

    sshd_set "Banner" "${BANNER_FILE}"
    pass "Banner file created and Banner set to ${BANNER_FILE}."
fi

# =============================================================================
# CHECK 14 — Ciphers (approved only)
# =============================================================================
hdr "Check 14 — Approved Ciphers"
info "Audit: grep -i '^Ciphers' ${SSHD_CONFIG}"

APPROVED_CIPHERS="aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"

CURR_CIPHERS=$(sshd_get "Ciphers")

if [[ -z "${CURR_CIPHERS}" ]]; then
    warn "Ciphers not explicitly set — applying approved list as best practice."
    sshd_set "Ciphers" "${APPROVED_CIPHERS}"
    pass "Ciphers set to approved list."
else
    # Check for known weak ciphers
    WEAK=0
    for weak_cipher in arcfour blowfish cast128 3des; do
        if echo "${CURR_CIPHERS}" | grep -qi "${weak_cipher}"; then
            fail "Weak cipher found: ${weak_cipher}"
            WEAK=1
            mark_fail
        fi
    done
    if [[ "${WEAK}" -eq 0 ]]; then
        pass "No known weak ciphers detected in current Ciphers line."
    else
        info "Remediation: Overwriting Ciphers with approved list ..."
        sshd_set "Ciphers" "${APPROVED_CIPHERS}"
        pass "Ciphers updated to approved list."
    fi
fi

# =============================================================================
# CHECK 15 — MACs (approved only)
# =============================================================================
hdr "Check 15 — Approved MACs"
info "Audit: grep -i '^MACs' ${SSHD_CONFIG}"

APPROVED_MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"

CURR_MACS=$(sshd_get "MACs")

if [[ -z "${CURR_MACS}" ]]; then
    warn "MACs not explicitly set — applying approved list as best practice."
    sshd_set "MACs" "${APPROVED_MACS}"
    pass "MACs set to approved list."
else
    WEAK=0
    for weak_mac in md5 sha1 umac-64; do
        if echo "${CURR_MACS}" | grep -qi "${weak_mac}"; then
            fail "Weak MAC found: ${weak_mac}"
            WEAK=1
            mark_fail
        fi
    done
    if [[ "${WEAK}" -eq 0 ]]; then
        pass "No known weak MACs detected."
    else
        info "Remediation: Overwriting MACs with approved list ..."
        sshd_set "MACs" "${APPROVED_MACS}"
        pass "MACs updated to approved list."
    fi
fi

# =============================================================================
# Reload sshd to apply changes (if running)
# =============================================================================
hdr "Applying Configuration"

if systemctl is-active sshd &>/dev/null; then
    # Validate config before reloading
    if sshd -t 2>/dev/null; then
        systemctl reload sshd && pass "sshd configuration reloaded successfully." \
            || warn "sshd reload returned non-zero — check journalctl -u sshd"
    else
        fail "sshd -t config test FAILED — reload aborted to prevent lockout."
        warn "Review ${SSHD_CONFIG} and fix errors before reloading."
        mark_fail
    fi
else
    info "sshd is not currently running — skipping reload (will apply on next start)."
fi

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 02_ssh — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 02_ssh — ONE OR MORE CHECKS FAILED"
    exit 1
fi
