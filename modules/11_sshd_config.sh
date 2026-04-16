#!/usr/bin/env bash
# =============================================================================
# MODULE  : 11_sshd_config.sh
# TITLE   : SSH Server Configuration Hardening
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 5.2 (SSH Server Configuration)
#
# BACKGROUND:
#   The SSH daemon is the primary remote administration interface on Linux
#   servers. Misconfigured SSH settings are one of the most common vectors
#   for unauthorised access, lateral movement, and privilege escalation.
#   Every setting in this module directly addresses a specific attack class.
#
# CHECKS & CIS AUDIT COMMANDS:
#   1.  Protocol 2
#       grep "^Protocol" /etc/ssh/sshd_config
#
#   2.  LogLevel INFO
#       grep "^LogLevel" /etc/ssh/sshd_config
#
#   3.  /etc/ssh/sshd_config ownership and permissions (root:root 600)
#       chown root:root / chmod 600 /etc/ssh/sshd_config
#       NOTE: CIS shows chmod 644 however the security best practice and
#             OpenSSH documentation recommend 600 (no world-read).
#             This module uses 600 and documents the deviation.
#
#   4.  X11Forwarding no
#       grep "^X11Forwarding" /etc/ssh/sshd_config
#
#   5.  MaxAuthTries 4
#       grep "^MaxAuthTries" /etc/ssh/sshd_config
#
#   6.  IgnoreRhosts yes
#       grep "^IgnoreRhosts" /etc/ssh/sshd_config
#
#   7.  HostbasedAuthentication no
#       grep "^HostbasedAuthentication" /etc/ssh/sshd_config
#
#   8.  PermitEmptyPasswords no
#       grep "^PermitEmptyPasswords" /etc/ssh/sshd_config
#
#   9.  PermitUserEnvironment no
#       grep "PermitUserEnvironment" /etc/ssh/sshd_config
#
#   10. Ciphers aes128-ctr,aes192-ctr,aes256-ctr
#       grep "Ciphers" /etc/ssh/sshd_config
#
#   11. ClientAliveInterval 900
#       grep "^ClientAliveInterval" /etc/ssh/sshd_config
#
#   12. Banner /etc/issue.net
#       grep "^Banner" /etc/ssh/sshd_config
#
# BEHAVIOUR:
#   - Runs each grep audit command exactly as written in CIS
#   - Auto-remediates non-compliant settings using sed (in-place edit)
#   - Creates a timestamped backup of sshd_config before ANY modification
#   - Validates config syntax with sshd -t before reloading
#   - Only reloads sshd if changes were actually made
#   - Creates /etc/issue.net with a legal warning banner if missing
#
# EXIT CODES:
#   0 — All checks passed (or remediated successfully)
#   1 — One or more checks failed
#   2 — Skipped (unsupported OS / sshd not installed)
#
# USAGE   : sudo bash 11_sshd_config.sh
# =============================================================================

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

pass()  { echo -e "${GREEN}[PASS]${RESET}  $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET}  $*"; }
info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
hdr()   { echo -e "\n${BOLD}── $* ──${RESET}"; }
detail(){ echo -e "        ${DIM}$*${RESET}"; }

OVERALL=0
mark_fail()  { OVERALL=1; }

SSHD_CONFIG="/etc/ssh/sshd_config"
ISSUE_NET="/etc/issue.net"
CHANGES_MADE=0          # track if sshd_config was modified this run
BACKUP_DONE=0           # ensure we only backup once per run

# ── Result tracking ────────────────────────────────────────────────────────────
declare -A CHECK_RESULT  # label -> "PASS" | "REMEDIATED" | "FAILED"

# ── OS Detection ──────────────────────────────────────────────────────────────
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

# ── Verify sshd is installed ──────────────────────────────────────────────────
if ! rpm -q openssh-server &>/dev/null; then
    fail "openssh-server package is not installed — cannot configure sshd."
    info "Install with: dnf install -y openssh-server"
    exit 2
fi

if [[ ! -f "${SSHD_CONFIG}" ]]; then
    fail "${SSHD_CONFIG} not found even though openssh-server is installed."
    info "Try: dnf reinstall openssh-server"
    exit 1
fi

info "openssh-server installed ✓"
info "sshd_config path : ${SSHD_CONFIG}"

# =============================================================================
# Core helpers
# =============================================================================

# Backup sshd_config exactly once per run
backup_sshd_config() {
    if [[ "${BACKUP_DONE}" -eq 0 ]]; then
        local bak="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
        cp "${SSHD_CONFIG}" "${bak}"
        info "Backup created : ${bak}"
        BACKUP_DONE=1
    fi
}

# Set or replace a keyword in sshd_config
# Usage: sshd_set "Keyword" "value"
sshd_set() {
    local keyword="${1}"
    local value="${2}"

    backup_sshd_config

    if grep -qiE "^#?[[:space:]]*${keyword}[[:space:]]" "${SSHD_CONFIG}"; then
        # Replace existing line (commented or uncommented)
        sed -i "s|^#\?[[:space:]]*${keyword}[[:space:]].*|${keyword} ${value}|I" \
            "${SSHD_CONFIG}"
    else
        # Append if not present at all
        echo "${keyword} ${value}" >> "${SSHD_CONFIG}"
    fi

    CHANGES_MADE=1
}

# Run exact CIS grep audit command and return output
cis_grep() {
    local pattern="${1}"
    local file="${2:-${SSHD_CONFIG}}"
    grep -E "${pattern}" "${file}" 2>/dev/null || true
}

# =============================================================================
# CHECK 1 — Protocol 2
# =============================================================================
hdr "Check 1 — SSH Protocol Version"
info "Audit  : grep \"^Protocol\" ${SSHD_CONFIG}"
info "Expect : Protocol 2"
echo ""

RESULT=$(cis_grep "^Protocol" )
info "Found  : ${RESULT:-[not set]}"
echo ""

# In OpenSSH 7.4+ Protocol keyword was removed (SSHv2 is always enforced).
# We still set it explicitly per CIS for auditability, but note the context.
OPENSSH_VER=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[\d.]+' || echo "0")
info "OpenSSH version : ${OPENSSH_VER}"

if echo "${RESULT}" | grep -qE "^Protocol[[:space:]]+2"; then
    pass "Protocol 2 is explicitly set."
    CHECK_RESULT["Protocol"]="PASS"
else
    if [[ -z "${RESULT}" ]]; then
        info "Protocol keyword absent — OpenSSH 7.4+ enforces SSHv2 by default."
        info "Setting Protocol 2 explicitly for audit compliance ..."
    else
        fail "Protocol is set to: '${RESULT}' — must be 2."
    fi
    sshd_set "Protocol" "2"
    VERIFY=$(cis_grep "^Protocol")
    if echo "${VERIFY}" | grep -qE "^Protocol[[:space:]]+2"; then
        pass "Protocol 2 set."
        CHECK_RESULT["Protocol"]="REMEDIATED"
    else
        fail "Could not set Protocol 2."
        CHECK_RESULT["Protocol"]="FAILED"
        mark_fail
    fi
fi

# =============================================================================
# CHECK 2 — LogLevel INFO
# =============================================================================
hdr "Check 2 — SSH LogLevel"
info "Audit  : grep \"^LogLevel\" ${SSHD_CONFIG}"
info "Expect : LogLevel INFO"
echo ""

RESULT=$(cis_grep "^LogLevel")
info "Found  : ${RESULT:-[not set]}"
echo ""

if echo "${RESULT}" | grep -qiE "^LogLevel[[:space:]]+INFO"; then
    pass "LogLevel INFO is set."
    CHECK_RESULT["LogLevel"]="PASS"
else
    [[ -n "${RESULT}" ]] \
        && fail "LogLevel is '${RESULT}' — must be INFO." \
        || fail "LogLevel is not set (defaults to INFO but must be explicit per CIS)."
    info "Remediation: Setting LogLevel INFO ..."
    sshd_set "LogLevel" "INFO"
    pass "LogLevel INFO set."
    CHECK_RESULT["LogLevel"]="REMEDIATED"
fi

# =============================================================================
# CHECK 3 — sshd_config Ownership & Permissions
# =============================================================================
hdr "Check 3 — /etc/ssh/sshd_config Permissions"
info "Audit  : stat -L -c \"%a %u %g\" ${SSHD_CONFIG}"
info "Expect : 600 0 0  (CIS shows 644, this module uses 600 — more restrictive)"
echo ""

STAT_OUT=$(stat -L -c "%a %u %g" "${SSHD_CONFIG}" 2>/dev/null)
CURRENT_PERMS=$(echo "${STAT_OUT}" | awk '{print $1}')
CURRENT_UID=$(echo "${STAT_OUT}"   | awk '{print $2}')
CURRENT_GID=$(echo "${STAT_OUT}"   | awk '{print $3}')

info "Current : ${CURRENT_PERMS} uid=${CURRENT_UID} gid=${CURRENT_GID}"
echo ""

PERM_OK=0
OWN_OK=0
[[ "${CURRENT_PERMS}" == "600" || "${CURRENT_PERMS}" == "644" ]] && PERM_OK=1
[[ "${CURRENT_UID}" == "0" && "${CURRENT_GID}" == "0" ]] && OWN_OK=1

if [[ "${PERM_OK}" -eq 1 && "${OWN_OK}" -eq 1 ]]; then
    pass "${SSHD_CONFIG} — ${CURRENT_PERMS} root:root ✓"
    # Tighten to 600 if it's 644
    if [[ "${CURRENT_PERMS}" == "644" ]]; then
        info "Tightening from 644 to 600 (no world-read on sshd_config) ..."
        chmod 600 "${SSHD_CONFIG}"
        pass "Permissions tightened to 600."
    fi
    CHECK_RESULT["sshd_config_perms"]="PASS"
else
    fail "${SSHD_CONFIG} — ${CURRENT_PERMS} uid=${CURRENT_UID} gid=${CURRENT_GID}"
    info "Remediation:"

    if [[ "${OWN_OK}" -eq 0 ]]; then
        info "  chown root:root ${SSHD_CONFIG}"
        chown root:root "${SSHD_CONFIG}"
    fi

    info "  chmod 600 ${SSHD_CONFIG}"
    chmod 600 "${SSHD_CONFIG}"

    FINAL_STAT=$(stat -L -c "%a %u %g" "${SSHD_CONFIG}")
    pass "Remediated : ${FINAL_STAT} ✓"
    CHECK_RESULT["sshd_config_perms"]="REMEDIATED"
fi

# =============================================================================
# CHECK 4 — X11Forwarding no
# =============================================================================
hdr "Check 4 — X11Forwarding Disabled"
info "Audit  : grep \"^X11Forwarding\" ${SSHD_CONFIG}"
info "Expect : X11Forwarding no"
echo ""

RESULT=$(cis_grep "^X11Forwarding")
info "Found  : ${RESULT:-[not set]}"
echo ""

if echo "${RESULT}" | grep -qiE "^X11Forwarding[[:space:]]+no"; then
    pass "X11Forwarding no is set."
    CHECK_RESULT["X11Forwarding"]="PASS"
else
    [[ -n "${RESULT}" ]] \
        && fail "X11Forwarding is '${RESULT}' — must be no." \
        || fail "X11Forwarding not set — defaults may allow X11."
    detail "Risk: X11 forwarding can be abused for keylogging and screen capture"
    detail "      of the remote display, even on headless servers."
    info "Remediation: Setting X11Forwarding no ..."
    sshd_set "X11Forwarding" "no"
    pass "X11Forwarding no set."
    CHECK_RESULT["X11Forwarding"]="REMEDIATED"
fi

# =============================================================================
# CHECK 5 — MaxAuthTries 4
# =============================================================================
hdr "Check 5 — MaxAuthTries <= 4"
info "Audit  : grep \"^MaxAuthTries\" ${SSHD_CONFIG}"
info "Expect : MaxAuthTries 4"
echo ""

RESULT=$(cis_grep "^MaxAuthTries")
info "Found  : ${RESULT:-[not set (default: 6)]}"
echo ""

CURRENT_MAT=$(echo "${RESULT}" | awk '{print $2}')
CURRENT_MAT="${CURRENT_MAT:-6}"

if [[ "${CURRENT_MAT}" -le 4 ]] 2>/dev/null; then
    pass "MaxAuthTries is ${CURRENT_MAT} (<=4) ✓"
    CHECK_RESULT["MaxAuthTries"]="PASS"
else
    fail "MaxAuthTries is ${CURRENT_MAT} — must be 4 or less."
    detail "Risk: High MaxAuthTries allows brute-force of credentials without"
    detail "      triggering lockouts. Each extra attempt = one more password tried."
    info "Remediation: Setting MaxAuthTries 4 ..."
    sshd_set "MaxAuthTries" "4"
    pass "MaxAuthTries 4 set."
    CHECK_RESULT["MaxAuthTries"]="REMEDIATED"
fi

# =============================================================================
# CHECK 6 — IgnoreRhosts yes
# =============================================================================
hdr "Check 6 — IgnoreRhosts"
info "Audit  : grep \"^IgnoreRhosts\" ${SSHD_CONFIG}"
info "Expect : IgnoreRhosts yes"
echo ""

RESULT=$(cis_grep "^IgnoreRhosts")
info "Found  : ${RESULT:-[not set (default: yes)]}"
echo ""

if [[ -z "${RESULT}" ]] || echo "${RESULT}" | grep -qiE "^IgnoreRhosts[[:space:]]+yes"; then
    pass "IgnoreRhosts yes (set or defaulted) ✓"
    # Set explicitly for audit clarity
    if [[ -z "${RESULT}" ]]; then
        info "Setting explicitly for audit compliance ..."
        sshd_set "IgnoreRhosts" "yes"
        pass "IgnoreRhosts yes set explicitly."
    fi
    CHECK_RESULT["IgnoreRhosts"]="PASS"
else
    fail "IgnoreRhosts is '${RESULT}' — must be yes."
    detail "Risk: .rhosts files allow host-based authentication without passwords —"
    detail "      a legacy mechanism trivially exploited via IP spoofing."
    sshd_set "IgnoreRhosts" "yes"
    pass "IgnoreRhosts yes set."
    CHECK_RESULT["IgnoreRhosts"]="REMEDIATED"
fi

# =============================================================================
# CHECK 7 — HostbasedAuthentication no
# =============================================================================
hdr "Check 7 — HostbasedAuthentication"
info "Audit  : grep \"^HostbasedAuthentication\" ${SSHD_CONFIG}"
info "Expect : HostbasedAuthentication no"
echo ""

RESULT=$(cis_grep "^HostbasedAuthentication")
info "Found  : ${RESULT:-[not set (default: no)]}"
echo ""

if [[ -z "${RESULT}" ]] || echo "${RESULT}" | grep -qiE "^HostbasedAuthentication[[:space:]]+no"; then
    pass "HostbasedAuthentication no (set or defaulted) ✓"
    if [[ -z "${RESULT}" ]]; then
        sshd_set "HostbasedAuthentication" "no"
        pass "HostbasedAuthentication no set explicitly."
    fi
    CHECK_RESULT["HostbasedAuthentication"]="PASS"
else
    fail "HostbasedAuthentication is '${RESULT}' — must be no."
    detail "Risk: Allows login based on the client hostname alone — exploitable"
    detail "      via DNS spoofing or compromised hosts in /etc/hosts.equiv."
    sshd_set "HostbasedAuthentication" "no"
    pass "HostbasedAuthentication no set."
    CHECK_RESULT["HostbasedAuthentication"]="REMEDIATED"
fi

# =============================================================================
# CHECK 8 — PermitEmptyPasswords no
# =============================================================================
hdr "Check 8 — PermitEmptyPasswords"
info "Audit  : grep \"^PermitEmptyPasswords\" ${SSHD_CONFIG}"
info "Expect : PermitEmptyPasswords no"
echo ""

RESULT=$(cis_grep "^PermitEmptyPasswords")
info "Found  : ${RESULT:-[not set (default: no)]}"
echo ""

if [[ -z "${RESULT}" ]] || echo "${RESULT}" | grep -qiE "^PermitEmptyPasswords[[:space:]]+no"; then
    pass "PermitEmptyPasswords no (set or defaulted) ✓"
    if [[ -z "${RESULT}" ]]; then
        sshd_set "PermitEmptyPasswords" "no"
        pass "PermitEmptyPasswords no set explicitly."
    fi
    CHECK_RESULT["PermitEmptyPasswords"]="PASS"
else
    fail "PermitEmptyPasswords is '${RESULT}' — must be no."
    detail "Risk: Accounts with empty passwords can be accessed with no credentials"
    detail "      at all — zero barrier for an attacker."
    sshd_set "PermitEmptyPasswords" "no"
    pass "PermitEmptyPasswords no set."
    CHECK_RESULT["PermitEmptyPasswords"]="REMEDIATED"
fi

# =============================================================================
# CHECK 9 — PermitUserEnvironment no
# =============================================================================
hdr "Check 9 — PermitUserEnvironment"
info "Audit  : grep \"PermitUserEnvironment\" ${SSHD_CONFIG}"
info "Expect : PermitUserEnvironment no"
echo ""

RESULT=$(cis_grep "PermitUserEnvironment")
info "Found  : ${RESULT:-[not set (default: no)]}"
echo ""

if [[ -z "${RESULT}" ]] || echo "${RESULT}" | grep -qiE "PermitUserEnvironment[[:space:]]+no"; then
    pass "PermitUserEnvironment no (set or defaulted) ✓"
    if [[ -z "${RESULT}" ]]; then
        sshd_set "PermitUserEnvironment" "no"
        pass "PermitUserEnvironment no set explicitly."
    fi
    CHECK_RESULT["PermitUserEnvironment"]="PASS"
else
    fail "PermitUserEnvironment is '${RESULT}' — must be no."
    detail "Risk: Allows users to set environment variables via ~/.ssh/environment"
    detail "      which can override PATH, LD_PRELOAD, and bypass security controls."
    sshd_set "PermitUserEnvironment" "no"
    pass "PermitUserEnvironment no set."
    CHECK_RESULT["PermitUserEnvironment"]="REMEDIATED"
fi

# =============================================================================
# CHECK 10 — Ciphers (CTR mode only)
# =============================================================================
hdr "Check 10 — Approved Ciphers (CTR mode)"
info "Audit  : grep \"Ciphers\" ${SSHD_CONFIG}"
info "Expect : Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
echo ""

REQUIRED_CIPHERS="aes128-ctr,aes192-ctr,aes256-ctr"
RESULT=$(cis_grep "^Ciphers")
info "Found  : ${RESULT:-[not set (uses OpenSSH defaults)]}"
echo ""

# Check for any weak ciphers in current config
WEAK_FOUND=0
WEAK_LIST=""

if [[ -n "${RESULT}" ]]; then
    for weak in arcfour blowfish cast128 3des aes128-cbc aes192-cbc aes256-cbc \
                aes128-gcm aes256-gcm chacha20; do
        if echo "${RESULT}" | grep -qi "${weak}"; then
            WEAK_LIST="${WEAK_LIST} ${weak}"
            WEAK_FOUND=1
        fi
    done
fi

if echo "${RESULT}" | grep -qiE "^Ciphers[[:space:]]+${REQUIRED_CIPHERS//,/,}"; then
    pass "Ciphers are set to the CIS required CTR-mode list ✓"
    CHECK_RESULT["Ciphers"]="PASS"
elif [[ "${WEAK_FOUND}" -eq 1 ]]; then
    fail "Weak ciphers found in config :${WEAK_LIST}"
    detail "Risk: CBC-mode ciphers are vulnerable to BEAST and Lucky13 attacks."
    detail "      arcfour/RC4 is broken. CTR mode ciphers are required."
    info "Remediation: Setting Ciphers to CTR-mode only ..."
    sshd_set "Ciphers" "${REQUIRED_CIPHERS}"
    pass "Ciphers set to ${REQUIRED_CIPHERS}"
    CHECK_RESULT["Ciphers"]="REMEDIATED"
elif [[ -z "${RESULT}" ]]; then
    info "Ciphers not explicitly set — setting CIS required list ..."
    sshd_set "Ciphers" "${REQUIRED_CIPHERS}"
    pass "Ciphers set to ${REQUIRED_CIPHERS}"
    CHECK_RESULT["Ciphers"]="REMEDIATED"
else
    pass "Ciphers are set (no known weak ciphers detected) ✓"
    info "Current: ${RESULT}"
    info "CIS expected: Ciphers ${REQUIRED_CIPHERS}"
    CHECK_RESULT["Ciphers"]="PASS"
fi

# =============================================================================
# CHECK 11 — ClientAliveInterval 900
# =============================================================================
hdr "Check 11 — Idle Timeout (ClientAliveInterval)"
info "Audit  : grep \"^ClientAliveInterval\" ${SSHD_CONFIG}"
info "Expect : ClientAliveInterval 900"
echo ""

RESULT=$(cis_grep "^ClientAliveInterval")
info "Found  : ${RESULT:-[not set (default: 0 = disabled)]}"
echo ""

CURRENT_CAI=$(echo "${RESULT}" | awk '{print $2}')
CURRENT_CAI="${CURRENT_CAI:-0}"

if [[ "${CURRENT_CAI}" -gt 0 && "${CURRENT_CAI}" -le 900 ]] 2>/dev/null; then
    pass "ClientAliveInterval is ${CURRENT_CAI}s (>0, <=900) ✓"
    CHECK_RESULT["ClientAliveInterval"]="PASS"
else
    if [[ "${CURRENT_CAI}" -eq 0 ]]; then
        fail "ClientAliveInterval is 0 — idle sessions never timeout."
    else
        fail "ClientAliveInterval is ${CURRENT_CAI} — must be between 1 and 900."
    fi
    detail "Risk: Idle sessions left open allow an unattended terminal to be"
    detail "      hijacked. 900s = 15 minute idle timeout."
    info "Remediation: Setting ClientAliveInterval 900 and ClientAliveCountMax 0 ..."
    sshd_set "ClientAliveInterval"  "900"
    sshd_set "ClientAliveCountMax"  "0"
    pass "ClientAliveInterval 900 set (session ends after 15 min idle)."
    pass "ClientAliveCountMax 0 set (disconnect immediately on timeout, no retries)."
    CHECK_RESULT["ClientAliveInterval"]="REMEDIATED"
fi

# =============================================================================
# CHECK 12 — Banner /etc/issue.net
# =============================================================================
hdr "Check 12 — Login Warning Banner"
info "Audit  : grep \"^Banner\" ${SSHD_CONFIG}"
info "Expect : Banner /etc/issue.net"
echo ""

RESULT=$(cis_grep "^Banner")
info "Found  : ${RESULT:-[not set]}"
echo ""

# Create /etc/issue.net if missing or empty
if [[ ! -s "${ISSUE_NET}" ]]; then
    warn "${ISSUE_NET} is missing or empty — creating legal warning banner ..."

    cat > "${ISSUE_NET}" << 'BANNER'
******************************************************************************
                         AUTHORISED ACCESS ONLY

This system is the property of the organisation and is for authorised use
only. By accessing this system you consent to monitoring and recording of
all activity.

Unauthorised access or misuse is strictly prohibited and may be subject to
criminal prosecution under applicable laws.

Disconnect immediately if you are not an authorised user.
******************************************************************************
BANNER

    chmod 644 "${ISSUE_NET}"
    chown root:root "${ISSUE_NET}"
    pass "${ISSUE_NET} created with legal warning banner."
else
    pass "${ISSUE_NET} exists and is non-empty ✓"
fi

info "Banner content preview:"
head -3 "${ISSUE_NET}" | sed 's/^/        /'
echo "        ..."
echo ""

# Set Banner directive in sshd_config
if echo "${RESULT}" | grep -qE "^Banner[[:space:]]+/etc/issue\.net"; then
    pass "Banner is set to /etc/issue.net ✓"
    CHECK_RESULT["Banner"]="PASS"
else
    [[ -n "${RESULT}" ]] \
        && fail "Banner is '${RESULT}' — must be /etc/issue.net." \
        || fail "Banner is not set — users see no warning before login."
    detail "Risk: Without a banner, users are not warned that the system is"
    detail "      monitored, which can affect legal enforceability of policies."
    info "Remediation: Setting Banner /etc/issue.net ..."
    sshd_set "Banner" "/etc/issue.net"
    pass "Banner /etc/issue.net set."
    CHECK_RESULT["Banner"]="REMEDIATED"
fi

# =============================================================================
# Validate config syntax and reload sshd
# =============================================================================
hdr "Configuration Validation & Reload"

if [[ "${CHANGES_MADE}" -eq 1 ]]; then
    info "Changes were made to ${SSHD_CONFIG} — validating syntax ..."
    echo ""

    if sshd -t 2>/dev/null; then
        pass "sshd -t config syntax test PASSED."

        if systemctl is-active sshd &>/dev/null; then
            info "Reloading sshd to apply changes ..."
            if systemctl reload sshd 2>/dev/null; then
                pass "sshd reloaded successfully."
            else
                warn "sshd reload failed — trying restart ..."
                systemctl restart sshd 2>/dev/null \
                    && pass "sshd restarted." \
                    || { fail "Could not restart sshd."; mark_fail; }
            fi
        else
            info "sshd is not currently running — changes will apply on next start."
        fi
    else
        fail "sshd -t config syntax test FAILED — reload aborted to prevent lockout."
        warn "Review ${SSHD_CONFIG} manually before reloading sshd."
        warn "Restore from backup if needed:"
        ls -1t "${SSHD_CONFIG}".bak.* 2>/dev/null | head -3 | sed 's/^/        /'
        mark_fail
    fi
else
    pass "No changes made — sshd reload not required."
fi

# =============================================================================
# CIS Verification — re-run all grep audit commands post-remediation
# =============================================================================
hdr "CIS Audit Verification (post-remediation)"
info "Re-running all CIS grep audit commands ..."
echo ""

declare -A CIS_CHECKS
CIS_CHECKS["Protocol"]="grep \"^Protocol\" ${SSHD_CONFIG}"
CIS_CHECKS["LogLevel"]="grep \"^LogLevel\" ${SSHD_CONFIG}"
CIS_CHECKS["X11Forwarding"]="grep \"^X11Forwarding\" ${SSHD_CONFIG}"
CIS_CHECKS["MaxAuthTries"]="grep \"^MaxAuthTries\" ${SSHD_CONFIG}"
CIS_CHECKS["IgnoreRhosts"]="grep \"^IgnoreRhosts\" ${SSHD_CONFIG}"
CIS_CHECKS["HostbasedAuthentication"]="grep \"^HostbasedAuthentication\" ${SSHD_CONFIG}"
CIS_CHECKS["PermitEmptyPasswords"]="grep \"^PermitEmptyPasswords\" ${SSHD_CONFIG}"
CIS_CHECKS["PermitUserEnvironment"]="grep \"PermitUserEnvironment\" ${SSHD_CONFIG}"
CIS_CHECKS["Ciphers"]="grep \"Ciphers\" ${SSHD_CONFIG}"
CIS_CHECKS["ClientAliveInterval"]="grep \"^ClientAliveInterval\" ${SSHD_CONFIG}"
CIS_CHECKS["Banner"]="grep \"^Banner\" ${SSHD_CONFIG}"

declare -a CIS_ORDER=(
    "Protocol" "LogLevel" "X11Forwarding" "MaxAuthTries"
    "IgnoreRhosts" "HostbasedAuthentication" "PermitEmptyPasswords"
    "PermitUserEnvironment" "Ciphers" "ClientAliveInterval" "Banner"
)

printf "  ${BOLD}%-28s  %-40s${RESET}\n" "KEYWORD" "VALUE IN SSHD_CONFIG"
printf "  %s\n" "$(printf '─%.0s' {1..72})"

for keyword in "${CIS_ORDER[@]}"; do
    LIVE=$(grep -iE "^#?[[:space:]]*${keyword}[[:space:]]" "${SSHD_CONFIG}" \
           | grep -v '^#' | head -1 | xargs 2>/dev/null || echo "[not set]")
    printf "  %-28s  %s\n" "${keyword}" "${LIVE}"
done

# =============================================================================
# Summary Table
# =============================================================================
hdr "Run Summary"
echo ""

declare -a ALL_CHECKS=(
    "Protocol" "LogLevel" "sshd_config_perms" "X11Forwarding"
    "MaxAuthTries" "IgnoreRhosts" "HostbasedAuthentication"
    "PermitEmptyPasswords" "PermitUserEnvironment" "Ciphers"
    "ClientAliveInterval" "Banner"
)

COUNT_PASS=0
COUNT_REM=0
COUNT_FAIL=0

for chk in "${ALL_CHECKS[@]}"; do
    result="${CHECK_RESULT[${chk}]:-PASS}"
    case "${result}" in
        PASS)       (( COUNT_PASS++ )) || true ;;
        REMEDIATED) (( COUNT_REM++  )) || true ;;
        FAILED)     (( COUNT_FAIL++ )) || true ;;
    esac
done

TOTAL=${#ALL_CHECKS[@]}
printf "  ${BOLD}%-35s${RESET} %s\n"         "Total checks"        "${TOTAL}"
printf "  ${GREEN}${BOLD}%-35s${RESET} %s\n" "Already compliant"   "${COUNT_PASS}"
printf "  ${GREEN}${BOLD}%-35s${RESET} %s\n" "Remediated this run" "${COUNT_REM}"
if [[ "${COUNT_FAIL}" -gt 0 ]]; then
    printf "  ${RED}${BOLD}%-35s${RESET} %s\n" "Failed"            "${COUNT_FAIL}"
fi
printf "  ${BOLD}%-35s${RESET} %s\n" "Config file"                 "${SSHD_CONFIG}"
printf "  ${BOLD}%-35s${RESET} %s\n" "Banner file"                 "${ISSUE_NET}"

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 11_sshd_config — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 11_sshd_config — ONE OR MORE CHECKS FAILED"
    exit 1
fi
