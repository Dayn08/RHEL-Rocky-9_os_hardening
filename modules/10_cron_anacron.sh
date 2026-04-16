#!/usr/bin/env bash
# =============================================================================
# MODULE  : 10_cron_anacron.sh
# TITLE   : Enable anacron / cron Daemon & Secure File Permissions
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 5.1 (Configure cron)
#
# BACKGROUND:
#   cron and anacron are the standard job schedulers on Linux. Insecure
#   permissions on cron-related files and directories can allow unprivileged
#   users to:
#     - Read scheduled job definitions (information disclosure)
#     - Modify or inject commands into scheduled jobs (privilege escalation)
#     - Add their own cron jobs that run as root
#
#   The CIS benchmark requires:
#     - cronie-anacron package installed
#     - crond service enabled and active
#     - All cron config files/dirs owned by root:root
#     - All cron config files/dirs have no group or other read/write/execute
#       (permissions matching the pattern ?00 — i.e. no bits for group/other)
#
# CHECKS:
#   1.  cronie-anacron package installed
#   2.  crond service enabled and active
#   3.  /etc/anacrontab  — permissions & ownership
#   4.  /etc/crontab     — permissions & ownership
#   5.  /etc/cron.hourly — permissions & ownership
#   6.  /etc/cron.daily  — permissions & ownership
#   7.  /etc/cron.weekly — permissions & ownership
#   8.  /etc/cron.monthly— permissions & ownership
#   9.  /etc/cron.d      — permissions & ownership
#  10.  /etc/cron.allow / /etc/cron.deny access control
#
# CIS AUDIT COMMANDS (per path):
#   stat -L -c "%a %u %g" <path> | egrep ".00 0 0"
#   Expected match: permissions ending in 00, owned by uid 0, gid 0
#
# BEHAVIOUR:
#   - Installs cronie-anacron if missing
#   - Enables/starts crond if not running
#   - Remediates ownership (chown root:root) and permissions (chmod 600/700)
#     on each cron path
#   - Files get 600, directories get 700
#   - Creates missing cron directories with correct permissions
#   - Configures /etc/cron.allow with root-only access
#
# EXIT CODES:
#   0 — All checks passed (or remediated successfully)
#   1 — One or more checks failed
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 10_cron_anacron.sh
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
mark_fail() { OVERALL=1; }

# ── Result tracking ────────────────────────────────────────────────────────────
declare -A PATH_RESULT   # path -> "PASS" | "REMEDIATED" | "FAILED" | "CREATED"

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

# =============================================================================
# CHECK 1 — cronie-anacron Package Installed
# =============================================================================
hdr "Check 1 — cronie-anacron Package"
info "Audit  : rpm -q cronie-anacron"
echo ""

if rpm -q cronie-anacron &>/dev/null; then
    PKG_VER=$(rpm -q cronie-anacron)
    pass "cronie-anacron is installed : ${PKG_VER}"
else
    fail "cronie-anacron is NOT installed."
    info "Remediation: Installing via dnf ..."

    if dnf install -y cronie-anacron &>/dev/null; then
        PKG_VER=$(rpm -q cronie-anacron)
        pass "cronie-anacron installed : ${PKG_VER}"
    else
        fail "dnf install cronie-anacron failed — check repo/network."
        mark_fail
        # Can still continue and audit permissions
    fi
fi

# Also ensure the base cronie package is installed
if ! rpm -q cronie &>/dev/null; then
    info "Installing cronie (base cron daemon) ..."
    dnf install -y cronie &>/dev/null \
        && pass "cronie installed." \
        || { fail "Could not install cronie."; mark_fail; }
fi

# =============================================================================
# CHECK 2 — crond Service Enabled and Active
# =============================================================================
hdr "Check 2 — crond Service"
info "Audit  : systemctl is-enabled crond / systemctl is-active crond"
echo ""

CROND_ENABLED=$(systemctl is-enabled crond 2>/dev/null || echo "not-found")
CROND_ACTIVE=$(systemctl is-active  crond 2>/dev/null || echo "inactive")

info "crond enabled : ${CROND_ENABLED}"
info "crond active  : ${CROND_ACTIVE}"
echo ""

# Enable
if [[ "${CROND_ENABLED}" == "enabled" ]]; then
    pass "crond is enabled (will start on boot)."
else
    fail "crond is not enabled (${CROND_ENABLED})."
    info "Remediation: systemctl enable crond"
    systemctl enable crond 2>/dev/null \
        && pass "crond enabled." \
        || { fail "Could not enable crond."; mark_fail; }
fi

# Start
if [[ "${CROND_ACTIVE}" == "active" ]]; then
    pass "crond is active (running)."
else
    fail "crond is not running (${CROND_ACTIVE})."
    info "Remediation: systemctl start crond"
    systemctl start crond 2>/dev/null \
        && pass "crond started." \
        || { fail "Could not start crond."; mark_fail; }
fi

# =============================================================================
# Permission check / remediation helper
# =============================================================================
# CIS audit pattern: stat -L -c "%a %u %g" <path> | egrep ".00 0 0"
#   %a = octal permissions
#   %u = numeric owner UID
#   %g = numeric group GID
# The regex ".00 0 0" means:
#   - Any leading permission digit(s)
#   - Last two octal digits are 00  (no group or other bits)
#   - Owner UID = 0 (root)
#   - Owner GID = 0 (root)
#
# For files      : target permissions = 600  (rw-------)
# For directories: target permissions = 700  (rwx------)
# =============================================================================

check_and_fix_path() {
    local target_path="${1}"
    local path_type="${2}"      # "file" or "dir"
    local section_title="${3}"

    local target_perms
    [[ "${path_type}" == "file" ]] && target_perms="600" || target_perms="700"

    echo ""
    hdr "${section_title}"
    info "Audit  : stat -L -c \"%a %u %g\" ${target_path} | egrep \".00 0 0\""
    echo ""

    # ── Handle missing paths ───────────────────────────────────────────────────
    if [[ ! -e "${target_path}" ]]; then
        warn "${target_path} does not exist — creating it ..."

        if [[ "${path_type}" == "dir" ]]; then
            mkdir -p "${target_path}"
            info "Directory created : ${target_path}"
        else
            touch "${target_path}"
            info "File created : ${target_path}"
        fi

        chown root:root "${target_path}"
        chmod "${target_perms}" "${target_path}"
        pass "${target_path} created with ${target_perms} root:root."
        PATH_RESULT["${target_path}"]="CREATED"
        return
    fi

    # ── Run CIS audit command ─────────────────────────────────────────────────
    STAT_OUT=$(stat -L -c "%a %u %g" "${target_path}" 2>/dev/null || echo "ERROR")
    info "stat output : ${STAT_OUT}"

    CURRENT_PERMS=$(echo "${STAT_OUT}" | awk '{print $1}')
    CURRENT_UID=$(echo "${STAT_OUT}"   | awk '{print $2}')
    CURRENT_GID=$(echo "${STAT_OUT}"   | awk '{print $3}')

    # Evaluate CIS pattern: last two octal digits = 00, uid = 0, gid = 0
    CIS_MATCH=$(echo "${STAT_OUT}" | grep -E '[0-9]00 0 0' || true)
    OWNER_OK=0
    PERMS_OK=0

    [[ "${CURRENT_UID}" == "0" && "${CURRENT_GID}" == "0" ]] && OWNER_OK=1
    # Check last two digits are 00
    [[ "${CURRENT_PERMS}" =~ 00$ ]] && PERMS_OK=1

    # ── Report current state ───────────────────────────────────────────────────
    if [[ "${OWNER_OK}" -eq 1 && "${PERMS_OK}" -eq 1 ]]; then
        pass "${target_path} — permissions ${CURRENT_PERMS}, owner ${CURRENT_UID}:${CURRENT_GID} ✓"
        detail "CIS pattern match : '${STAT_OUT}' matches egrep '.00 0 0'"
        PATH_RESULT["${target_path}"]="PASS"
        return
    fi

    # ── Report issues ──────────────────────────────────────────────────────────
    fail "${target_path} — current: ${CURRENT_PERMS} ${CURRENT_UID}:${CURRENT_GID}"

    if [[ "${OWNER_OK}" -eq 0 ]]; then
        warn "  Ownership : ${CURRENT_UID}:${CURRENT_GID} (expected 0:0 / root:root)"
    fi
    if [[ "${PERMS_OK}" -eq 0 ]]; then
        warn "  Permissions : ${CURRENT_PERMS} (expected pattern ?00 — no group/other bits)"
    fi

    # ── Remediate ownership ───────────────────────────────────────────────────
    info "Remediation:"

    if [[ "${OWNER_OK}" -eq 0 ]]; then
        info "  chown root:root ${target_path}"
        chown root:root "${target_path}" \
            && info "  Ownership set to root:root." \
            || { fail "  chown failed."; mark_fail; }
    fi

    # ── Remediate permissions ─────────────────────────────────────────────────
    if [[ "${PERMS_OK}" -eq 0 ]]; then
        info "  chmod ${target_perms} ${target_path}"
        chmod "${target_perms}" "${target_path}" \
            && info "  Permissions set to ${target_perms}." \
            || { fail "  chmod failed."; mark_fail; }
    fi

    # ── Post-remediation verify ────────────────────────────────────────────────
    FINAL_STAT=$(stat -L -c "%a %u %g" "${target_path}" 2>/dev/null || echo "ERROR")
    FINAL_PERMS=$(echo "${FINAL_STAT}" | awk '{print $1}')
    FINAL_UID=$(echo "${FINAL_STAT}"   | awk '{print $2}')
    FINAL_GID=$(echo "${FINAL_STAT}"   | awk '{print $3}')

    echo ""
    info "Post-remediation : ${FINAL_STAT}"

    FINAL_MATCH=$(echo "${FINAL_STAT}" | grep -E '[0-9]00 0 0' || true)

    if [[ -n "${FINAL_MATCH}" ]]; then
        pass "${target_path} — remediated to ${FINAL_PERMS} root:root ✓"
        PATH_RESULT["${target_path}"]="REMEDIATED"
    else
        fail "${target_path} — still non-compliant after remediation : ${FINAL_STAT}"
        PATH_RESULT["${target_path}"]="FAILED"
        mark_fail
    fi
}

# =============================================================================
# CHECK 3-9 — Cron path permissions
# =============================================================================

check_and_fix_path "/etc/anacrontab"   "file"  "Check 3  — /etc/anacrontab"
check_and_fix_path "/etc/crontab"      "file"  "Check 4  — /etc/crontab"
check_and_fix_path "/etc/cron.hourly"  "dir"   "Check 5  — /etc/cron.hourly"
check_and_fix_path "/etc/cron.daily"   "dir"   "Check 6  — /etc/cron.daily"
check_and_fix_path "/etc/cron.weekly"  "dir"   "Check 7  — /etc/cron.weekly"
check_and_fix_path "/etc/cron.monthly" "dir"   "Check 8  — /etc/cron.monthly"
check_and_fix_path "/etc/cron.d"       "dir"   "Check 9  — /etc/cron.d"

# =============================================================================
# CHECK 10 — /etc/cron.allow and /etc/cron.deny access control
# =============================================================================
hdr "Check 10 — cron Access Control (cron.allow / cron.deny)"
info "Restricting cron usage to authorised users only."
echo ""

CRON_ALLOW="/etc/cron.allow"
CRON_DENY="/etc/cron.deny"

# CIS recommendation: cron.allow exists (with only root), cron.deny removed
# This means only users explicitly listed in cron.allow can use cron.

# Handle cron.deny — should not exist (or be empty) when cron.allow is used
if [[ -f "${CRON_DENY}" ]]; then
    DENY_CONTENTS=$(cat "${CRON_DENY}" 2>/dev/null | grep -v '^#' | grep -v '^$' || true)
    if [[ -n "${DENY_CONTENTS}" ]]; then
        warn "${CRON_DENY} exists with entries — when cron.allow is used, cron.deny is ignored."
        info "Removing ${CRON_DENY} to avoid confusion ..."
        rm -f "${CRON_DENY}"
        pass "${CRON_DENY} removed."
    else
        info "${CRON_DENY} exists but is empty — removing for cleanliness ..."
        rm -f "${CRON_DENY}"
        pass "${CRON_DENY} removed."
    fi
else
    pass "${CRON_DENY} does not exist (correct — using cron.allow whitelist)."
fi

# Handle cron.allow — should exist and be root:root 600
if [[ -f "${CRON_ALLOW}" ]]; then
    info "${CRON_ALLOW} exists."
    ALLOW_CONTENTS=$(grep -v '^#' "${CRON_ALLOW}" | grep -v '^$' || true)
    if echo "${ALLOW_CONTENTS}" | grep -q '^root$'; then
        pass "root is listed in ${CRON_ALLOW}."
    else
        warn "root is NOT listed in ${CRON_ALLOW} — adding ..."
        echo "root" >> "${CRON_ALLOW}"
        pass "root added to ${CRON_ALLOW}."
    fi
else
    info "${CRON_ALLOW} does not exist — creating with root-only access ..."
    echo "root" > "${CRON_ALLOW}"
    pass "${CRON_ALLOW} created with root-only access."
fi

# Secure cron.allow permissions
chown root:root "${CRON_ALLOW}"
chmod 600 "${CRON_ALLOW}"
CRON_ALLOW_STAT=$(stat -L -c "%a %u %g" "${CRON_ALLOW}")
pass "${CRON_ALLOW} — ${CRON_ALLOW_STAT} ✓"

# =============================================================================
# Summary Table
# =============================================================================
echo ""
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║           CRON / ANACRON HARDENING SUMMARY                      ║${RESET}"
echo -e "${BOLD}╠════════════════════════════╦═══════════╦═══════╦════════════════╣${RESET}"
printf "${BOLD}║  %-26s ║ %-9s ║ %-5s ║ %-14s ║${RESET}\n" \
    "PATH" "TYPE" "PERM" "STATUS"
echo -e "${BOLD}╠════════════════════════════╬═══════════╬═══════╬════════════════╣${RESET}"

# Define display order and types
declare -a DISPLAY_PATHS=(
    "/etc/anacrontab:file"
    "/etc/crontab:file"
    "/etc/cron.hourly:dir"
    "/etc/cron.daily:dir"
    "/etc/cron.weekly:dir"
    "/etc/cron.monthly:dir"
    "/etc/cron.d:dir"
    "/etc/cron.allow:file"
)

COUNT_PASS=0
COUNT_REM=0
COUNT_CREATE=0
COUNT_FAIL=0

for entry in "${DISPLAY_PATHS[@]}"; do
    path="${entry%%:*}"
    ptype="${entry##*:}"
    [[ "${ptype}" == "file" ]] && perm="600" || perm="700"

    result="${PATH_RESULT[${path}]:-PASS}"

    case "${result}" in
        PASS)       STATUS_STR="Already OK    "; (( COUNT_PASS++   )) || true ;;
        REMEDIATED) STATUS_STR="Fixed ✓       "; (( COUNT_REM++    )) || true ;;
        CREATED)    STATUS_STR="Created ✓     "; (( COUNT_CREATE++ )) || true ;;
        FAILED)     STATUS_STR="FAILED ✗      "; (( COUNT_FAIL++   )) || true ;;
    esac

    printf "║  %-26s ║ %-9s ║ %-5s ║ %-14s ║\n" \
        "${path}" "${ptype}" "${perm}" "${result}"
done

echo -e "${BOLD}╠════════════════════════════╩═══════════╩═══════╩════════════════╣${RESET}"

TOTAL=$(( ${#DISPLAY_PATHS[@]} ))
printf "${BOLD}║  %-64s ║${RESET}\n" "Total paths audited  : ${TOTAL}"
printf "║  %-64s ║\n"              "Already compliant    : ${COUNT_PASS}"
printf "${GREEN}${BOLD}║  %-64s ║${RESET}\n" "Remediated           : ${COUNT_REM}"
printf "${GREEN}${BOLD}║  %-64s ║${RESET}\n" "Created              : ${COUNT_CREATE}"
if [[ "${COUNT_FAIL}" -gt 0 ]]; then
    printf "${RED}${BOLD}║  %-64s ║${RESET}\n" "Failed               : ${COUNT_FAIL}"
else
    printf "║  %-64s ║\n" "Failed               : ${COUNT_FAIL}"
fi
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"

echo ""
info "crond service status :"
detail "systemctl status crond"
info "View scheduled jobs  :"
detail "crontab -l -u root"
detail "cat /etc/crontab"
detail "ls -la /etc/cron.d/"

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 10_cron_anacron — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 10_cron_anacron — ONE OR MORE CHECKS FAILED"
    exit 1
fi
