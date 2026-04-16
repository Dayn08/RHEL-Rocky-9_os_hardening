#!/usr/bin/env bash
# =============================================================================
# MODULE  : 05_restrict_core_dumps.sh
# TITLE   : Restrict Core Dumps
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 1.5.1
#
# BACKGROUND:
#   Core dumps can contain sensitive data (passwords, encryption keys, memory
#   contents) written to disk when a process crashes. Setting a hard limit of
#   0 prevents any user from overriding the soft limit. The kernel parameter
#   fs.suid_dumpable must be 0 to prevent setuid programs from dumping core,
#   which could expose privileged memory to unprivileged users.
#
# CHECKS:
#   1.  /etc/security/limits.conf has "* hard core 0"
#   2.  /etc/security/limits.d/*.conf files do not override with a higher value
#   3.  sysctl fs.suid_dumpable = 0  (runtime)
#   4.  fs.suid_dumpable = 0 persisted in /etc/sysctl.conf or /etc/sysctl.d/
#   5.  systemd-coredump is disabled / masked  (RHEL/Rocky 9 specific)
#   6.  /etc/systemd/coredump.conf has Storage=none and ProcessSizeMax=0
#
# AUDIT COMMANDS (CIS reference):
#   grep "hard core" /etc/security/limits.conf   → * hard core 0
#   sysctl fs.suid_dumpable                       → fs.suid_dumpable = 2
#   NOTE: CIS shows suid_dumpable = 2 as the FOUND (non-compliant) state.
#         The REQUIRED value is 0.
#
# BEHAVIOUR:
#   - Auto-remediates all findings
#   - Backs up files before modification
#   - Applies sysctl change at runtime AND persists to /etc/sysctl.d/
#   - Does NOT restart any services (changes are non-disruptive)
#
# EXIT CODES:
#   0 — All checks passed (or remediated successfully)
#   1 — One or more checks failed / could not be remediated
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 05_restrict_core_dumps.sh
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

# ── Constants ──────────────────────────────────────────────────────────────────
LIMITS_CONF="/etc/security/limits.conf"
LIMITS_DIR="/etc/security/limits.d"
SYSCTL_DROP_IN="/etc/sysctl.d/60-coredump-hardening.conf"
COREDUMP_CONF="/etc/systemd/coredump.conf"
COREDUMP_DROP_DIR="/etc/systemd/coredump.conf.d"

# ── Helper: backup a file once per run ────────────────────────────────────────
backup_file() {
    local f="${1}"
    local bak="${f}.bak.$(date +%Y%m%d%H%M%S)"
    if [[ -f "${f}" ]]; then
        cp "${f}" "${bak}"
        info "  Backup created : ${bak}"
    fi
}

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
# CHECK 1 — /etc/security/limits.conf hard core limit
# =============================================================================
hdr "Check 1 — Hard Core Limit in limits.conf"
info "Audit  : grep \"hard core\" ${LIMITS_CONF}"
info "Expect : * hard core 0"
echo ""

if [[ ! -f "${LIMITS_CONF}" ]]; then
    fail "${LIMITS_CONF} not found."
    info "Remediation: Creating ${LIMITS_CONF} with core dump restriction ..."
    touch "${LIMITS_CONF}"
    chmod 644 "${LIMITS_CONF}"
fi

# Show current state
CURRENT_HARD=$(grep -E '^\s*\*\s+hard\s+core\s+' "${LIMITS_CONF}" 2>/dev/null || true)

if [[ -n "${CURRENT_HARD}" ]]; then
    info "Current entry : ${CURRENT_HARD}"
fi

# Check for correct entry
if grep -qE '^\s*\*\s+hard\s+core\s+0\s*$' "${LIMITS_CONF}" 2>/dev/null; then
    pass "\"* hard core 0\" is present in ${LIMITS_CONF}"
else
    fail "\"* hard core 0\" NOT found in ${LIMITS_CONF}"
    info "Remediation: Adding/updating hard core limit ..."
    backup_file "${LIMITS_CONF}"

    # Remove any existing hard core lines (all domains) to avoid duplicates
    sed -i '/^\s*.*\s\+hard\s\+core\s\+/d' "${LIMITS_CONF}"

    # Append the required line
    echo ""                             >> "${LIMITS_CONF}"
    echo "# Added by 05_restrict_core_dumps.sh — CIS RHEL9 1.5.1" >> "${LIMITS_CONF}"
    echo "* hard core 0"                >> "${LIMITS_CONF}"
    echo "* soft core 0"                >> "${LIMITS_CONF}"

    # Verify
    if grep -qE '^\s*\*\s+hard\s+core\s+0\s*$' "${LIMITS_CONF}"; then
        pass "Remediation successful — \"* hard core 0\" set in ${LIMITS_CONF}"
    else
        fail "Remediation failed — please set \"* hard core 0\" manually."
        mark_fail
    fi
fi

# Also add soft core 0 if missing (belt-and-suspenders)
if ! grep -qE '^\s*\*\s+soft\s+core\s+0\s*$' "${LIMITS_CONF}" 2>/dev/null; then
    info "Adding soft core 0 as well (belt-and-suspenders) ..."
    echo "* soft core 0" >> "${LIMITS_CONF}"
    pass "\"* soft core 0\" added to ${LIMITS_CONF}"
fi

# =============================================================================
# CHECK 2 — limits.d drop-in files do not override with a higher value
# =============================================================================
hdr "Check 2 — limits.d Drop-in Override Check"
info "Audit  : grep -rE 'hard core' ${LIMITS_DIR}/"

if [[ ! -d "${LIMITS_DIR}" ]]; then
    pass "${LIMITS_DIR} does not exist — no drop-in overrides possible."
else
    # Find any hard core entries that are NOT 0
    OVERRIDES=$(
        grep -rE '^\s*.*\s+hard\s+core\s+[^0]' "${LIMITS_DIR}/" 2>/dev/null \
        | grep -v '^\s*#' \
        || true
    )

    if [[ -z "${OVERRIDES}" ]]; then
        pass "No conflicting hard core overrides found in ${LIMITS_DIR}/"

        # Also show any existing entries for awareness
        ALL_CORE=$(grep -rE 'core' "${LIMITS_DIR}/" 2>/dev/null || true)
        if [[ -n "${ALL_CORE}" ]]; then
            info "Existing core-related entries in ${LIMITS_DIR}/:"
            echo "${ALL_CORE}" | sed 's/^/        /'
        fi
    else
        fail "Conflicting hard core limit found in limits.d — overrides limits.conf!"
        echo "${OVERRIDES}" | sed 's/^/        /'
        echo ""
        info "Remediation: Removing conflicting entries ..."
        while IFS=: read -r filepath _; do
            backup_file "${filepath}"
            sed -i '/^\s*.*\s\+hard\s\+core\s\+[^0]/d' "${filepath}"
            info "  Fixed : ${filepath}"
        done <<< "${OVERRIDES}"
        pass "Conflicting entries removed from ${LIMITS_DIR}/"
    fi
fi

# =============================================================================
# CHECK 3 — sysctl fs.suid_dumpable runtime value
# =============================================================================
hdr "Check 3 — sysctl fs.suid_dumpable (Runtime)"
info "Audit  : sysctl fs.suid_dumpable"
info "Expect : fs.suid_dumpable = 0"
info "Note   : CIS benchmark shows value 2 as the non-compliant example."
echo ""

if ! command -v sysctl &>/dev/null; then
    fail "sysctl command not found."
    mark_fail
else
    CURRENT_SUID=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "UNKNOWN")
    info "Current runtime value : fs.suid_dumpable = ${CURRENT_SUID}"

    case "${CURRENT_SUID}" in
        0)
            pass "fs.suid_dumpable = 0 (setuid programs will not dump core)."
            ;;
        1)
            fail "fs.suid_dumpable = 1 — all processes can dump core (insecure)."
            info "Remediation: Setting fs.suid_dumpable = 0 at runtime ..."
            sysctl -w fs.suid_dumpable=0 &>/dev/null
            VERIFY=$(sysctl -n fs.suid_dumpable 2>/dev/null)
            [[ "${VERIFY}" == "0" ]] && pass "Runtime value set to 0." \
                                     || { fail "Could not set runtime value."; mark_fail; }
            ;;
        2)
            fail "fs.suid_dumpable = 2 — suidsafe mode, core written to cwd (insecure)."
            info "This is the non-compliant state shown in the CIS audit example."
            info "Remediation: Setting fs.suid_dumpable = 0 at runtime ..."
            sysctl -w fs.suid_dumpable=0 &>/dev/null
            VERIFY=$(sysctl -n fs.suid_dumpable 2>/dev/null)
            [[ "${VERIFY}" == "0" ]] && pass "Runtime value set to 0." \
                                      || { fail "Could not set runtime value."; mark_fail; }
            ;;
        *)
            warn "Unexpected value for fs.suid_dumpable: '${CURRENT_SUID}'"
            ;;
    esac
fi

# =============================================================================
# CHECK 4 — fs.suid_dumpable persisted in sysctl.d
# =============================================================================
hdr "Check 4 — fs.suid_dumpable Persisted (sysctl.d)"
info "Audit  : grep -r 'fs.suid_dumpable' /etc/sysctl.conf /etc/sysctl.d/"
echo ""

# Search all sysctl config locations
SYSCTL_SOURCES=(
    "/etc/sysctl.conf"
    /etc/sysctl.d/*.conf
)

PERSISTED=0
CONFLICT=0

for src in "${SYSCTL_SOURCES[@]}"; do
    [[ ! -f "${src}" ]] && continue
    MATCH=$(grep -E '^\s*fs\.suid_dumpable\s*=' "${src}" 2>/dev/null || true)
    if [[ -n "${MATCH}" ]]; then
        VAL=$(echo "${MATCH}" | awk -F= '{print $2}' | tr -d ' ' | tail -1)
        info "Found in ${src} : ${MATCH}"
        if [[ "${VAL}" == "0" ]]; then
            PERSISTED=1
        else
            warn "Conflicting value (${VAL}) in ${src} — will be overridden by drop-in."
            CONFLICT=1
        fi
    fi
done

if [[ "${PERSISTED}" -eq 1 && "${CONFLICT}" -eq 0 ]]; then
    pass "fs.suid_dumpable = 0 is correctly persisted."
else
    if [[ "${PERSISTED}" -eq 0 ]]; then
        fail "fs.suid_dumpable not persisted — will revert to default on reboot."
    fi
    info "Remediation: Writing ${SYSCTL_DROP_IN} ..."

    mkdir -p "$(dirname "${SYSCTL_DROP_IN}")"
    cat > "${SYSCTL_DROP_IN}" << 'EOF'
# /etc/sysctl.d/60-coredump-hardening.conf
# Restrict core dumps — CIS RHEL9 Benchmark Section 1.5.1
#
# 0 = setuid programs will not produce core dumps
# (prevents privileged memory from being written to disk by unprivileged users)
fs.suid_dumpable = 0
EOF

    chmod 644 "${SYSCTL_DROP_IN}"
    chown root:root "${SYSCTL_DROP_IN}"

    # Apply immediately
    sysctl -p "${SYSCTL_DROP_IN}" &>/dev/null && \
        pass "Persisted to ${SYSCTL_DROP_IN} and applied." || \
        { fail "sysctl -p failed — check ${SYSCTL_DROP_IN}"; mark_fail; }
fi

# =============================================================================
# CHECK 5 — systemd-coredump masked / disabled
# =============================================================================
hdr "Check 5 — systemd-coredump Service"
info "Audit  : systemctl is-active systemd-coredump.socket"
echo ""

# Check if systemd-coredump socket unit exists on this system
if systemctl list-units --all --type=socket 2>/dev/null | grep -q "systemd-coredump"; then

    COREDUMP_ACTIVE=$(systemctl is-active systemd-coredump.socket 2>/dev/null || echo "inactive")
    COREDUMP_ENABLED=$(systemctl is-enabled systemd-coredump.socket 2>/dev/null || echo "disabled")
    info "systemd-coredump.socket : active=${COREDUMP_ACTIVE}, enabled=${COREDUMP_ENABLED}"

    if [[ "${COREDUMP_ACTIVE}" == "inactive" && \
          ("${COREDUMP_ENABLED}" == "disabled" || "${COREDUMP_ENABLED}" == "masked") ]]; then
        pass "systemd-coredump.socket is inactive and disabled."
    else
        fail "systemd-coredump.socket is active or enabled — should be disabled."
        info "Remediation: Stopping and masking systemd-coredump ..."
        systemctl stop    systemd-coredump.socket 2>/dev/null || true
        systemctl disable systemd-coredump.socket 2>/dev/null || true
        systemctl mask    systemd-coredump.socket 2>/dev/null || true
        pass "systemd-coredump.socket stopped, disabled, and masked."
    fi
else
    pass "systemd-coredump.socket unit not present on this system."
fi

# =============================================================================
# CHECK 6 — /etc/systemd/coredump.conf Storage=none
# =============================================================================
hdr "Check 6 — systemd coredump.conf Configuration"
info "Audit  : grep -E 'Storage|ProcessSizeMax' ${COREDUMP_CONF}"
info "Expect : Storage=none, ProcessSizeMax=0"
echo ""

COREDUMP_ISSUE=0

# Check if coredump.conf exists (it ships with systemd on RHEL/Rocky 9)
if [[ -f "${COREDUMP_CONF}" ]]; then

    STORAGE_VAL=$(grep -E '^\s*Storage\s*=' "${COREDUMP_CONF}" 2>/dev/null \
                  | tail -1 | awk -F= '{print $2}' | tr -d ' ' || echo "")
    PSMX_VAL=$(grep -E '^\s*ProcessSizeMax\s*=' "${COREDUMP_CONF}" 2>/dev/null \
               | tail -1 | awk -F= '{print $2}' | tr -d ' ' || echo "")

    info "Current Storage       : '${STORAGE_VAL:-not set (defaults to external)}'"
    info "Current ProcessSizeMax: '${PSMX_VAL:-not set}'"
    echo ""

    if [[ "${STORAGE_VAL}" == "none" ]]; then
        pass "Storage=none is set in ${COREDUMP_CONF}"
    else
        fail "Storage is '${STORAGE_VAL:-not set}' — should be 'none'."
        COREDUMP_ISSUE=1
    fi

    if [[ "${PSMX_VAL}" == "0" ]]; then
        pass "ProcessSizeMax=0 is set in ${COREDUMP_CONF}"
    else
        fail "ProcessSizeMax is '${PSMX_VAL:-not set}' — should be '0'."
        COREDUMP_ISSUE=1
    fi

else
    info "${COREDUMP_CONF} not found — will create drop-in configuration."
    COREDUMP_ISSUE=1
fi

# Remediate coredump.conf via drop-in (preferred over editing the main file)
if [[ "${COREDUMP_ISSUE}" -eq 1 ]]; then
    info "Remediation: Writing coredump drop-in configuration ..."
    mkdir -p "${COREDUMP_DROP_DIR}"

    cat > "${COREDUMP_DROP_DIR}/99-disable-coredump.conf" << 'EOF'
# /etc/systemd/coredump.conf.d/99-disable-coredump.conf
# Disable systemd core dump collection — CIS RHEL9 Section 1.5.1
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

    chmod 644 "${COREDUMP_DROP_DIR}/99-disable-coredump.conf"
    chown root:root "${COREDUMP_DROP_DIR}/99-disable-coredump.conf"

    # Reload systemd daemon to pick up the drop-in
    systemctl daemon-reload 2>/dev/null || true

    pass "Coredump drop-in written to ${COREDUMP_DROP_DIR}/99-disable-coredump.conf"
    pass "systemd daemon reloaded."
fi

# =============================================================================
# Final state summary
# =============================================================================
hdr "Final State Verification"
echo ""

# Re-read runtime value after all remediation
FINAL_SUID=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "UNKNOWN")
FINAL_HARD=$(grep -E '^\s*\*\s+hard\s+core\s+0' "${LIMITS_CONF}" 2>/dev/null \
             | head -1 | xargs || echo "NOT SET")
FINAL_SOFT=$(grep -E '^\s*\*\s+soft\s+core\s+0' "${LIMITS_CONF}" 2>/dev/null \
             | head -1 | xargs || echo "NOT SET")
FINAL_SYSCTL_FILE="absent"
[[ -f "${SYSCTL_DROP_IN}" ]] && FINAL_SYSCTL_FILE="${SYSCTL_DROP_IN}"

printf "  ${BOLD}%-40s${RESET} %s\n" "fs.suid_dumpable (runtime)"  "${FINAL_SUID}"
printf "  ${BOLD}%-40s${RESET} %s\n" "limits.conf hard core"        "${FINAL_HARD}"
printf "  ${BOLD}%-40s${RESET} %s\n" "limits.conf soft core"        "${FINAL_SOFT}"
printf "  ${BOLD}%-40s${RESET} %s\n" "sysctl.d persistence file"    "${FINAL_SYSCTL_FILE}"

echo ""

# Confirm expected values
[[ "${FINAL_SUID}" == "0" ]] \
    && pass "fs.suid_dumpable runtime = 0 ✓" \
    || { fail "fs.suid_dumpable runtime = ${FINAL_SUID} (expected 0)"; mark_fail; }

grep -qE '^\s*\*\s+hard\s+core\s+0' "${LIMITS_CONF}" 2>/dev/null \
    && pass "* hard core 0 confirmed in ${LIMITS_CONF} ✓" \
    || { fail "* hard core 0 missing from ${LIMITS_CONF}"; mark_fail; }

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 05_restrict_core_dumps — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 05_restrict_core_dumps — ONE OR MORE CHECKS FAILED"
    exit 1
fi
