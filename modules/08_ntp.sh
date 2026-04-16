#!/usr/bin/env bash
# =============================================================================
# MODULE  : 08_ntp.sh
# TITLE   : Configure Network Time Protocol (NTP)
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 2.2.1
#
# BACKGROUND:
#   Accurate time synchronisation is critical for:
#     - Log correlation across systems (security forensics)
#     - Kerberos / GSSAPI authentication (tickets expire based on time)
#     - TLS/SSL certificate validity checks
#     - Audit trail integrity (tamper detection)
#     - Cron job scheduling accuracy
#
#   RHEL/Rocky Linux 9 ships with chrony as the DEFAULT and PREFERRED NTP
#   implementation. The legacy ntpd daemon (ntp package) is still available
#   but is deprecated in favour of chrony which is more accurate, more
#   secure, and better suited for virtual machines.
#
#   This module handles BOTH implementations:
#     - If chrony is installed/active  → audit and harden chrony
#     - If ntp (ntpd) is installed     → audit and harden ntpd
#     - If neither                     → install and configure chrony
#
# CHECKS:
#   [chrony path]
#   1.  chronyd package installed and service active
#   2.  At least one NTP server defined in /etc/chrony.conf
#   3.  makestep directive configured (fast initial sync)
#   4.  chrony not running as root (uses chrony user by default)
#   5.  noclientlog and access restrictions configured
#
#   [ntpd path — legacy, CIS reference commands]
#   1.  ntp package installed and ntpd service active
#   2.  restrict default includes: kod nomodify notrap nopeer noquery
#   3.  restrict -6 default includes: kod nomodify notrap nopeer noquery
#   4.  At least one ^server line defined in /etc/ntp.conf
#   5.  ntpd running as unprivileged ntp:ntp user (OPTIONS in /etc/sysconfig/ntpd)
#
# CIS AUDIT COMMANDS (ntpd reference):
#   grep "restrict default"    /etc/ntp.conf
#   grep "restrict -6 default" /etc/ntp.conf
#   grep "^server"             /etc/ntp.conf
#   grep "ntp:ntp"             /etc/sysconfig/ntpd
#
# EXIT CODES:
#   0 — All checks passed (or remediated successfully)
#   1 — One or more checks failed
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 08_ntp.sh
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
CHRONY_CONF="/etc/chrony.conf"
NTP_CONF="/etc/ntp.conf"
NTP_SYSCONFIG="/etc/sysconfig/ntpd"

# Default NTP servers — uses chrony.pool.ntp.org (geo-distributed, reliable)
# Override these with your organisation's internal NTP servers if required.
DEFAULT_NTP_SERVERS=(
    "pool 0.rhel.pool.ntp.org iburst"
    "pool 1.rhel.pool.ntp.org iburst"
    "pool 2.rhel.pool.ntp.org iburst"
    "pool 3.rhel.pool.ntp.org iburst"
)

# Required ntpd restrict flags (CIS reference)
REQUIRED_RESTRICT_FLAGS="kod nomodify notrap nopeer noquery"

# ── Helper: backup a file ──────────────────────────────────────────────────────
backup_file() {
    local f="${1}"
    [[ -f "${f}" ]] || return 0
    local bak="${f}.bak.$(date +%Y%m%d%H%M%S)"
    cp "${f}" "${bak}"
    info "  Backup created : ${bak}"
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
# Detect which NTP implementation is present
# =============================================================================
hdr "NTP Implementation Detection"

CHRONY_INSTALLED=0
NTP_INSTALLED=0
ACTIVE_IMPL=""

rpm -q chrony  &>/dev/null && CHRONY_INSTALLED=1
rpm -q ntp     &>/dev/null && NTP_INSTALLED=1

CHRONY_ACTIVE=$(systemctl is-active chronyd 2>/dev/null || echo "inactive")
NTPD_ACTIVE=$(systemctl is-active   ntpd    2>/dev/null || echo "inactive")

info "chrony  installed : $([[ ${CHRONY_INSTALLED} -eq 1 ]] && echo yes || echo no)"
info "chrony  active    : ${CHRONY_ACTIVE}"
info "ntp     installed : $([[ ${NTP_INSTALLED} -eq 1 ]] && echo yes || echo no)"
info "ntpd    active    : ${NTPD_ACTIVE}"
echo ""

# Determine active implementation
if [[ "${CHRONY_INSTALLED}" -eq 1 || "${CHRONY_ACTIVE}" == "active" ]]; then
    ACTIVE_IMPL="chrony"
    info "Using chrony path (preferred for RHEL/Rocky 9)"
elif [[ "${NTP_INSTALLED}" -eq 1 || "${NTPD_ACTIVE}" == "active" ]]; then
    ACTIVE_IMPL="ntpd"
    warn "Using legacy ntpd path — consider migrating to chrony."
else
    ACTIVE_IMPL="none"
    warn "No NTP implementation detected — will install chrony."
fi

# Warn if both are running (conflict)
if [[ "${CHRONY_ACTIVE}" == "active" && "${NTPD_ACTIVE}" == "active" ]]; then
    fail "Both chronyd AND ntpd are running — this is a conflict."
    info "Remediation: Stopping and disabling ntpd (chrony takes precedence) ..."
    systemctl stop    ntpd 2>/dev/null || true
    systemctl disable ntpd 2>/dev/null || true
    systemctl mask    ntpd 2>/dev/null || true
    pass "ntpd stopped, disabled, and masked."
    ACTIVE_IMPL="chrony"
fi

# =============================================================================
# CHRONY PATH
# =============================================================================
if [[ "${ACTIVE_IMPL}" == "chrony" || "${ACTIVE_IMPL}" == "none" ]]; then

    # ── Install if missing ────────────────────────────────────────────────────
    hdr "Chrony — Package & Service"
    info "Audit  : rpm -q chrony"

    if [[ "${CHRONY_INSTALLED}" -eq 0 ]]; then
        fail "chrony is not installed."
        info "Remediation: Installing chrony via dnf ..."
        if dnf install -y chrony &>/dev/null; then
            pass "chrony installed successfully."
            CHRONY_INSTALLED=1
        else
            fail "dnf install chrony failed — check repo/network."
            mark_fail
            exit 1
        fi
    else
        CHRONY_VER=$(rpm -q --queryformat "%{VERSION}-%{RELEASE}" chrony)
        pass "chrony is installed (${CHRONY_VER})."
    fi

    # ── Enable and start chronyd ──────────────────────────────────────────────
    info "Audit  : systemctl is-enabled chronyd / systemctl is-active chronyd"

    if ! systemctl is-enabled chronyd &>/dev/null; then
        info "Remediation: Enabling chronyd ..."
        systemctl enable chronyd &>/dev/null
        pass "chronyd enabled."
    else
        pass "chronyd is enabled."
    fi

    if ! systemctl is-active chronyd &>/dev/null; then
        info "Remediation: Starting chronyd ..."
        systemctl start chronyd && pass "chronyd started." \
            || { fail "Could not start chronyd."; mark_fail; }
    else
        pass "chronyd is active."
    fi

    # ── Check config file ─────────────────────────────────────────────────────
    hdr "Chrony — Configuration File"
    info "Audit  : ${CHRONY_CONF}"

    if [[ ! -f "${CHRONY_CONF}" ]]; then
        fail "${CHRONY_CONF} not found — creating default configuration ..."
        backup_file "${CHRONY_CONF}"

        cat > "${CHRONY_CONF}" << EOF
# ${CHRONY_CONF}
# Generated by 08_ntp.sh — CIS RHEL9 Section 2.2.1
# Replace pool entries below with your organisation's internal NTP servers.

$(printf '%s\n' "${DEFAULT_NTP_SERVERS[@]}")

# Record the rate at which the system clock gains/loses time
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second (useful after provisioning)
makestep 1.0 3

# Enable kernel synchronisation of the hardware clock
rtcsync

# Only allow access from localhost (no external NTP clients)
allow 127.0.0.1
allow ::1

# Do not log client accesses
noclientlog

# Send a message to syslog if the clock adjustment is larger than 0.5 seconds
logchange 0.5

# Specify log directory
logdir /var/log/chrony
EOF
        chmod 640 "${CHRONY_CONF}"
        chown root:chrony "${CHRONY_CONF}" 2>/dev/null || chown root:root "${CHRONY_CONF}"
        pass "Default ${CHRONY_CONF} created."
    else
        pass "${CHRONY_CONF} exists."
    fi

    # ── Check 2: NTP servers defined ──────────────────────────────────────────
    hdr "Chrony — NTP Server Entries"
    info "Audit  : grep -E '^(server|pool)' ${CHRONY_CONF}"
    echo ""

    SERVER_LINES=$(grep -E '^\s*(server|pool)\s+' "${CHRONY_CONF}" 2>/dev/null || true)

    if [[ -n "${SERVER_LINES}" ]]; then
        pass "NTP server/pool entries found in ${CHRONY_CONF}:"
        echo "${SERVER_LINES}" | sed 's/^/        /'
    else
        fail "No server or pool entries in ${CHRONY_CONF}."
        info "Remediation: Adding default NTP pool servers ..."
        backup_file "${CHRONY_CONF}"
        {
            echo ""
            echo "# NTP servers added by 08_ntp.sh"
            printf '%s\n' "${DEFAULT_NTP_SERVERS[@]}"
        } >> "${CHRONY_CONF}"
        pass "Default NTP pool servers added to ${CHRONY_CONF}."
    fi

    # ── Check 3: makestep directive ───────────────────────────────────────────
    hdr "Chrony — makestep Directive"
    info "Audit  : grep 'makestep' ${CHRONY_CONF}"

    MAKESTEP=$(grep -E '^\s*makestep\s+' "${CHRONY_CONF}" 2>/dev/null || true)

    if [[ -n "${MAKESTEP}" ]]; then
        pass "makestep is configured : ${MAKESTEP}"
    else
        fail "makestep not configured — initial large clock offsets won't be corrected."
        info "Remediation: Adding makestep 1.0 3 ..."
        backup_file "${CHRONY_CONF}"
        echo "makestep 1.0 3" >> "${CHRONY_CONF}"
        pass "makestep 1.0 3 added to ${CHRONY_CONF}."
    fi

    # ── Check 4: chrony user (not root) ───────────────────────────────────────
    hdr "Chrony — Running as Unprivileged User"
    info "Audit  : ps -ef | grep chronyd"
    echo ""

    CHRONY_PROC=$(ps -ef 2>/dev/null | grep '[c]hronyd' || true)

    if [[ -n "${CHRONY_PROC}" ]]; then
        CHRONY_PROC_USER=$(echo "${CHRONY_PROC}" | awk '{print $1}' | head -1)
        info "chronyd process user : ${CHRONY_PROC_USER}"

        if [[ "${CHRONY_PROC_USER}" == "chrony" ]]; then
            pass "chronyd is running as unprivileged user 'chrony'."
        elif [[ "${CHRONY_PROC_USER}" == "root" ]]; then
            fail "chronyd is running as root — should run as 'chrony' user."
            warn "Check /etc/chrony.conf for a 'user chrony' directive."
            if ! grep -qE '^\s*user\s+chrony' "${CHRONY_CONF}" 2>/dev/null; then
                info "Remediation: Adding 'user chrony' to ${CHRONY_CONF} ..."
                backup_file "${CHRONY_CONF}"
                echo "user chrony" >> "${CHRONY_CONF}"
                pass "'user chrony' added — restart chronyd to apply: systemctl restart chronyd"
            fi
            mark_fail
        else
            info "chronyd running as '${CHRONY_PROC_USER}' — verify this is correct."
        fi
    else
        warn "chronyd process not found in ps output (may have just started)."
    fi

    # ── Check 5: noclientlog ──────────────────────────────────────────────────
    hdr "Chrony — noclientlog Directive"
    info "Audit  : grep 'noclientlog' ${CHRONY_CONF}"

    if grep -qE '^\s*noclientlog' "${CHRONY_CONF}" 2>/dev/null; then
        pass "noclientlog is set — client access logging disabled (reduces disk I/O)."
    else
        warn "noclientlog not set — adding it as best practice ..."
        echo "noclientlog" >> "${CHRONY_CONF}"
        pass "noclientlog added to ${CHRONY_CONF}."
    fi

    # ── Reload chrony to pick up any config changes ───────────────────────────
    hdr "Chrony — Apply Configuration"

    if systemctl is-active chronyd &>/dev/null; then
        if systemctl reload-or-restart chronyd 2>/dev/null; then
            pass "chronyd reloaded with updated configuration."
        else
            warn "chronyd reload returned non-zero — check: journalctl -u chronyd"
        fi
    fi

    # ── Show sync status ──────────────────────────────────────────────────────
    hdr "Chrony — Sync Status"
    info "Running: chronyc tracking"
    echo ""

    if command -v chronyc &>/dev/null; then
        chronyc tracking 2>/dev/null | sed 's/^/        /' \
            || warn "chronyc tracking failed — daemon may still be starting."
        echo ""
        info "NTP sources:"
        chronyc sources -v 2>/dev/null | head -20 | sed 's/^/        /' \
            || true
    else
        warn "chronyc not found — cannot show sync status."
    fi

fi   # end chrony path

# =============================================================================
# NTPD PATH (legacy — CIS reference audit commands)
# =============================================================================
if [[ "${ACTIVE_IMPL}" == "ntpd" ]]; then

    hdr "NTP (ntpd) — Legacy Path"
    warn "ntpd is deprecated in RHEL/Rocky 9. Consider migrating to chrony."
    info "Migration: dnf swap ntp chrony && systemctl enable --now chronyd"
    echo ""

    # ── Check 1: Package and service ─────────────────────────────────────────
    hdr "ntpd — Package & Service"
    info "Audit  : rpm -q ntp"

    if rpm -q ntp &>/dev/null; then
        NTP_VER=$(rpm -q --queryformat "%{VERSION}-%{RELEASE}" ntp)
        pass "ntp package installed (${NTP_VER})."
    else
        fail "ntp package not installed."
        mark_fail
    fi

    if systemctl is-enabled ntpd &>/dev/null; then
        pass "ntpd service is enabled."
    else
        fail "ntpd service is not enabled."
        info "Remediation: Enabling ntpd ..."
        systemctl enable ntpd 2>/dev/null && pass "ntpd enabled." || mark_fail
    fi

    if systemctl is-active ntpd &>/dev/null; then
        pass "ntpd service is active."
    else
        fail "ntpd is not running."
        info "Remediation: Starting ntpd ..."
        systemctl start ntpd 2>/dev/null && pass "ntpd started." || mark_fail
    fi

    # ── Check 2: restrict default (CIS audit command) ─────────────────────────
    hdr "ntpd — restrict default (IPv4)"
    info "Audit  : grep \"restrict default\" ${NTP_CONF}"
    info "Expect : restrict default kod nomodify notrap nopeer noquery"
    echo ""

    if [[ ! -f "${NTP_CONF}" ]]; then
        fail "${NTP_CONF} not found."
        mark_fail
    else
        RESTRICT_DEFAULT=$(grep -E '^\s*restrict\s+default\s+' "${NTP_CONF}" 2>/dev/null \
                           | head -1 || true)
        info "Current : ${RESTRICT_DEFAULT:-[not set]}"
        echo ""

        ALL_FLAGS_PRESENT=1
        for flag in kod nomodify notrap nopeer noquery; do
            if ! echo "${RESTRICT_DEFAULT}" | grep -qw "${flag}"; then
                ALL_FLAGS_PRESENT=0
                warn "Missing flag : ${flag}"
            fi
        done

        if [[ "${ALL_FLAGS_PRESENT}" -eq 1 && -n "${RESTRICT_DEFAULT}" ]]; then
            pass "restrict default has all required flags."
        else
            fail "restrict default is missing required flags."
            info "Remediation: Updating restrict default in ${NTP_CONF} ..."
            backup_file "${NTP_CONF}"

            # Remove existing restrict default line and replace
            sed -i '/^\s*restrict\s\+default\s\+/d' "${NTP_CONF}"
            echo "restrict default ${REQUIRED_RESTRICT_FLAGS}" >> "${NTP_CONF}"

            if grep -qE "restrict default.*kod.*nomodify.*notrap.*nopeer.*noquery" \
                    "${NTP_CONF}" 2>/dev/null; then
                pass "restrict default updated successfully."
            else
                fail "Failed to update restrict default."
                mark_fail
            fi
        fi
    fi

    # ── Check 3: restrict -6 default (CIS audit command) ─────────────────────
    hdr "ntpd — restrict -6 default (IPv6)"
    info "Audit  : grep \"restrict -6 default\" ${NTP_CONF}"
    info "Expect : restrict -6 default kod nomodify notrap nopeer noquery"
    echo ""

    RESTRICT_V6=$(grep -E '^\s*restrict\s+-6\s+default\s+' "${NTP_CONF}" 2>/dev/null \
                  | head -1 || true)
    info "Current : ${RESTRICT_V6:-[not set]}"
    echo ""

    ALL_V6_FLAGS=1
    for flag in kod nomodify notrap nopeer noquery; do
        if ! echo "${RESTRICT_V6}" | grep -qw "${flag}"; then
            ALL_V6_FLAGS=0
            warn "Missing flag : ${flag}"
        fi
    done

    if [[ "${ALL_V6_FLAGS}" -eq 1 && -n "${RESTRICT_V6}" ]]; then
        pass "restrict -6 default has all required flags."
    else
        fail "restrict -6 default is missing required flags."
        info "Remediation: Updating restrict -6 default in ${NTP_CONF} ..."
        backup_file "${NTP_CONF}"
        sed -i '/^\s*restrict\s\+-6\s\+default\s\+/d' "${NTP_CONF}"
        echo "restrict -6 default ${REQUIRED_RESTRICT_FLAGS}" >> "${NTP_CONF}"

        if grep -qE "restrict -6 default.*kod.*nomodify.*notrap.*nopeer.*noquery" \
                "${NTP_CONF}" 2>/dev/null; then
            pass "restrict -6 default updated successfully."
        else
            fail "Failed to update restrict -6 default."
            mark_fail
        fi
    fi

    # ── Check 4: server entries (CIS audit command) ────────────────────────────
    hdr "ntpd — NTP Server Entries"
    info "Audit  : grep \"^server\" ${NTP_CONF}"
    echo ""

    SERVER_LINES=$(grep -E '^\s*server\s+' "${NTP_CONF}" 2>/dev/null || true)

    if [[ -n "${SERVER_LINES}" ]]; then
        pass "Server entries found in ${NTP_CONF}:"
        echo "${SERVER_LINES}" | sed 's/^/        /'
    else
        fail "No 'server' entries found in ${NTP_CONF}."
        info "Remediation: Adding default NTP servers ..."
        backup_file "${NTP_CONF}"
        {
            echo ""
            echo "# NTP servers added by 08_ntp.sh"
            echo "server 0.rhel.pool.ntp.org iburst"
            echo "server 1.rhel.pool.ntp.org iburst"
            echo "server 2.rhel.pool.ntp.org iburst"
            echo "server 3.rhel.pool.ntp.org iburst"
        } >> "${NTP_CONF}"
        pass "Default NTP servers added to ${NTP_CONF}."
    fi

    # ── Check 5: ntpd unprivileged user (CIS audit command) ───────────────────
    hdr "ntpd — Running as Unprivileged User (ntp:ntp)"
    info "Audit  : grep \"ntp:ntp\" ${NTP_SYSCONFIG}"
    info "Expect : OPTIONS=\"-u ntp:ntp -p /var/run/ntpd.pid\""
    echo ""

    if [[ ! -f "${NTP_SYSCONFIG}" ]]; then
        fail "${NTP_SYSCONFIG} not found."
        info "Remediation: Creating ${NTP_SYSCONFIG} ..."
        mkdir -p "$(dirname "${NTP_SYSCONFIG}")"
        echo 'OPTIONS="-u ntp:ntp -p /var/run/ntpd.pid"' > "${NTP_SYSCONFIG}"
        pass "${NTP_SYSCONFIG} created with OPTIONS=\"-u ntp:ntp -p /var/run/ntpd.pid\""
    else
        CURRENT_OPTIONS=$(grep -E '^\s*OPTIONS=' "${NTP_SYSCONFIG}" 2>/dev/null | head -1 || true)
        info "Current OPTIONS : ${CURRENT_OPTIONS:-[not set]}"
        echo ""

        if grep -qE '^\s*OPTIONS=.*-u\s+ntp:ntp' "${NTP_SYSCONFIG}" 2>/dev/null; then
            pass "ntpd is configured to run as ntp:ntp."
        else
            fail "ntpd OPTIONS does not include \"-u ntp:ntp\"."
            info "Remediation: Updating OPTIONS in ${NTP_SYSCONFIG} ..."
            backup_file "${NTP_SYSCONFIG}"

            if grep -qE '^\s*OPTIONS=' "${NTP_SYSCONFIG}"; then
                sed -i 's|^\s*OPTIONS=.*|OPTIONS="-u ntp:ntp -p /var/run/ntpd.pid"|' \
                    "${NTP_SYSCONFIG}"
            else
                echo 'OPTIONS="-u ntp:ntp -p /var/run/ntpd.pid"' >> "${NTP_SYSCONFIG}"
            fi

            if grep -qE '^\s*OPTIONS=.*-u\s+ntp:ntp' "${NTP_SYSCONFIG}"; then
                pass "OPTIONS updated — ntpd will run as ntp:ntp on next restart."
                info "Apply now: systemctl restart ntpd"
            else
                fail "Failed to update OPTIONS in ${NTP_SYSCONFIG}."
                mark_fail
            fi
        fi
    fi

    # ── Reload ntpd ────────────────────────────────────────────────────────────
    hdr "ntpd — Apply Configuration"
    if systemctl is-active ntpd &>/dev/null; then
        systemctl restart ntpd 2>/dev/null \
            && pass "ntpd restarted with updated configuration." \
            || warn "ntpd restart returned non-zero — check: journalctl -u ntpd"
    fi

fi   # end ntpd path

# =============================================================================
# Final state summary
# =============================================================================
hdr "Final NTP State"
echo ""

printf "  ${BOLD}%-35s${RESET} %s\n" "Implementation"     "${ACTIVE_IMPL}"

case "${ACTIVE_IMPL}" in
    chrony)
        CHRONY_STATUS=$(systemctl is-active chronyd 2>/dev/null || echo "unknown")
        CHRONY_ENABLED=$(systemctl is-enabled chronyd 2>/dev/null || echo "unknown")
        printf "  ${BOLD}%-35s${RESET} %s\n" "chronyd active"   "${CHRONY_STATUS}"
        printf "  ${BOLD}%-35s${RESET} %s\n" "chronyd enabled"  "${CHRONY_ENABLED}"
        printf "  ${BOLD}%-35s${RESET} %s\n" "Config file"      "${CHRONY_CONF}"
        ;;
    ntpd)
        NTPD_STATUS=$(systemctl is-active ntpd 2>/dev/null || echo "unknown")
        NTPD_ENABLED=$(systemctl is-enabled ntpd 2>/dev/null || echo "unknown")
        printf "  ${BOLD}%-35s${RESET} %s\n" "ntpd active"      "${NTPD_STATUS}"
        printf "  ${BOLD}%-35s${RESET} %s\n" "ntpd enabled"     "${NTPD_ENABLED}"
        printf "  ${BOLD}%-35s${RESET} %s\n" "Config file"      "${NTP_CONF}"
        printf "  ${BOLD}%-35s${RESET} %s\n" "Sysconfig file"   "${NTP_SYSCONFIG}"
        ;;
esac

echo ""
info "To verify time synchronisation:"
if [[ "${ACTIVE_IMPL}" == "chrony" ]]; then
    detail "chronyc tracking"
    detail "chronyc sources -v"
    detail "timedatectl show"
else
    detail "ntpq -p"
    detail "timedatectl show"
fi

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 08_ntp — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 08_ntp — ONE OR MORE CHECKS FAILED"
    exit 1
fi
