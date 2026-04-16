#!/usr/bin/env bash
# =============================================================================
# MODULE  : 04_remove_packages.sh
# TITLE   : Remove Unnecessary & Insecure Packages / Services
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Sections 2.1, 2.2, 3.x
#
# PACKAGES TARGETED:
#   Security Tools (legacy / insecure protocols):
#     - setroubleshoot          (SELinux troubleshoot daemon — attack surface)
#     - mcstrans                (MCS Translation Service — unnecessary)
#     - telnet-server           (cleartext remote login server)
#     - telnet                  (cleartext remote login client)
#     - rsh-server              (cleartext remote shell server)
#     - rsh                     (cleartext remote shell client)
#     - ypbind  / ypserv        (NIS client / NIS server — legacy, plaintext)
#     - tftp    / tftp-server   (trivial FTP — no auth, no encryption)
#     - talk    / talk-server   (legacy chat)
#     - xinetd                  (legacy super-server)
#     - xorg-x11-server-Xorg    (X Window System — not needed on servers)
#     - dhcp-server             (DHCP server — only needed on dedicated hosts)
#
# BEHAVIOUR:
#   - Audits each package with rpm -q
#   - Stops and disables the associated service before removal
#   - Removes via dnf if installed
#   - Verifies removal succeeded
#   - Produces a per-package PASS / FAIL / NOT_INSTALLED summary
#
# EXIT CODES:
#   0 — All targeted packages are absent (clean)
#   1 — One or more removals failed
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 04_remove_packages.sh
# =============================================================================

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

pass()   { echo -e "${GREEN}[PASS]${RESET}       $*"; }
fail()   { echo -e "${RED}[FAIL]${RESET}       $*"; }
removed(){ echo -e "${GREEN}[REMOVED]${RESET}    $*"; }
skip()   { echo -e "${DIM}[NOT FOUND]${RESET}  $*"; }
info()   { echo -e "${CYAN}[INFO]${RESET}       $*"; }
warn()   { echo -e "${YELLOW}[WARN]${RESET}       $*"; }
hdr()    { echo -e "\n${BOLD}── $* ──${RESET}"; }

OVERALL=0
mark_fail() { OVERALL=1; }

# Result tracking for summary table
declare -A PKG_RESULT   # pkg_name -> "ALREADY_ABSENT" | "REMOVED" | "FAILED"

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

if ! command -v dnf &>/dev/null; then
    fail "dnf not found — cannot remove packages."
    exit 2
fi

# =============================================================================
# Package definitions
#
# Format per entry (associative array):
#   KEY   = canonical package name (rpm -q key)
#   VALUE = "display_label|service_name_or_NONE"
#
# service_name is stopped/disabled before removal.
# Use NONE if there is no associated systemd service.
# =============================================================================

# Ordered list (preserves display sequence)
PKG_ORDER=(
    "setroubleshoot"
    "setroubleshoot-server"
    "mcstrans"
    "telnet-server"
    "telnet"
    "rsh-server"
    "rsh"
    "ypbind"
    "ypserv"
    "tftp"
    "tftp-server"
    "talk"
    "talk-server"
    "xinetd"
    "xorg-x11-server-Xorg"
    "dhcp-server"
)

# pkg -> "label|service"
declare -A PKG_META
PKG_META["setroubleshoot"]="SELinux Troubleshoot Daemon|setroubleshootd"
PKG_META["setroubleshoot-server"]="SELinux Troubleshoot Server|setroubleshoot"
PKG_META["mcstrans"]="MCS Translation Service|mcstrans"
PKG_META["telnet-server"]="Telnet Server|telnet.socket"
PKG_META["telnet"]="Telnet Client|NONE"
PKG_META["rsh-server"]="RSH Server|rsh.socket"
PKG_META["rsh"]="RSH Client|NONE"
PKG_META["ypbind"]="NIS Client (ypbind)|ypbind"
PKG_META["ypserv"]="NIS Server (ypserv)|ypserv"
PKG_META["tftp"]="TFTP Client|NONE"
PKG_META["tftp-server"]="TFTP Server|tftp.socket"
PKG_META["talk"]="Talk Client|NONE"
PKG_META["talk-server"]="Talk Server|ntalk.socket"
PKG_META["xinetd"]="xinetd Super-Server|xinetd"
PKG_META["xorg-x11-server-Xorg"]="X Window System Server|NONE"
PKG_META["dhcp-server"]="DHCP Server|dhcpd"

# =============================================================================
# Helper — stop and disable a service safely
# =============================================================================
stop_service() {
    local svc="${1}"
    [[ "${svc}" == "NONE" ]] && return 0

    if systemctl list-units --all --type=service,socket 2>/dev/null \
            | grep -q "${svc}"; then
        info "  Stopping  service : ${svc}"
        systemctl stop    "${svc}" 2>/dev/null || true
        info "  Disabling service : ${svc}"
        systemctl disable "${svc}" 2>/dev/null || true
        systemctl mask    "${svc}" 2>/dev/null || true
    else
        info "  Service not active or not found : ${svc} (skip stop)"
    fi
}

# =============================================================================
# Helper — audit + remove a single package
# =============================================================================
process_package() {
    local pkg="${1}"
    local meta="${PKG_META[${pkg}]}"
    local label="${meta%%|*}"
    local svc="${meta##*|}"

    echo ""
    hdr "${label} (${pkg})"
    info "Audit : rpm -q ${pkg}"

    # ── Audit ──────────────────────────────────────────────────────────────────
    if ! rpm -q "${pkg}" &>/dev/null; then
        skip "${pkg} is not installed — no action needed."
        PKG_RESULT["${pkg}"]="ALREADY_ABSENT"
        return
    fi

    INSTALLED_VER=$(rpm -q --queryformat "%{VERSION}-%{RELEASE}" "${pkg}" 2>/dev/null)
    fail "${pkg} is installed (${INSTALLED_VER}) — must be removed."

    # ── Stop service before removal ────────────────────────────────────────────
    stop_service "${svc}"

    # ── Remediation ────────────────────────────────────────────────────────────
    info "  Remediation : dnf remove -y ${pkg}"

    if dnf remove -y "${pkg}" &>/dev/null; then
        # Verify removal
        if rpm -q "${pkg}" &>/dev/null; then
            fail "  Package still present after dnf remove — manual intervention required."
            PKG_RESULT["${pkg}"]="FAILED"
            mark_fail
        else
            removed "${pkg} removed successfully."
            PKG_RESULT["${pkg}"]="REMOVED"
        fi
    else
        fail "  dnf remove ${pkg} returned non-zero exit code."
        PKG_RESULT["${pkg}"]="FAILED"
        mark_fail
    fi
}

# =============================================================================
# Process all packages
# =============================================================================
hdr "Starting Package Removal Audit"
info "Packages to audit : ${#PKG_ORDER[@]}"

for pkg in "${PKG_ORDER[@]}"; do
    process_package "${pkg}"
done

# =============================================================================
# Additional service hardening — disable xinetd-managed services if xinetd
# was installed (belt-and-suspenders)
# =============================================================================
hdr "Legacy inetd / xinetd Service Check"
info "Audit : chkconfig --list (if available)"

XINETD_SERVICES=(
    "chargen-dgram" "chargen-stream"
    "daytime-dgram" "daytime-stream"
    "discard-dgram" "discard-stream"
    "echo-dgram"    "echo-stream"
    "time-dgram"    "time-stream"
    "finger"        "ntalk"
)

XINETD_FOUND=0
for xsvc in "${XINETD_SERVICES[@]}"; do
    if systemctl list-units --all 2>/dev/null | grep -q "${xsvc}"; then
        warn "Legacy inetd service detected: ${xsvc} — disabling."
        systemctl stop    "${xsvc}" 2>/dev/null || true
        systemctl disable "${xsvc}" 2>/dev/null || true
        systemctl mask    "${xsvc}" 2>/dev/null || true
        XINETD_FOUND=1
    fi
done

if [[ "${XINETD_FOUND}" -eq 0 ]]; then
    pass "No legacy inetd/xinetd services detected."
fi

# =============================================================================
# X Window System — also disable graphical target if set
# =============================================================================
hdr "X Window System — Graphical Target"
info "Audit : systemctl get-default"

CURRENT_TARGET=$(systemctl get-default 2>/dev/null || echo "unknown")
info "Current default target : ${CURRENT_TARGET}"

if [[ "${CURRENT_TARGET}" == "graphical.target" ]]; then
    fail "System default target is graphical.target — servers should use multi-user.target."
    info "Remediation: Setting default target to multi-user.target ..."
    systemctl set-default multi-user.target
    pass "Default target set to multi-user.target."
elif [[ "${CURRENT_TARGET}" == "multi-user.target" ]]; then
    pass "Default target is multi-user.target (correct for a server)."
else
    info "Default target is '${CURRENT_TARGET}' — no change made."
fi

# =============================================================================
# Summary Table
# =============================================================================
echo ""
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║          PACKAGE REMOVAL SUMMARY                            ║${RESET}"
echo -e "${BOLD}╠══════════════════════════════════════════╦═══════════════════╣${RESET}"
printf "${BOLD}║  %-40s ║ %-17s ║${RESET}\n" "PACKAGE" "STATUS"
echo -e "${BOLD}╠══════════════════════════════════════════╬═══════════════════╣${RESET}"

COUNT_ABSENT=0
COUNT_REMOVED=0
COUNT_FAILED=0

for pkg in "${PKG_ORDER[@]}"; do
    result="${PKG_RESULT[${pkg}]:-FAILED}"
    meta="${PKG_META[${pkg}]}"
    label="${meta%%|*}"

    case "${result}" in
        ALREADY_ABSENT)
            STATUS_STR="${DIM}Not installed  ${RESET}"
            (( COUNT_ABSENT++ )) || true
            ;;
        REMOVED)
            STATUS_STR="${GREEN}Removed ✓      ${RESET}"
            (( COUNT_REMOVED++ )) || true
            ;;
        FAILED)
            STATUS_STR="${RED}FAILED ✗       ${RESET}"
            (( COUNT_FAILED++ )) || true
            ;;
    esac

    printf "║  %-40s ║ %b%-18s${RESET} ║\n" "${label:0:40}" "" "${result}"
done

echo -e "${BOLD}╠══════════════════════════════════════════╩═══════════════════╣${RESET}"

TOTAL=${#PKG_ORDER[@]}
printf "${BOLD}║  %-62s ║${RESET}\n" "Total packages audited : ${TOTAL}"
printf "${GREEN}${BOLD}║  %-62s ║${RESET}\n" "Already absent         : ${COUNT_ABSENT}"
printf "${GREEN}${BOLD}║  %-62s ║${RESET}\n" "Removed this run       : ${COUNT_REMOVED}"

if [[ "${COUNT_FAILED}" -gt 0 ]]; then
    printf "${RED}${BOLD}║  %-62s ║${RESET}\n" "Failed to remove       : ${COUNT_FAILED}"
else
    printf "║  %-62s ║\n" "Failed to remove       : ${COUNT_FAILED}"
fi

echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 04_remove_packages — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 04_remove_packages — ONE OR MORE REMOVALS FAILED"
    exit 1
fi
