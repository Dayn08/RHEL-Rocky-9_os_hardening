#!/usr/bin/env bash
# =============================================================================
# MODULE  : 07_disable_legacy_sockets.sh
# TITLE   : Disable Legacy inetd / Socket Services
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 2.1 (inetd Services)
#
# BACKGROUND:
#   These are legacy network services originally managed by inetd/xinetd that
#   serve no purpose on a modern server. They expose unnecessary network
#   attack surface and should be disabled and masked:
#
#   chargen-dgram   — Character Generator (UDP) : streams random characters,
#                     can be used in UDP amplification / reflection DDoS attacks
#   chargen-stream  — Character Generator (TCP) : same as above over TCP
#   daytime-dgram   — Daytime Protocol (UDP, RFC 867) : returns current time
#                     as plaintext, superseded by NTP/chrony
#   daytime-stream  — Daytime Protocol (TCP) : same as above over TCP
#   echo-dgram      — Echo Protocol (UDP, RFC 862) : reflects data back to
#                     sender, used in UDP amplification attacks
#   echo-stream     — Echo Protocol (TCP) : same as above over TCP
#   tcpmux-server   — TCP Port Service Multiplexer (RFC 1078, port 1) :
#                     legacy multiplexer with no modern use case
#
# AUDIT COMMAND (CIS reference, per service):
#   systemctl status <service>.socket
#   Expected: inactive (dead) or not-found
#
# CHECKS (per socket unit):
#   1.  Socket unit is not active (not listening)
#   2.  Socket unit is not enabled (won't start on boot)
#   3.  Socket unit is masked (cannot be started accidentally)
#
# EXIT CODES:
#   0 — All targeted sockets are inactive / masked / not present
#   1 — One or more sockets could not be disabled
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 07_disable_legacy_sockets.sh
# =============================================================================

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

pass()   { echo -e "${GREEN}[PASS]${RESET}      $*"; }
fail()   { echo -e "${RED}[FAIL]${RESET}      $*"; }
info()   { echo -e "${CYAN}[INFO]${RESET}      $*"; }
warn()   { echo -e "${YELLOW}[WARN]${RESET}      $*"; }
skipped(){ echo -e "${DIM}[NOT FOUND]${RESET} $*"; }
hdr()    { echo -e "\n${BOLD}── $* ──${RESET}"; }
detail() { echo -e "        ${DIM}$*${RESET}"; }

OVERALL=0
mark_fail() { OVERALL=1; }

# ── Result tracking ────────────────────────────────────────────────────────────
# socket_name -> "NOT_FOUND" | "ALREADY_DISABLED" | "DISABLED" | "FAILED"
declare -A SOCKET_RESULT

# =============================================================================
# Socket definitions
#
# Format: "socket_unit_name|display_label|port|protocol|rfc"
# =============================================================================
SOCKET_ORDER=(
    "chargen-dgram"
    "chargen-stream"
    "daytime-dgram"
    "daytime-stream"
    "echo-dgram"
    "echo-stream"
    "tcpmux-server"
)

declare -A SOCKET_META
SOCKET_META["chargen-dgram"]="Character Generator (UDP)|19|UDP|RFC 864"
SOCKET_META["chargen-stream"]="Character Generator (TCP)|19|TCP|RFC 864"
SOCKET_META["daytime-dgram"]="Daytime Protocol (UDP)|13|UDP|RFC 867"
SOCKET_META["daytime-stream"]="Daytime Protocol (TCP)|13|TCP|RFC 867"
SOCKET_META["echo-dgram"]="Echo Protocol (UDP)|7|UDP|RFC 862"
SOCKET_META["echo-stream"]="Echo Protocol (TCP)|7|TCP|RFC 862"
SOCKET_META["tcpmux-server"]="TCP Port Multiplexer|1|TCP|RFC 1078"

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
# Helper — full audit + disable cycle for a single socket unit
# =============================================================================
process_socket() {
    local unit_base="${1}"
    local unit="${unit_base}.socket"
    local meta="${SOCKET_META[${unit_base}]}"
    local label port proto rfc
    IFS='|' read -r label port proto rfc <<< "${meta}"

    echo ""
    hdr "${label}  [${unit}]"
    info "Audit  : systemctl status ${unit}"
    detail "Port ${port}/${proto} — ${rfc}"
    echo ""

    # ── Check if the unit is known to systemd at all ──────────────────────────
    # systemctl status returns exit 4 for "unit not found"
    STATUS_EXIT=0
    STATUS_OUT=$(systemctl status "${unit}" 2>&1) || STATUS_EXIT=$?

    if [[ "${STATUS_EXIT}" -eq 4 ]] || \
       echo "${STATUS_OUT}" | grep -qiE "could not be found|no such unit|not-found"; then
        skipped "${unit} — unit not found on this system (package not installed)."
        SOCKET_RESULT["${unit_base}"]="NOT_FOUND"
        return
    fi

    # ── Parse current state ───────────────────────────────────────────────────
    ACTIVE_STATE=$(systemctl is-active  "${unit}" 2>/dev/null || echo "inactive")
    ENABLED_STATE=$(systemctl is-enabled "${unit}" 2>/dev/null || echo "disabled")

    info "Active  : ${ACTIVE_STATE}"
    info "Enabled : ${ENABLED_STATE}"

    # ── Already clean? ────────────────────────────────────────────────────────
    if [[ "${ACTIVE_STATE}"  == "inactive" || "${ACTIVE_STATE}"  == "dead" ]] && \
       [[ "${ENABLED_STATE}" == "masked"   || "${ENABLED_STATE}" == "disabled" ]]; then
        pass "${unit} is already inactive and disabled/masked."
        SOCKET_RESULT["${unit_base}"]="ALREADY_DISABLED"
        return
    fi

    # ── Remediation ───────────────────────────────────────────────────────────
    fail "${unit} is ${ACTIVE_STATE} / ${ENABLED_STATE} — must be disabled and masked."
    echo ""
    info "Remediation:"

    # Stop if active
    if [[ "${ACTIVE_STATE}" == "active" ]]; then
        info "  Stopping  : systemctl stop ${unit}"
        if systemctl stop "${unit}" 2>/dev/null; then
            info "  Stopped."
        else
            warn "  Could not stop ${unit} — it may have already stopped."
        fi
    fi

    # Disable if enabled
    if [[ "${ENABLED_STATE}" != "disabled" && "${ENABLED_STATE}" != "masked" ]]; then
        info "  Disabling : systemctl disable ${unit}"
        systemctl disable "${unit}" 2>/dev/null || true
    fi

    # Mask unconditionally — prevents accidental re-enablement
    info "  Masking   : systemctl mask ${unit}"
    if systemctl mask "${unit}" 2>/dev/null; then
        info "  Masked."
    else
        warn "  Could not mask ${unit} — may not be a real unit file."
    fi

    # ── Verify post-remediation ───────────────────────────────────────────────
    echo ""
    FINAL_ACTIVE=$(systemctl is-active  "${unit}" 2>/dev/null || echo "inactive")
    FINAL_ENABLED=$(systemctl is-enabled "${unit}" 2>/dev/null || echo "disabled")

    info "Post-remediation — Active: ${FINAL_ACTIVE} | Enabled: ${FINAL_ENABLED}"

    if [[ "${FINAL_ACTIVE}"  == "inactive" || "${FINAL_ACTIVE}"  == "dead"   ]] && \
       [[ "${FINAL_ENABLED}" == "masked"   || "${FINAL_ENABLED}" == "disabled" ]]; then
        pass "${unit} successfully disabled and masked."
        SOCKET_RESULT["${unit_base}"]="DISABLED"
    else
        fail "Could not fully disable ${unit} — manual intervention required."
        SOCKET_RESULT["${unit_base}"]="FAILED"
        mark_fail
    fi
}

# =============================================================================
# Process all sockets
# =============================================================================
hdr "Starting Legacy Socket Audit"
info "Sockets to audit : ${#SOCKET_ORDER[@]}"

for svc in "${SOCKET_ORDER[@]}"; do
    process_socket "${svc}"
done

# =============================================================================
# Also check for xinetd-managed versions of these services
# (some older RHEL environments manage them via xinetd config files)
# =============================================================================
hdr "xinetd Config Check (belt-and-suspenders)"
info "Audit  : checking /etc/xinetd.d/ for enabled legacy services"
echo ""

XINETD_DIR="/etc/xinetd.d"
XINETD_SERVICES=("chargen" "daytime" "echo" "tcpmux")
XINETD_FOUND=0

if [[ ! -d "${XINETD_DIR}" ]]; then
    pass "${XINETD_DIR} does not exist — xinetd not configured."
else
    for xsvc in "${XINETD_SERVICES[@]}"; do
        for variant in "${xsvc}" "${xsvc}-stream" "${xsvc}-dgram"; do
            cfg="${XINETD_DIR}/${variant}"
            if [[ -f "${cfg}" ]]; then
                # Check if disable = yes is set
                if grep -qiE '^\s*disable\s*=\s*yes' "${cfg}" 2>/dev/null; then
                    pass "${cfg} — disable = yes (already configured correctly)"
                else
                    fail "${cfg} exists and is NOT disabled."
                    info "  Remediation: Setting disable = yes in ${cfg} ..."
                    # Backup before edit
                    cp "${cfg}" "${cfg}.bak.$(date +%Y%m%d%H%M%S)"
                    if grep -qiE '^\s*disable\s*=' "${cfg}"; then
                        sed -i 's/^\s*disable\s*=.*/\tdisable\t\t\t= yes/' "${cfg}"
                    else
                        # Add disable line inside the service block
                        sed -i '/^{/a \\tdisable\t\t\t= yes' "${cfg}"
                    fi
                    pass "  ${cfg} — disable = yes set."
                    XINETD_FOUND=1
                fi
            fi
        done
    done

    if [[ "${XINETD_FOUND}" -eq 0 ]]; then
        pass "No active legacy services found in ${XINETD_DIR}/"
    else
        info "If xinetd is running, reload it: systemctl reload xinetd"
    fi
fi

# =============================================================================
# Summary Table
# =============================================================================
echo ""
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║         LEGACY SOCKET SERVICE SUMMARY                               ║${RESET}"
echo -e "${BOLD}╠══════════════════════════════════╦═══════════╦═══════╦══════════════╣${RESET}"
printf "${BOLD}║  %-30s ║ %-9s ║ %-5s ║ %-12s ║${RESET}\n" \
    "SOCKET UNIT" "PROTOCOL" "PORT" "STATUS"
echo -e "${BOLD}╠══════════════════════════════════╬═══════════╬═══════╬══════════════╣${RESET}"

COUNT_NOT_FOUND=0
COUNT_ALREADY=0
COUNT_DISABLED=0
COUNT_FAILED=0

for svc in "${SOCKET_ORDER[@]}"; do
    result="${SOCKET_RESULT[${svc}]:-FAILED}"
    meta="${SOCKET_META[${svc}]}"
    IFS='|' read -r label port proto rfc <<< "${meta}"

    case "${result}" in
        NOT_FOUND)
            STATUS_STR="Not found   "
            (( COUNT_NOT_FOUND++ )) || true
            ;;
        ALREADY_DISABLED)
            STATUS_STR="Was clean   "
            (( COUNT_ALREADY++ )) || true
            ;;
        DISABLED)
            STATUS_STR="Disabled ✓  "
            (( COUNT_DISABLED++ )) || true
            ;;
        FAILED)
            STATUS_STR="FAILED ✗    "
            (( COUNT_FAILED++ )) || true
            ;;
    esac

    printf "║  %-30s ║ %-9s ║ %-5s ║ %s ║\n" \
        "${svc}.socket" "${proto}" "${port}" "${result}"
done

echo -e "${BOLD}╠══════════════════════════════════╩═══════════╩═══════╩══════════════╣${RESET}"

TOTAL=${#SOCKET_ORDER[@]}
printf "${BOLD}║  %-68s ║${RESET}\n" "Total audited   : ${TOTAL}"
printf "║  %-68s ║\n" "Not found       : ${COUNT_NOT_FOUND}"
printf "║  %-68s ║\n" "Already clean   : ${COUNT_ALREADY}"
printf "${GREEN}${BOLD}║  %-68s ║${RESET}\n" "Disabled now    : ${COUNT_DISABLED}"
if [[ "${COUNT_FAILED}" -gt 0 ]]; then
    printf "${RED}${BOLD}║  %-68s ║${RESET}\n" "Failed          : ${COUNT_FAILED}"
else
    printf "║  %-68s ║\n" "Failed          : ${COUNT_FAILED}"
fi
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════╝${RESET}"

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 07_disable_legacy_sockets — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 07_disable_legacy_sockets — ONE OR MORE SOCKETS COULD NOT BE DISABLED"
    exit 1
fi
