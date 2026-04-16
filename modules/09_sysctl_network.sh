#!/usr/bin/env bash
# =============================================================================
# MODULE  : 09_sysctl_network.sh
# TITLE   : Network Kernel Parameter Hardening (sysctl)
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 3.1 - 3.2 (Network Configuration)
#
# BACKGROUND:
#   These kernel parameters control how the system handles network traffic
#   at the IP layer. Incorrect settings can expose the host to:
#     - Routing attacks (IP forwarding, source routing)
#     - ICMP redirect attacks (MITM via routing table manipulation)
#     - Smurf / amplification DDoS attacks (broadcast ICMP)
#     - TCP SYN flood denial-of-service attacks
#     - Spoofed packet injection (reverse path filtering)
#
# PARAMETERS HARDENED:
#   net.ipv4.ip_forward                        = 0  (disable IP forwarding)
#   net.ipv4.conf.all.send_redirects           = 0  (no ICMP redirects sent)
#   net.ipv4.conf.default.send_redirects       = 0
#   net.ipv4.conf.all.accept_source_route      = 0  (no source-routed packets)
#   net.ipv4.conf.default.accept_source_route  = 0
#   net.ipv4.conf.all.accept_redirects         = 0  (no ICMP redirects accepted)
#   net.ipv4.conf.default.accept_redirects     = 0
#   net.ipv4.conf.all.secure_redirects         = 0  (no secure ICMP redirects)
#   net.ipv4.conf.default.secure_redirects     = 0
#   net.ipv4.conf.all.log_martians             = 1  (log spoofed/bogus packets)
#   net.ipv4.conf.default.log_martians         = 1
#   net.ipv4.icmp_echo_ignore_broadcasts       = 1  (ignore broadcast pings)
#   net.ipv4.icmp_ignore_bogus_error_responses = 1  (ignore bogus ICMP errors)
#   net.ipv4.conf.all.rp_filter                = 1  (reverse path filtering)
#   net.ipv4.conf.default.rp_filter            = 1
#   net.ipv4.tcp_syncookies                    = 1  (SYN flood protection)
#
# AUDIT COMMAND (CIS reference per parameter):
#   /sbin/sysctl <parameter>
#   Expected values shown above.
#
# BEHAVIOUR:
#   - Audits every parameter using /sbin/sysctl
#   - Auto-remediates non-compliant values at runtime with sysctl -w
#   - Persists all settings to /etc/sysctl.d/62-network-hardening.conf
#   - Scans all other sysctl files for conflicting overrides and removes them
#   - Re-runs the CIS audit commands after remediation to confirm compliance
#
# EXIT CODES:
#   0 — All parameters compliant (or remediated successfully)
#   1 — One or more parameters could not be set
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 09_sysctl_network.sh
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

SYSCTL_DROP_IN="/etc/sysctl.d/62-network-hardening.conf"

# ── Result tracking ────────────────────────────────────────────────────────────
# param -> "PASS" | "REMEDIATED" | "FAILED"
declare -A PARAM_RESULT
declare -A PARAM_FOUND_VAL

# ── Helper: backup a file ──────────────────────────────────────────────────────
backup_file() {
    local f="${1}"
    [[ -f "${f}" ]] || return 0
    cp "${f}" "${f}.bak.$(date +%Y%m%d%H%M%S)"
    info "  Backup : ${f}.bak.*"
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

if ! command -v sysctl &>/dev/null; then
    fail "sysctl not found."
    exit 1
fi

# =============================================================================
# Parameter table
#
# Format per entry:  "param|required_value|section_title|cis_context"
# =============================================================================
declare -a PARAM_ORDER
declare -A PARAM_META

# ── Section: IP Forwarding ───────────────────────────────────────────────────
PARAM_ORDER+=("net.ipv4.ip_forward")
PARAM_META["net.ipv4.ip_forward"]="0|Disable IP Forwarding|Prevents the host acting as a router. A server should never forward packets between interfaces unless it is a designated gateway."

# ── Section: Send Packet Redirects ───────────────────────────────────────────
PARAM_ORDER+=("net.ipv4.conf.all.send_redirects")
PARAM_META["net.ipv4.conf.all.send_redirects"]="0|Disable Send Packet Redirects (all)|ICMP redirects sent to other hosts can be used to alter their routing tables. Only a router should send them."

PARAM_ORDER+=("net.ipv4.conf.default.send_redirects")
PARAM_META["net.ipv4.conf.default.send_redirects"]="0|Disable Send Packet Redirects (default)|Applies the restriction to interfaces that do not have an explicit setting."

# ── Section: Source Routed Packet Acceptance ─────────────────────────────────
PARAM_ORDER+=("net.ipv4.conf.all.accept_source_route")
PARAM_META["net.ipv4.conf.all.accept_source_route"]="0|Disable Source Routed Packet Acceptance (all)|Source routing lets an attacker dictate the path a packet takes, bypassing firewalls."

PARAM_ORDER+=("net.ipv4.conf.default.accept_source_route")
PARAM_META["net.ipv4.conf.default.accept_source_route"]="0|Disable Source Routed Packet Acceptance (default)|Applies to new interfaces that inherit the default policy."

# ── Section: ICMP Redirect Acceptance ────────────────────────────────────────
PARAM_ORDER+=("net.ipv4.conf.all.accept_redirects")
PARAM_META["net.ipv4.conf.all.accept_redirects"]="0|Disable ICMP Redirect Acceptance (all)|Accepting ICMP redirects allows a remote host to alter the system routing table — classic MITM vector."

PARAM_ORDER+=("net.ipv4.conf.default.accept_redirects")
PARAM_META["net.ipv4.conf.default.accept_redirects"]="0|Disable ICMP Redirect Acceptance (default)|Covers interfaces not explicitly configured."

# ── Section: Secure ICMP Redirect Acceptance ─────────────────────────────────
PARAM_ORDER+=("net.ipv4.conf.all.secure_redirects")
PARAM_META["net.ipv4.conf.all.secure_redirects"]="0|Disable Secure ICMP Redirect Acceptance (all)|'Secure' redirects only accepted from listed gateways — still exploitable if the gateway is compromised."

PARAM_ORDER+=("net.ipv4.conf.default.secure_redirects")
PARAM_META["net.ipv4.conf.default.secure_redirects"]="0|Disable Secure ICMP Redirect Acceptance (default)|Applies the same restriction to the default interface policy."

# ── Section: Log Suspicious Packets ──────────────────────────────────────────
PARAM_ORDER+=("net.ipv4.conf.all.log_martians")
PARAM_META["net.ipv4.conf.all.log_martians"]="1|Log Suspicious Packets — log_martians (all)|Logs packets with impossible source addresses (martians). Essential for detecting spoofing attempts."

PARAM_ORDER+=("net.ipv4.conf.default.log_martians")
PARAM_META["net.ipv4.conf.default.log_martians"]="1|Log Suspicious Packets — log_martians (default)|Ensures martian logging applies to new interfaces at bring-up."

# ── Section: Ignore Broadcast Requests ───────────────────────────────────────
PARAM_ORDER+=("net.ipv4.icmp_echo_ignore_broadcasts")
PARAM_META["net.ipv4.icmp_echo_ignore_broadcasts"]="1|Enable Ignore Broadcast Requests|Prevents Smurf DDoS attacks where broadcast ping is used to amplify traffic toward a victim."

# ── Section: Bad Error Message Protection ────────────────────────────────────
PARAM_ORDER+=("net.ipv4.icmp_ignore_bogus_error_responses")
PARAM_META["net.ipv4.icmp_ignore_bogus_error_responses"]="1|Enable Bad Error Message Protection|Ignores invalid ICMP error responses that violate RFC 1122 — reduces noise and potential DoS."

# ── Section: Reverse Path Filtering ──────────────────────────────────────────
PARAM_ORDER+=("net.ipv4.conf.all.rp_filter")
PARAM_META["net.ipv4.conf.all.rp_filter"]="1|Enable RFC Source Route Validation — rp_filter (all)|Reverse path filtering drops packets whose source address is not reachable via the interface they arrived on. Prevents IP spoofing."

PARAM_ORDER+=("net.ipv4.conf.default.rp_filter")
PARAM_META["net.ipv4.conf.default.rp_filter"]="1|Enable RFC Source Route Validation — rp_filter (default)|Applies strict RPF to new interfaces when they come up."

# ── Section: TCP SYN Cookies ──────────────────────────────────────────────────
PARAM_ORDER+=("net.ipv4.tcp_syncookies")
PARAM_META["net.ipv4.tcp_syncookies"]="1|Enable TCP SYN Cookies|SYN cookies protect against SYN flood attacks by encoding connection state in the ISN, removing the need for a listen backlog entry until the handshake completes."

# =============================================================================
# Helper — audit and remediate a single sysctl parameter
# =============================================================================
process_param() {
    local param="${1}"
    local meta="${PARAM_META[${param}]}"
    local required_val section_title context
    IFS='|' read -r required_val section_title context <<< "${meta}"

    echo ""
    hdr "${section_title}"
    info "Audit  : /sbin/sysctl ${param}"
    info "Expect : ${param} = ${required_val}"
    detail "${context}"
    echo ""

    # ── Read current runtime value ─────────────────────────────────────────
    CURRENT_VAL=$(sysctl -n "${param}" 2>/dev/null || echo "ERROR")
    PARAM_FOUND_VAL["${param}"]="${CURRENT_VAL}"

    info "Current : ${param} = ${CURRENT_VAL}"

    # ── Evaluate ───────────────────────────────────────────────────────────
    if [[ "${CURRENT_VAL}" == "${required_val}" ]]; then
        pass "${param} = ${CURRENT_VAL} ✓"
        PARAM_RESULT["${param}"]="PASS"
        return
    fi

    # ── Remediate runtime ──────────────────────────────────────────────────
    fail "${param} = ${CURRENT_VAL} (expected ${required_val})"
    info "Remediation: sysctl -w ${param}=${required_val}"

    if sysctl -w "${param}=${required_val}" &>/dev/null; then
        VERIFY=$(sysctl -n "${param}" 2>/dev/null || echo "ERROR")
        if [[ "${VERIFY}" == "${required_val}" ]]; then
            pass "Runtime value updated : ${param} = ${VERIFY}"
            PARAM_RESULT["${param}"]="REMEDIATED"
        else
            fail "sysctl -w ran but value is still ${VERIFY} — kernel may reject this."
            PARAM_RESULT["${param}"]="FAILED"
            mark_fail
        fi
    else
        fail "sysctl -w ${param}=${required_val} returned non-zero."
        PARAM_RESULT["${param}"]="FAILED"
        mark_fail
    fi
}

# =============================================================================
# Run all parameter checks
# =============================================================================
hdr "Starting Network Parameter Audit (${#PARAM_ORDER[@]} parameters)"

for param in "${PARAM_ORDER[@]}"; do
    process_param "${param}"
done

# =============================================================================
# Persist all settings to sysctl.d drop-in
# =============================================================================
hdr "Persisting Settings to ${SYSCTL_DROP_IN}"
info "Writing all ${#PARAM_ORDER[@]} parameters to drop-in file ..."
echo ""

mkdir -p "$(dirname "${SYSCTL_DROP_IN}")"
backup_file "${SYSCTL_DROP_IN}"

cat > "${SYSCTL_DROP_IN}" << 'SYSCTLEOF'
# /etc/sysctl.d/62-network-hardening.conf
# Network kernel parameter hardening
# Generated by 09_sysctl_network.sh — CIS RHEL9 Benchmark Section 3.1-3.2
# ─────────────────────────────────────────────────────────────────────────────

# ── IP Forwarding ─────────────────────────────────────────────────────────────
# 0 = this host does not route packets between interfaces (not a router)
net.ipv4.ip_forward = 0

# ── Send Packet Redirects ─────────────────────────────────────────────────────
# 0 = do not send ICMP redirect messages to other hosts
net.ipv4.conf.all.send_redirects     = 0
net.ipv4.conf.default.send_redirects = 0

# ── Source Routed Packet Acceptance ──────────────────────────────────────────
# 0 = reject packets that specify their own route (source routing)
net.ipv4.conf.all.accept_source_route     = 0
net.ipv4.conf.default.accept_source_route = 0

# ── ICMP Redirect Acceptance ──────────────────────────────────────────────────
# 0 = do not accept ICMP redirect messages (routing table manipulation)
net.ipv4.conf.all.accept_redirects     = 0
net.ipv4.conf.default.accept_redirects = 0

# ── Secure ICMP Redirect Acceptance ──────────────────────────────────────────
# 0 = reject even 'trusted gateway' ICMP redirects
net.ipv4.conf.all.secure_redirects     = 0
net.ipv4.conf.default.secure_redirects = 0

# ── Log Martians (suspicious / spoofed packets) ───────────────────────────────
# 1 = log packets with unrouteable source addresses to kernel log
net.ipv4.conf.all.log_martians     = 1
net.ipv4.conf.default.log_martians = 1

# ── Ignore Broadcast ICMP (Smurf DDoS protection) ────────────────────────────
# 1 = ignore ICMP echo requests to broadcast / multicast addresses
net.ipv4.icmp_echo_ignore_broadcasts = 1

# ── Bogus ICMP Error Message Protection ──────────────────────────────────────
# 1 = ignore invalid ICMP error responses violating RFC 1122
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ── Reverse Path Filtering (anti-spoofing) ────────────────────────────────────
# 1 = strict mode — drop packets whose source is not reachable via the
#     interface they arrived on (prevents IP spoofing)
net.ipv4.conf.all.rp_filter     = 1
net.ipv4.conf.default.rp_filter = 1

# ── TCP SYN Cookies (SYN flood protection) ───────────────────────────────────
# 1 = enable SYN cookies when the SYN backlog overflows
net.ipv4.tcp_syncookies = 1
SYSCTLEOF

chmod 644 "${SYSCTL_DROP_IN}"
chown root:root "${SYSCTL_DROP_IN}"

# Apply the drop-in
if sysctl -p "${SYSCTL_DROP_IN}" &>/dev/null; then
    pass "All parameters applied from ${SYSCTL_DROP_IN}"
else
    warn "sysctl -p reported warnings — check file content."
fi

# =============================================================================
# Scan for conflicting overrides in other sysctl files
# =============================================================================
hdr "Conflicting sysctl Override Scan"
info "Scanning /etc/sysctl.conf and /etc/sysctl.d/*.conf for conflicts ..."
echo ""

CONFLICT_FOUND=0

while IFS= read -r -d '' src_file; do
    # Skip our own drop-in
    [[ "${src_file}" == "${SYSCTL_DROP_IN}" ]] && continue

    for param in "${PARAM_ORDER[@]}"; do
        required_val="${PARAM_META[${param}]%%|*}"

        MATCH=$(grep -E "^\s*${param//./\\.}\s*=" "${src_file}" 2>/dev/null || true)
        if [[ -n "${MATCH}" ]]; then
            FILE_VAL=$(echo "${MATCH}" | awk -F= '{print $2}' | tr -d ' \t' | tail -1)
            if [[ "${FILE_VAL}" != "${required_val}" ]]; then
                warn "Conflict: ${param} = ${FILE_VAL} in ${src_file} (expected ${required_val})"
                backup_file "${src_file}"
                # Escape dots for sed
                PARAM_ESC="${param//./\\.}"
                sed -i "/^\s*${PARAM_ESC}\s*=/d" "${src_file}"
                info "  Removed conflicting entry from ${src_file}"
                CONFLICT_FOUND=1
            fi
        fi
    done
done < <(find /etc/sysctl.d/ -maxdepth 1 -name "*.conf" -print0 2>/dev/null; \
         [[ -f /etc/sysctl.conf ]] && printf '%s\0' /etc/sysctl.conf)

if [[ "${CONFLICT_FOUND}" -eq 0 ]]; then
    pass "No conflicting overrides found in other sysctl files."
fi

# =============================================================================
# CIS Re-verification — run exact audit commands post-remediation
# =============================================================================
hdr "CIS Audit Verification (post-remediation)"
info "Re-running /sbin/sysctl for all parameters ..."
echo ""

printf "  ${BOLD}%-50s  %-10s  %-10s  %-10s${RESET}\n" \
    "PARAMETER" "EXPECTED" "FOUND" "STATUS"
printf "  %s\n" "$(printf '─%.0s' {1..90})"

VERIFY_PASS=0
VERIFY_FAIL=0

for param in "${PARAM_ORDER[@]}"; do
    required_val="${PARAM_META[${param}]%%|*}"
    LIVE_VAL=$(/sbin/sysctl -n "${param}" 2>/dev/null || echo "ERROR")

    if [[ "${LIVE_VAL}" == "${required_val}" ]]; then
        STATUS="${GREEN}PASS${RESET}"
        (( VERIFY_PASS++ )) || true
    else
        STATUS="${RED}FAIL${RESET}"
        (( VERIFY_FAIL++ )) || true
        mark_fail
    fi

    printf "  %-50s  %-10s  %-10s  " "${param}" "${required_val}" "${LIVE_VAL}"
    echo -e "${STATUS}"
done

echo ""
printf "  %s\n" "$(printf '─%.0s' {1..90})"
printf "  ${GREEN}${BOLD}PASS: %-3s${RESET}   ${RED}${BOLD}FAIL: %-3s${RESET}\n" \
    "${VERIFY_PASS}" "${VERIFY_FAIL}"

# =============================================================================
# Summary Table
# =============================================================================
hdr "Run Summary"
echo ""

COUNT_PASS=0
COUNT_REMEDIATED=0
COUNT_FAILED=0

for param in "${PARAM_ORDER[@]}"; do
    result="${PARAM_RESULT[${param}]:-FAILED}"
    case "${result}" in
        PASS)       (( COUNT_PASS++       )) || true ;;
        REMEDIATED) (( COUNT_REMEDIATED++ )) || true ;;
        FAILED)     (( COUNT_FAILED++     )) || true ;;
    esac
done

TOTAL=${#PARAM_ORDER[@]}
printf "  ${BOLD}%-35s${RESET} %s\n"  "Total parameters audited"  "${TOTAL}"
printf "  ${GREEN}%-35s${RESET} %s\n" "Already compliant"          "${COUNT_PASS}"
printf "  ${GREEN}%-35s${RESET} %s\n" "Remediated this run"        "${COUNT_REMEDIATED}"
if [[ "${COUNT_FAILED}" -gt 0 ]]; then
    printf "  ${RED}%-35s${RESET} %s\n" "Failed"                   "${COUNT_FAILED}"
fi
printf "  ${BOLD}%-35s${RESET} %s\n"  "Persistence file"           "${SYSCTL_DROP_IN}"

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 09_sysctl_network — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 09_sysctl_network — ONE OR MORE PARAMETERS FAILED"
    exit 1
fi
