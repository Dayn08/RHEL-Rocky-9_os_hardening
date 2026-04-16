#!/usr/bin/env bash
# =============================================================================
# MODULE  : 06_aslr.sh
# TITLE   : Enable Randomized Virtual Memory Region Placement (ASLR)
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 1.5.3
#
# BACKGROUND:
#   Address Space Layout Randomisation (ASLR) randomly arranges the memory
#   address space of a process (stack, heap, shared libraries, mmap regions)
#   on each execution. This makes it significantly harder for an attacker to
#   predict target addresses when crafting memory-based exploits such as:
#     - Return-Oriented Programming (ROP) chains
#     - Buffer overflow / stack smashing attacks
#     - Heap spray attacks
#     - Format string exploits that rely on known memory layouts
#
#   kernel.randomize_va_space controls ASLR behaviour:
#     0 = Disabled — no randomisation (dangerous)
#     1 = Partial  — stack, VDSO, mmap randomised; heap is NOT randomised
#     2 = Full     — stack, heap, VDSO, mmap, and shared library randomised
#                    (CIS required value)
#
# AUDIT COMMAND (CIS reference):
#   sysctl kernel.randomize_va_space
#   Expected: kernel.randomize_va_space = 2
#
# CHECKS:
#   1.  kernel.randomize_va_space runtime value = 2
#   2.  kernel.randomize_va_space persisted in /etc/sysctl.d/
#   3.  No conflicting lower value in /etc/sysctl.conf or other sysctl.d files
#   4.  Verify ASLR is effective (entropy bits check)
#
# EXIT CODES:
#   0 — All checks passed (or remediated successfully)
#   1 — One or more checks failed
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 06_aslr.sh
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
SYSCTL_DROP_IN="/etc/sysctl.d/61-aslr-hardening.conf"
REQUIRED_VALUE="2"
PARAM="kernel.randomize_va_space"

# ── Helper: backup a file once per run ────────────────────────────────────────
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

# ── Quick explainer ────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}ASLR value reference:${RESET}"
printf "  ${DIM}%-5s %-20s %s${RESET}\n" "0" "Disabled"        "No randomisation — exploits work reliably"
printf "  ${DIM}%-5s %-20s %s${RESET}\n" "1" "Partial ASLR"    "Stack/mmap randomised, heap is NOT"
printf "  ${GREEN}${BOLD}%-5s %-20s %s${RESET}\n" "2" "Full ASLR (CIS)" "Stack + heap + mmap + libs all randomised"
echo ""

# =============================================================================
# CHECK 1 — Runtime value of kernel.randomize_va_space
# =============================================================================
hdr "Check 1 — Runtime ASLR Value"
info "Audit  : sysctl ${PARAM}"
info "Expect : ${PARAM} = ${REQUIRED_VALUE}"
echo ""

if ! command -v sysctl &>/dev/null; then
    fail "sysctl command not found."
    mark_fail
    exit 1
fi

CURRENT_VAL=$(sysctl -n "${PARAM}" 2>/dev/null || echo "UNKNOWN")
info "Current runtime value : ${PARAM} = ${CURRENT_VAL}"
echo ""

case "${CURRENT_VAL}" in
    "${REQUIRED_VALUE}")
        pass "ASLR is fully enabled — ${PARAM} = ${CURRENT_VAL}"
        ;;
    1)
        fail "${PARAM} = 1 — partial ASLR only (heap is NOT randomised)."
        warn "Heap spray attacks remain viable with partial ASLR."
        info "Remediation: Setting ${PARAM} = 2 at runtime ..."
        sysctl -w "${PARAM}=${REQUIRED_VALUE}" &>/dev/null
        VERIFY=$(sysctl -n "${PARAM}" 2>/dev/null)
        if [[ "${VERIFY}" == "${REQUIRED_VALUE}" ]]; then
            pass "Runtime value updated to ${REQUIRED_VALUE}."
        else
            fail "Could not set runtime value — current: ${VERIFY}"
            mark_fail
        fi
        ;;
    0)
        fail "${PARAM} = 0 — ASLR is completely DISABLED."
        warn "Memory layout is fully predictable — all exploit classes are viable."
        info "Remediation: Enabling full ASLR now ..."
        sysctl -w "${PARAM}=${REQUIRED_VALUE}" &>/dev/null
        VERIFY=$(sysctl -n "${PARAM}" 2>/dev/null)
        if [[ "${VERIFY}" == "${REQUIRED_VALUE}" ]]; then
            pass "Runtime value updated to ${REQUIRED_VALUE}."
        else
            fail "Could not set runtime value — current: ${VERIFY}"
            mark_fail
        fi
        ;;
    *)
        warn "Unexpected value: '${CURRENT_VAL}' — expected 0, 1, or 2."
        info "Remediation: Forcing ${PARAM} = ${REQUIRED_VALUE} ..."
        sysctl -w "${PARAM}=${REQUIRED_VALUE}" &>/dev/null || mark_fail
        ;;
esac

# =============================================================================
# CHECK 2 — Persistent configuration in sysctl.d
# =============================================================================
hdr "Check 2 — Persistent ASLR Configuration"
info "Audit  : grep -r '${PARAM}' /etc/sysctl.conf /etc/sysctl.d/"
echo ""

SYSCTL_SOURCES=("/etc/sysctl.conf")
while IFS= read -r -d '' f; do
    SYSCTL_SOURCES+=("${f}")
done < <(find /etc/sysctl.d/ -maxdepth 1 -name "*.conf" -print0 2>/dev/null)

PERSISTED=0
FOUND_FILES=()

for src in "${SYSCTL_SOURCES[@]}"; do
    [[ ! -f "${src}" ]] && continue
    MATCH=$(grep -E "^\s*${PARAM}\s*=" "${src}" 2>/dev/null || true)
    if [[ -n "${MATCH}" ]]; then
        VAL=$(echo "${MATCH}" | awk -F= '{print $2}' | tr -d ' \t' | tail -1)
        info "Found in ${src} : ${MATCH}"
        FOUND_FILES+=("${src}:${VAL}")
        [[ "${VAL}" == "${REQUIRED_VALUE}" ]] && PERSISTED=1
    fi
done

if [[ "${PERSISTED}" -eq 1 ]]; then
    pass "${PARAM} = ${REQUIRED_VALUE} is correctly persisted."
else
    [[ ${#FOUND_FILES[@]} -eq 0 ]] \
        && fail "${PARAM} not found in any sysctl config — will revert on reboot." \
        || fail "${PARAM} found but not set to ${REQUIRED_VALUE} — incorrect persistence."

    info "Remediation: Writing ${SYSCTL_DROP_IN} ..."

    mkdir -p "$(dirname "${SYSCTL_DROP_IN}")"

    cat > "${SYSCTL_DROP_IN}" << EOF
# ${SYSCTL_DROP_IN}
# Enable full ASLR — CIS RHEL9 Benchmark Section 1.5.3
#
# 0 = Disabled  (no randomisation — exploits work reliably)
# 1 = Partial   (stack/mmap randomised, heap is NOT)
# 2 = Full ASLR (stack + heap + mmap + shared libs) ← CIS required
kernel.randomize_va_space = 2
EOF

    chmod 644 "${SYSCTL_DROP_IN}"
    chown root:root "${SYSCTL_DROP_IN}"

    # Apply the drop-in immediately
    if sysctl -p "${SYSCTL_DROP_IN}" &>/dev/null; then
        pass "Persisted to ${SYSCTL_DROP_IN} and applied."
    else
        fail "sysctl -p failed — check ${SYSCTL_DROP_IN}"
        mark_fail
    fi
fi

# =============================================================================
# CHECK 3 — Conflicting lower values in other sysctl files
# =============================================================================
hdr "Check 3 — Conflicting sysctl Overrides"
info "Audit  : checking all sysctl sources for conflicting ${PARAM} values"
echo ""

CONFLICTS=()

for src in "${SYSCTL_SOURCES[@]}"; do
    [[ ! -f "${src}" ]] && continue
    # Skip our own drop-in
    [[ "${src}" == "${SYSCTL_DROP_IN}" ]] && continue

    MATCH=$(grep -E "^\s*${PARAM}\s*=" "${src}" 2>/dev/null || true)
    if [[ -n "${MATCH}" ]]; then
        VAL=$(echo "${MATCH}" | awk -F= '{print $2}' | tr -d ' \t' | tail -1)
        if [[ "${VAL}" != "${REQUIRED_VALUE}" ]]; then
            CONFLICTS+=("${src}")
            warn "Conflicting value (${PARAM} = ${VAL}) in ${src}"
        fi
    fi
done

if [[ ${#CONFLICTS[@]} -eq 0 ]]; then
    pass "No conflicting ${PARAM} values found in other sysctl files."
else
    fail "${#CONFLICTS[@]} conflicting file(s) found — our drop-in (61-*) will win due to"
    info "alphabetical load order, but cleaning up conflicts is recommended."
    echo ""
    for conflict_file in "${CONFLICTS[@]}"; do
        info "  Fixing : ${conflict_file}"
        backup_file "${conflict_file}"
        sed -i "/^\s*${PARAM}\s*=/d" "${conflict_file}"
        info "  Removed conflicting line from ${conflict_file}"
    done
    pass "Conflicting entries removed."
fi

# =============================================================================
# CHECK 4 — ASLR entropy bits (effectiveness verification)
# =============================================================================
hdr "Check 4 — ASLR Entropy Verification"
info "Audit  : checking mmap and stack entropy bits"
echo ""

# These kernel parameters show how many bits of entropy are used for ASLR.
# Higher = more random = harder to brute-force.
# Typical values on x86_64: mmap=28, stack=22

MMAP_ENTROPY=""
STACK_ENTROPY=""

if [[ -r /proc/sys/vm/mmap_rnd_bits ]]; then
    MMAP_ENTROPY=$(cat /proc/sys/vm/mmap_rnd_bits)
fi

if [[ -r /proc/sys/vm/mmap_rnd_compat_bits ]]; then
    MMAP_COMPAT=$(cat /proc/sys/vm/mmap_rnd_compat_bits)
else
    MMAP_COMPAT="N/A"
fi

if [[ -r /proc/sys/kernel/perf_event_mlock_kb ]]; then
    # Stack entropy is not directly exposed — infer from randomize_va_space
    STACK_ENTROPY="controlled by randomize_va_space"
fi

if [[ -n "${MMAP_ENTROPY}" ]]; then
    if [[ "${MMAP_ENTROPY}" -ge 28 ]] 2>/dev/null; then
        pass "mmap entropy bits : ${MMAP_ENTROPY} (good — >= 28 bits)"
    elif [[ "${MMAP_ENTROPY}" -ge 18 ]] 2>/dev/null; then
        warn "mmap entropy bits : ${MMAP_ENTROPY} (low — consider increasing to 32)"
        detail "sysctl -w vm.mmap_rnd_bits=32"
    else
        fail "mmap entropy bits : ${MMAP_ENTROPY} (very low — ASLR effectiveness reduced)"
        mark_fail
    fi
    info "mmap compat entropy bits : ${MMAP_COMPAT} (for 32-bit processes)"
else
    info "vm.mmap_rnd_bits not accessible — skipping entropy check."
fi

# =============================================================================
# Final state summary
# =============================================================================
hdr "Final State Verification"
echo ""

FINAL_VAL=$(sysctl -n "${PARAM}" 2>/dev/null || echo "UNKNOWN")
PERSIST_EXISTS="no"
[[ -f "${SYSCTL_DROP_IN}" ]] && PERSIST_EXISTS="yes (${SYSCTL_DROP_IN})"

printf "  ${BOLD}%-42s${RESET} %s\n" "${PARAM} (runtime)"   "${FINAL_VAL}"
printf "  ${BOLD}%-42s${RESET} %s\n" "Persistence file present"  "${PERSIST_EXISTS}"

echo ""

if [[ "${FINAL_VAL}" == "${REQUIRED_VALUE}" ]]; then
    pass "${PARAM} = ${FINAL_VAL} — Full ASLR active ✓"
else
    fail "${PARAM} = ${FINAL_VAL} — expected ${REQUIRED_VALUE}"
    mark_fail
fi

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 06_aslr — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 06_aslr — ONE OR MORE CHECKS FAILED"
    exit 1
fi
