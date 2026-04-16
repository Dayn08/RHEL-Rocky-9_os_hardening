#!/usr/bin/env bash
# =============================================================================
# MODULE  : 01_gpg_check.sh
# TITLE   : RPM GPG Key & gpgcheck Verification
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 1.2 (Software Updates)
#
# CHECKS  :
#   1. Verify Red Hat / Rocky Linux GPG key is installed
#   2. Verify gpgcheck is globally activated in /etc/yum.conf
#
# EXIT CODES:
#   0 — All checks passed (or auto-remediated successfully)
#   1 — One or more checks failed and could not be remediated
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 01_gpg_check.sh
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

# ── Track overall result ──────────────────────────────────────────────────────
OVERALL=0   # 0 = pass, 1 = fail

mark_fail() { OVERALL=1; }

# ── OS detection ──────────────────────────────────────────────────────────────
hdr "OS Detection"

if [[ ! -f /etc/os-release ]]; then
    warn "Cannot detect OS — /etc/os-release not found. Skipping module."
    exit 2
fi

source /etc/os-release

case "${ID}" in
    rhel)
        OS_LABEL="Red Hat Enterprise Linux ${VERSION_ID}"
        GPG_KEY_FILE="/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
        GPG_KEY_PATTERN="Red Hat"
        ;;
    rocky)
        OS_LABEL="Rocky Linux ${VERSION_ID}"
        GPG_KEY_FILE="/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9"
        GPG_KEY_PATTERN="Rocky"
        ;;
    *)
        warn "Unsupported OS: ${ID}. This module targets RHEL/Rocky Linux 9."
        exit 2
        ;;
esac

# Verify major version is 9
MAJOR_VER="${VERSION_ID%%.*}"
if [[ "${MAJOR_VER}" != "9" ]]; then
    warn "Detected ${OS_LABEL} — expected version 9. Skipping module."
    exit 2
fi

info "Detected OS : ${OS_LABEL}"

# =============================================================================
# CHECK 1 — GPG Key Installed
# =============================================================================
hdr "Check 1 — GPG Key Installed"
info "Audit  : rpm -q --queryformat \"%{SUMMARY}\\n\" gpg-pubkey"
info "Source : ${GPG_KEY_FILE}"

# 1a. Query installed GPG keys via RPM database
GPG_KEYS_INSTALLED=$(rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey 2>/dev/null || true)

if echo "${GPG_KEYS_INSTALLED}" | grep -qi "${GPG_KEY_PATTERN}"; then
    pass "GPG key for ${GPG_KEY_PATTERN} is present in the RPM database."
    echo ""
    info "Installed GPG keys:"
    echo "${GPG_KEYS_INSTALLED}" | sed 's/^/        /'
else
    fail "No GPG key matching '${GPG_KEY_PATTERN}' found in RPM database."
    mark_fail
fi

# 1b. Verify the key file exists on disk
echo ""
info "Audit  : Checking key file on disk → ${GPG_KEY_FILE}"

if [[ -f "${GPG_KEY_FILE}" ]]; then
    pass "GPG key file found : ${GPG_KEY_FILE}"

    # Print fingerprint for manual verification
    echo ""
    info "Fingerprint (verify against official source):"
    gpg --quiet --with-fingerprint "${GPG_KEY_FILE}" 2>/dev/null \
        | grep -E "(pub|Key fingerprint)" \
        | sed 's/^/        /' \
        || warn "gpg tool unavailable — cannot print fingerprint."

    info "Reference URL (RHEL) : https://www.redhat.com/security/team/key"
    info "Reference URL (Rocky): https://rockylinux.org/keys"
else
    fail "GPG key file NOT found : ${GPG_KEY_FILE}"
    info "Remediation: Import the key manually:"
    echo ""
    echo "        rpm --import ${GPG_KEY_FILE}"
    echo ""
    mark_fail
fi

# =============================================================================
# CHECK 2 — gpgcheck Globally Activated
# =============================================================================
hdr "Check 2 — gpgcheck Globally Activated"
info "Audit  : grep -H '^gpgcheck=1' /etc/yum.conf"

YUM_CONF="/etc/yum.conf"

if [[ ! -f "${YUM_CONF}" ]]; then
    fail "${YUM_CONF} not found."
    mark_fail
else
    # Audit
    GPGCHECK_LINE=$(grep -E '^gpgcheck=' "${YUM_CONF}" || true)

    if grep -qE '^gpgcheck=1' "${YUM_CONF}"; then
        pass "gpgcheck=1 is set in ${YUM_CONF}"
        echo ""
        info "Matched line:"
        grep -nH '^gpgcheck=1' "${YUM_CONF}" | sed 's/^/        /'

    else
        fail "gpgcheck is NOT set to 1 in ${YUM_CONF}"

        if [[ -n "${GPGCHECK_LINE}" ]]; then
            warn "Current setting: $(grep -nE '^gpgcheck=' "${YUM_CONF}")"
        else
            warn "No gpgcheck= entry found in ${YUM_CONF}"
        fi

        # ── Auto-remediation ──────────────────────────────────────────────────
        info "Remediation: Setting gpgcheck=1 in ${YUM_CONF} ..."

        # Backup first
        BACKUP="${YUM_CONF}.bak.$(date +%Y%m%d%H%M%S)"
        cp "${YUM_CONF}" "${BACKUP}"
        info "Backup created : ${BACKUP}"

        if grep -qE '^gpgcheck=' "${YUM_CONF}"; then
            # Replace existing incorrect value
            sed -i 's/^gpgcheck=.*/gpgcheck=1/' "${YUM_CONF}"
        else
            # Add under [main] section if it exists, else append
            if grep -q '^\[main\]' "${YUM_CONF}"; then
                sed -i '/^\[main\]/a gpgcheck=1' "${YUM_CONF}"
            else
                echo "gpgcheck=1" >> "${YUM_CONF}"
            fi
        fi

        # Re-verify after remediation
        if grep -qE '^gpgcheck=1' "${YUM_CONF}"; then
            pass "Remediation successful — gpgcheck=1 is now set in ${YUM_CONF}"
        else
            fail "Remediation failed — please set 'gpgcheck=1' manually in ${YUM_CONF}"
            mark_fail
        fi
    fi
fi

# 2b. Also check all .repo files under /etc/yum.repos.d/ for gpgcheck=0
echo ""
hdr "Check 2b — Repo Files with gpgcheck=0 (advisory)"
info "Audit  : grep -rl 'gpgcheck=0' /etc/yum.repos.d/"

UNSAFE_REPOS=$(grep -rl '^gpgcheck=0' /etc/yum.repos.d/ 2>/dev/null || true)

if [[ -z "${UNSAFE_REPOS}" ]]; then
    pass "No .repo files found with gpgcheck=0 in /etc/yum.repos.d/"
else
    warn "The following repo files have gpgcheck=0 (review and fix):"
    echo "${UNSAFE_REPOS}" | sed 's/^/        /'
    # This is advisory — does not affect overall PASS/FAIL
fi

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 01_gpg_check — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 01_gpg_check — ONE OR MORE CHECKS FAILED"
    exit 1
fi
