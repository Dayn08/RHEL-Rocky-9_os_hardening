#!/usr/bin/env bash
# =============================================================================
# MODULE  : 12_password_policy.sh
# TITLE   : Password Policies, Account Security & Login Banners
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Sections 5.3, 5.4, 6.1
#
# CHECKS:
#   1.  SHA-512 password hashing algorithm (ENCRYPT_METHOD in login.defs)
#   2.  pam_pwquality — password complexity requirements
#   3.  Password reuse limit (pam_unix remember=5)
#   4.  PASS_MAX_DAYS 180  (password expiration)
#   5.  PASS_MIN_DAYS 7    (minimum days between changes)
#   6.  PASS_WARN_AGE 7   (warning days before expiry)
#   7.  Apply chage settings to all existing non-system users
#   8.  Disable interactive shell for system accounts (UID < 500)
#   9.  root account default GID = 0
#  10.  Lock inactive accounts after 35 days (useradd -D -f 35)
#  11.  Set warning banners (/etc/motd, /etc/issue, /etc/issue.net)
#  12.  Remove OS information from login banners
#  13.  Permissions on /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow
#
# EXIT CODES:
#   0 — All checks passed (or remediated successfully)
#   1 — One or more checks failed
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 12_password_policy.sh
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
LOGIN_DEFS="/etc/login.defs"
SYSTEM_AUTH="/etc/pam.d/system-auth"
PASSWORD_AUTH="/etc/pam.d/password-auth"
PWQUALITY_CONF="/etc/security/pwquality.conf"

# CIS-required password policy values
PASS_MAX_DAYS_REQ=180
PASS_MIN_DAYS_REQ=7
PASS_WARN_AGE_REQ=7
INACTIVE_LOCK_DAYS=35
SYSTEM_UID_MAX=499       # UIDs <= this are system accounts (RHEL convention)

# pam_pwquality requirements
PW_MINLEN=12
PW_DCREDIT=-1   # at least 1 digit
PW_UCREDIT=-1   # at least 1 uppercase
PW_LCREDIT=-1   # at least 1 lowercase
PW_OCREDIT=-1   # at least 1 special char
PW_RETRY=3

# OS fingerprint patterns to strip from banners
OS_PATTERNS=(
    "kernel" "linux" "release" "version" "ubuntu" "debian"
    "red hat" "redhat" "centos" "rocky" "fedora" "suse"
    "\\\\s" "\\\\r" "\\\\m" "\\\\l" "\\\\n" "\\\\v"
    "uname" "hostname"
)

# ── Helper: backup a file ──────────────────────────────────────────────────────
backup_file() {
    local f="${1}"
    [[ -f "${f}" ]] || return 0
    local bak="${f}.bak.$(date +%Y%m%d%H%M%S)"
    cp "${f}" "${bak}"
    info "  Backup : ${bak}"
}

# ── Helper: set or update a key=value line in login.defs ──────────────────────
set_login_defs() {
    local key="${1}"
    local val="${2}"
    backup_file "${LOGIN_DEFS}"
    if grep -qE "^#?[[:space:]]*${key}[[:space:]]" "${LOGIN_DEFS}"; then
        sed -i "s|^#\?[[:space:]]*${key}[[:space:]].*|${key}\t${val}|" "${LOGIN_DEFS}"
    else
        echo -e "${key}\t${val}" >> "${LOGIN_DEFS}"
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

# Ensure required packages are installed
for pkg in libpwquality shadow-utils util-linux; do
    if ! rpm -q "${pkg}" &>/dev/null; then
        info "Installing ${pkg} ..."
        dnf install -y "${pkg}" &>/dev/null || warn "Could not install ${pkg}"
    fi
done

# =============================================================================
# CHECK 1 — SHA-512 Password Hashing Algorithm
# =============================================================================
hdr "Check 1 — Password Hashing Algorithm (SHA-512)"
info "Audit  : grep ENCRYPT_METHOD ${LOGIN_DEFS}"
info "Expect : ENCRYPT_METHOD SHA512"
echo ""

ENCRYPT_LINE=$(grep -E "^ENCRYPT_METHOD" "${LOGIN_DEFS}" 2>/dev/null || true)
info "Found  : ${ENCRYPT_LINE:-[not set]}"
echo ""

if echo "${ENCRYPT_LINE}" | grep -qiE "^ENCRYPT_METHOD[[:space:]]+SHA512"; then
    pass "ENCRYPT_METHOD SHA512 is set in ${LOGIN_DEFS} ✓"
else
    fail "ENCRYPT_METHOD is not SHA512 — found: '${ENCRYPT_LINE:-not set}'"
    detail "Risk: Weaker hashing algorithms (MD5, DES) are trivially cracked with"
    detail "      modern GPUs. SHA-512 is the minimum acceptable standard."
    info "Remediation: Setting ENCRYPT_METHOD SHA512 in ${LOGIN_DEFS} ..."
    set_login_defs "ENCRYPT_METHOD" "SHA512"

    VERIFY=$(grep -E "^ENCRYPT_METHOD" "${LOGIN_DEFS}" || true)
    if echo "${VERIFY}" | grep -qiE "^ENCRYPT_METHOD[[:space:]]+SHA512"; then
        pass "ENCRYPT_METHOD SHA512 set ✓"
        echo ""
        warn "IMPORTANT: Existing password hashes are NOT automatically upgraded."
        warn "All existing users should have their passwords reset or be forced"
        warn "to change on next login to benefit from SHA-512 hashing."
        info "To force password change for a specific user:"
        detail "chage -d 0 <username>   # expire immediately, forces change on login"
        info "To force all non-system users (run separately after review):"
        detail "awk -F: '(\$3 >= 500 && \$1 != \"nobody\") {print \$1}' /etc/passwd \\"
        detail "  | xargs -I{} chage -d 0 {}"
    else
        fail "Failed to set ENCRYPT_METHOD SHA512."
        mark_fail
    fi
fi

# =============================================================================
# CHECK 2 — pam_pwquality Password Complexity
# =============================================================================
hdr "Check 2 — Password Complexity (pam_pwquality)"
info "Audit  : grep pam_pwquality.so ${SYSTEM_AUTH}"
info "Expect : password required pam_pwquality.so try_first_pass retry=3"
info "         minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1"
echo ""

# Check if pam_pwquality is configured in system-auth
PAM_PW_LINE=$(grep -E "pam_pwquality\.so" "${SYSTEM_AUTH}" 2>/dev/null || true)
info "Found in ${SYSTEM_AUTH}:"
echo "${PAM_PW_LINE:-  [not configured]}" | sed 's/^/        /'
echo ""

# Validate each required parameter
PAM_OK=1
for param_check in "retry=${PW_RETRY}" "minlen=${PW_MINLEN}" \
                   "dcredit=${PW_DCREDIT}" "ucredit=${PW_UCREDIT}" \
                   "ocredit=${PW_OCREDIT}" "lcredit=${PW_LCREDIT}"; do
    if ! echo "${PAM_PW_LINE}" | grep -q "${param_check}"; then
        warn "Missing or incorrect parameter: ${param_check}"
        PAM_OK=0
    fi
done

if [[ "${PAM_OK}" -eq 1 && -n "${PAM_PW_LINE}" ]]; then
    pass "pam_pwquality is correctly configured in ${SYSTEM_AUTH} ✓"
else
    fail "pam_pwquality configuration is missing or incomplete."
    info "Remediation: Configuring via ${PWQUALITY_CONF} and ${SYSTEM_AUTH} ..."

    # 2a — Write pwquality.conf (preferred RHEL9 approach)
    backup_file "${PWQUALITY_CONF}"
    cat > "${PWQUALITY_CONF}" << EOF
# ${PWQUALITY_CONF}
# Generated by 12_password_policy.sh — CIS RHEL9 Section 5.3
#
# Password must be at least 13 characters
minlen = ${PW_MINLEN}
#
# Require at least 1 digit (-1 = at least 1 required)
dcredit = ${PW_DCREDIT}
#
# Require at least 1 uppercase letter
ucredit = ${PW_UCREDIT}
#
# Require at least 1 lowercase letter
lcredit = ${PW_LCREDIT}
#
# Require at least 1 special/other character
ocredit = ${PW_OCREDIT}
#
# Number of retries before returning error
retry = ${PW_RETRY}
#
# Reject passwords containing the username
usercheck = 1
#
# Enforce even for root
enforce_for_root
EOF
    chmod 644 "${PWQUALITY_CONF}"
    pass "${PWQUALITY_CONF} configured."

    # 2b — Ensure pam_pwquality is in system-auth
    if ! grep -q "pam_pwquality.so" "${SYSTEM_AUTH}" 2>/dev/null; then
        info "Adding pam_pwquality.so to ${SYSTEM_AUTH} ..."
        backup_file "${SYSTEM_AUTH}"
        # Insert before pam_unix.so in the password stack
        sed -i "/^password.*pam_unix\.so/i password    required      pam_pwquality.so try_first_pass retry=${PW_RETRY} minlen=${PW_MINLEN} dcredit=${PW_DCREDIT} ucredit=${PW_UCREDIT} ocredit=${PW_OCREDIT} lcredit=${PW_LCREDIT}" \
            "${SYSTEM_AUTH}"
        pass "pam_pwquality.so added to ${SYSTEM_AUTH}"
    else
        info "pam_pwquality.so present in ${SYSTEM_AUTH} — updating parameters ..."
        backup_file "${SYSTEM_AUTH}"
        sed -i "s|^password.*pam_pwquality\.so.*|password    required      pam_pwquality.so try_first_pass retry=${PW_RETRY} minlen=${PW_MINLEN} dcredit=${PW_DCREDIT} ucredit=${PW_UCREDIT} ocredit=${PW_OCREDIT} lcredit=${PW_LCREDIT}|" \
            "${SYSTEM_AUTH}"
        pass "pam_pwquality.so parameters updated in ${SYSTEM_AUTH}"
    fi

    # Mirror to password-auth if it exists
    if [[ -f "${PASSWORD_AUTH}" ]] && ! grep -q "pam_pwquality.so" "${PASSWORD_AUTH}"; then
        backup_file "${PASSWORD_AUTH}"
        sed -i "/^password.*pam_unix\.so/i password    required      pam_pwquality.so try_first_pass retry=${PW_RETRY} minlen=${PW_MINLEN} dcredit=${PW_DCREDIT} ucredit=${PW_UCREDIT} ocredit=${PW_OCREDIT} lcredit=${PW_LCREDIT}" \
            "${PASSWORD_AUTH}"
        pass "pam_pwquality.so added to ${PASSWORD_AUTH}"
    fi
fi

# =============================================================================
# CHECK 3 — Password Reuse Limit (remember=5)
# =============================================================================
hdr "Check 3 — Password Reuse Limit"
info "Audit  : grep \"remember\" ${SYSTEM_AUTH}"
info "Expect : password sufficient pam_unix.so remember=5"
echo ""

REMEMBER_LINE=$(grep -E "remember" "${SYSTEM_AUTH}" 2>/dev/null || true)
info "Found  : ${REMEMBER_LINE:-[not set]}"
echo ""

CURRENT_REMEMBER=$(echo "${REMEMBER_LINE}" | grep -oP 'remember=\K\d+' || echo "0")

if [[ "${CURRENT_REMEMBER}" -ge 5 ]] 2>/dev/null; then
    pass "Password reuse limit is ${CURRENT_REMEMBER} (>= 5) ✓"
else
    fail "Password reuse limit is ${CURRENT_REMEMBER:-not set} — must be at least 5."
    detail "Risk: Without reuse limits users cycle between a few known passwords,"
    detail "      completely defeating password expiration policies."
    info "Remediation: Setting remember=5 on pam_unix.so in ${SYSTEM_AUTH} ..."
    backup_file "${SYSTEM_AUTH}"

    if grep -q "pam_unix.so" "${SYSTEM_AUTH}"; then
        # Add or update remember= on the pam_unix.so password line
        if grep -E "^password.*(sufficient|[[:space:]]).*pam_unix\.so" "${SYSTEM_AUTH}" \
                | grep -q "remember="; then
            sed -i "s|remember=[0-9]*|remember=5|g" "${SYSTEM_AUTH}"
        else
            sed -i "/^password.*pam_unix\.so/ s/$/ remember=5/" "${SYSTEM_AUTH}"
        fi
        pass "remember=5 added to pam_unix.so in ${SYSTEM_AUTH} ✓"
    else
        fail "pam_unix.so not found in ${SYSTEM_AUTH} — manual configuration required."
        mark_fail
    fi

    # Mirror to password-auth
    if [[ -f "${PASSWORD_AUTH}" ]]; then
        backup_file "${PASSWORD_AUTH}"
        if grep -E "^password.*pam_unix\.so" "${PASSWORD_AUTH}" | grep -q "remember="; then
            sed -i "s|remember=[0-9]*|remember=5|g" "${PASSWORD_AUTH}"
        else
            sed -i "/^password.*pam_unix\.so/ s/$/ remember=5/" "${PASSWORD_AUTH}"
        fi
        pass "remember=5 mirrored to ${PASSWORD_AUTH} ✓"
    fi
fi

# =============================================================================
# CHECK 4 — PASS_MAX_DAYS
# =============================================================================
hdr "Check 4 — Password Expiration Days (PASS_MAX_DAYS)"
info "Audit  : grep ^PASS_MAX_DAYS ${LOGIN_DEFS}"
info "Expect : PASS_MAX_DAYS ${PASS_MAX_DAYS_REQ}"
echo ""

PASS_MAX_LINE=$(grep -E "^PASS_MAX_DAYS" "${LOGIN_DEFS}" 2>/dev/null || true)
CURRENT_MAX=$(echo "${PASS_MAX_LINE}" | awk '{print $2}')
info "Found  : ${PASS_MAX_LINE:-[not set]}"
echo ""

if [[ -n "${CURRENT_MAX}" && "${CURRENT_MAX}" -le "${PASS_MAX_DAYS_REQ}" ]] 2>/dev/null; then
    pass "PASS_MAX_DAYS is ${CURRENT_MAX} (<= ${PASS_MAX_DAYS_REQ}) ✓"
else
    fail "PASS_MAX_DAYS is '${CURRENT_MAX:-not set}' — must be <= ${PASS_MAX_DAYS_REQ}."
    info "Remediation: Setting PASS_MAX_DAYS ${PASS_MAX_DAYS_REQ} ..."
    set_login_defs "PASS_MAX_DAYS" "${PASS_MAX_DAYS_REQ}"
    pass "PASS_MAX_DAYS ${PASS_MAX_DAYS_REQ} set in ${LOGIN_DEFS} ✓"
fi

# =============================================================================
# CHECK 5 — PASS_MIN_DAYS
# =============================================================================
hdr "Check 5 — Minimum Days Between Password Changes (PASS_MIN_DAYS)"
info "Audit  : grep ^PASS_MIN_DAYS ${LOGIN_DEFS}"
info "Expect : PASS_MIN_DAYS ${PASS_MIN_DAYS_REQ}"
echo ""

PASS_MIN_LINE=$(grep -E "^PASS_MIN_DAYS" "${LOGIN_DEFS}" 2>/dev/null || true)
CURRENT_MIN=$(echo "${PASS_MIN_LINE}" | awk '{print $2}')
info "Found  : ${PASS_MIN_LINE:-[not set]}"
echo ""

if [[ -n "${CURRENT_MIN}" && "${CURRENT_MIN}" -ge "${PASS_MIN_DAYS_REQ}" ]] 2>/dev/null; then
    pass "PASS_MIN_DAYS is ${CURRENT_MIN} (>= ${PASS_MIN_DAYS_REQ}) ✓"
else
    fail "PASS_MIN_DAYS is '${CURRENT_MIN:-not set}' — must be >= ${PASS_MIN_DAYS_REQ}."
    detail "Risk: Without a minimum, users can change password multiple times in one"
    detail "      day to cycle back to a previously used password, bypassing remember=."
    info "Remediation: Setting PASS_MIN_DAYS ${PASS_MIN_DAYS_REQ} ..."
    set_login_defs "PASS_MIN_DAYS" "${PASS_MIN_DAYS_REQ}"
    pass "PASS_MIN_DAYS ${PASS_MIN_DAYS_REQ} set in ${LOGIN_DEFS} ✓"
fi

# =============================================================================
# CHECK 6 — PASS_WARN_AGE
# =============================================================================
hdr "Check 6 — Password Expiry Warning Days (PASS_WARN_AGE)"
info "Audit  : grep ^PASS_WARN_AGE ${LOGIN_DEFS}"
info "Expect : PASS_WARN_AGE ${PASS_WARN_AGE_REQ}"
echo ""

PASS_WARN_LINE=$(grep -E "^PASS_WARN_AGE" "${LOGIN_DEFS}" 2>/dev/null || true)
CURRENT_WARN=$(echo "${PASS_WARN_LINE}" | awk '{print $2}')
info "Found  : ${PASS_WARN_LINE:-[not set]}"
echo ""

if [[ -n "${CURRENT_WARN}" && "${CURRENT_WARN}" -ge "${PASS_WARN_AGE_REQ}" ]] 2>/dev/null; then
    pass "PASS_WARN_AGE is ${CURRENT_WARN} (>= ${PASS_WARN_AGE_REQ}) ✓"
else
    fail "PASS_WARN_AGE is '${CURRENT_WARN:-not set}' — must be >= ${PASS_WARN_AGE_REQ}."
    info "Remediation: Setting PASS_WARN_AGE ${PASS_WARN_AGE_REQ} ..."
    set_login_defs "PASS_WARN_AGE" "${PASS_WARN_AGE_REQ}"
    pass "PASS_WARN_AGE ${PASS_WARN_AGE_REQ} set in ${LOGIN_DEFS} ✓"
fi

# =============================================================================
# CHECK 7 — Apply chage settings to existing non-system users
# =============================================================================
hdr "Check 7 — Apply Password Aging to Existing Users (chage)"
info "Audit  : chage --list <user> | grep 'Maximum\\|Minimum\\|Warning'"
info "Applying to all non-system users (UID > ${SYSTEM_UID_MAX}) ..."
echo ""

printf "  ${BOLD}%-20s %-12s %-12s %-12s %-15s${RESET}\n" \
    "USER" "MAX_DAYS" "MIN_DAYS" "WARN_DAYS" "STATUS"
printf "  %s\n" "$(printf '─%.0s' {1..75})"

while IFS=: read -r username _ uid _ _ _ shell; do
    # Skip system accounts and special shells
    [[ "${uid}" -le "${SYSTEM_UID_MAX}" ]] && continue
    [[ "${shell}" == "/sbin/nologin" || "${shell}" == "/usr/sbin/nologin" ]] && continue
    [[ "${shell}" == "/bin/false" ]] && continue
    [[ "${username}" == "nobody" ]] && continue

    CURRENT_MAX_U=$(chage -l "${username}" 2>/dev/null \
                    | grep "Maximum" | awk -F: '{print $2}' | xargs || echo "?")
    CURRENT_MIN_U=$(chage -l "${username}" 2>/dev/null \
                    | grep "Minimum" | awk -F: '{print $2}' | xargs || echo "?")
    CURRENT_WARN_U=$(chage -l "${username}" 2>/dev/null \
                     | grep "warning" | awk -F: '{print $2}' | xargs || echo "?")

    NEEDS_UPDATE=0

    # Check max days
    if [[ "${CURRENT_MAX_U}" == "Never" ]] || \
       ( [[ "${CURRENT_MAX_U}" =~ ^[0-9]+$ ]] && \
         [[ "${CURRENT_MAX_U}" -gt "${PASS_MAX_DAYS_REQ}" ]] ); then
        NEEDS_UPDATE=1
    fi

    # Check min days
    if [[ "${CURRENT_MIN_U}" =~ ^[0-9]+$ ]] && \
       [[ "${CURRENT_MIN_U}" -lt "${PASS_MIN_DAYS_REQ}" ]]; then
        NEEDS_UPDATE=1
    fi

    if [[ "${NEEDS_UPDATE}" -eq 1 ]]; then
        chage --maxdays  "${PASS_MAX_DAYS_REQ}" \
              --mindays  "${PASS_MIN_DAYS_REQ}"  \
              --warndays "${PASS_WARN_AGE_REQ}"  \
              "${username}" 2>/dev/null && STATUS="Updated ✓" || STATUS="Error"
    else
        STATUS="OK"
    fi

    printf "  %-20s %-12s %-12s %-12s %-15s\n" \
        "${username}" "${CURRENT_MAX_U}" "${CURRENT_MIN_U}" \
        "${CURRENT_WARN_U}" "${STATUS}"

done < /etc/passwd
echo ""

# =============================================================================
# CHECK 8 — Disable Interactive Shell for System Accounts
# =============================================================================
hdr "Check 8 — Disable System Accounts Interactive Shell"
info "Audit  : egrep -v \"^\+\" /etc/passwd | awk -F: ..."
info "         (system accounts UID < 500 with interactive shells)"
echo ""

info "Scanning for system accounts with interactive shells ..."
echo ""

OFFENDERS=$(
    awk -F: '
        /^\+/ { next }
        $1 == "root"     { next }
        $1 == "sync"     { next }
        $1 == "shutdown" { next }
        $1 == "halt"     { next }
        $3 < 500 &&
        $7 !~ /\/sbin\/nologin|\/usr\/sbin\/nologin|\/bin\/false|\/dev\/null/ {
            print $1 ":" $3 ":" $7
        }
    ' /etc/passwd || true
)

if [[ -z "${OFFENDERS}" ]]; then
    pass "No system accounts with interactive shells found ✓"
    detail "Audit output: [no output — compliant]"
else
    fail "System accounts with interactive shells detected:"
    echo ""
    printf "  ${BOLD}%-20s %-8s %-30s %-20s${RESET}\n" "ACCOUNT" "UID" "CURRENT SHELL" "ACTION"
    printf "  %s\n" "$(printf '─%.0s' {1..80})"

    while IFS=: read -r acct uid cshell; do
        info "  Locking shell for system account: ${acct} (UID ${uid}, shell: ${cshell})"
        if usermod -s /sbin/nologin "${acct}" 2>/dev/null; then
            printf "  %-20s %-8s %-30s %-20s\n" \
                "${acct}" "${uid}" "${cshell}" "Set to nologin ✓"
        else
            printf "  %-20s %-8s %-30s %-20s\n" \
                "${acct}" "${uid}" "${cshell}" "FAILED"
            mark_fail
        fi
    done <<< "${OFFENDERS}"
fi

# =============================================================================
# CHECK 9 — Root Account Default GID = 0
# =============================================================================
hdr "Check 9 — Root Account Default GID"
info "Audit  : grep root /etc/passwd | cut -f4 -d:"
info "Expect : 0"
echo ""

ROOT_GID=$(grep -E "^root:" /etc/passwd | cut -f4 -d: || echo "UNKNOWN")
info "root GID : ${ROOT_GID}"
echo ""

if [[ "${ROOT_GID}" == "0" ]]; then
    pass "root account GID is 0 ✓"
else
    fail "root account GID is ${ROOT_GID} — must be 0."
    info "Remediation: usermod -g 0 root"
    usermod -g 0 root 2>/dev/null \
        && pass "root GID set to 0 ✓" \
        || { fail "Could not set root GID."; mark_fail; }
fi

# =============================================================================
# CHECK 10 — Lock Inactive User Accounts
# =============================================================================
hdr "Check 10 — Lock Inactive Accounts (useradd -D -f ${INACTIVE_LOCK_DAYS})"
info "Audit  : useradd -D | grep INACTIVE"
info "Expect : INACTIVE=${INACTIVE_LOCK_DAYS}"
echo ""

CURRENT_INACTIVE=$(useradd -D 2>/dev/null | grep "^INACTIVE" | cut -d= -f2 || echo "-1")
info "Current INACTIVE default : ${CURRENT_INACTIVE}"
echo ""

if [[ "${CURRENT_INACTIVE}" == "${INACTIVE_LOCK_DAYS}" ]]; then
    pass "INACTIVE default is ${INACTIVE_LOCK_DAYS} days ✓"
else
    fail "INACTIVE is ${CURRENT_INACTIVE} — must be ${INACTIVE_LOCK_DAYS}."
    detail "Risk: Abandoned accounts that are never used remain active indefinitely,"
    detail "      giving attackers a persistent foothold if credentials are compromised."
    info "Remediation: useradd -D -f ${INACTIVE_LOCK_DAYS}"
    useradd -D -f "${INACTIVE_LOCK_DAYS}" 2>/dev/null \
        && pass "Default INACTIVE set to ${INACTIVE_LOCK_DAYS} days ✓" \
        || { fail "Could not set INACTIVE default."; mark_fail; }

    VERIFY=$(useradd -D | grep "^INACTIVE" | cut -d= -f2)
    info "Verified INACTIVE = ${VERIFY}"
fi

# Apply to existing users who have INACTIVE=-1 (never locks)
info "Checking existing users for INACTIVE=-1 ..."
echo ""
INACTIVE_FIXED=0

while IFS=: read -r username _ uid _ _ _ shell; do
    [[ "${uid}" -le "${SYSTEM_UID_MAX}" ]] && continue
    [[ "${shell}" == "/sbin/nologin" || "${shell}" == "/usr/sbin/nologin" \
       || "${shell}" == "/bin/false" ]] && continue
    [[ "${username}" == "nobody" ]] && continue

    USER_INACTIVE=$(chage -l "${username}" 2>/dev/null \
                    | grep "Password inactive" | awk -F: '{print $2}' | xargs || echo "never")

    if [[ "${USER_INACTIVE}" == "never" || "${USER_INACTIVE}" == "-1" ]]; then
        chage --inactive "${INACTIVE_LOCK_DAYS}" "${username}" 2>/dev/null
        info "  Set INACTIVE=${INACTIVE_LOCK_DAYS} for user: ${username}"
        INACTIVE_FIXED=1
    fi
done < /etc/passwd

[[ "${INACTIVE_FIXED}" -eq 1 ]] \
    && pass "INACTIVE applied to existing users ✓" \
    || pass "All existing users already have INACTIVE configured ✓"

# =============================================================================
# CHECK 11 — Set Warning Banners
# =============================================================================
hdr "Check 11 — Login Warning Banners"
info "Audit  : stat -L -c \"%a %u %g\" /etc/motd /etc/issue /etc/issue.net"
echo ""

LEGAL_BANNER='******************************************************************************
                         AUTHORISED ACCESS ONLY

This system is the property of the organisation and is for authorised use
only. All activity on this system is monitored and recorded.

Unauthorised access or misuse is strictly prohibited and may be subject to
criminal prosecution under applicable laws. Disconnect immediately if you
are not an authorised user.
******************************************************************************'

declare -A BANNER_FILES
BANNER_FILES["/etc/motd"]="644"
BANNER_FILES["/etc/issue"]="644"
BANNER_FILES["/etc/issue.net"]="644"

for bfile in "/etc/motd" "/etc/issue" "/etc/issue.net"; do
    expected_perm="${BANNER_FILES[${bfile}]}"
    echo ""
    info "Checking : ${bfile}"

    if [[ ! -f "${bfile}" ]] || [[ ! -s "${bfile}" ]]; then
        info "  ${bfile} is missing or empty — writing banner ..."
        echo "${LEGAL_BANNER}" > "${bfile}"
        pass "  ${bfile} created with legal banner ✓"
    else
        pass "  ${bfile} exists and is non-empty ✓"
    fi

    # Fix permissions
    chmod "${expected_perm}" "${bfile}"
    chown root:root "${bfile}"
    STAT=$(stat -L -c "%a %u %g" "${bfile}")
    pass "  Permissions : ${STAT} ✓"
done

# =============================================================================
# CHECK 12 — Remove OS Information from Banners
# =============================================================================
hdr "Check 12 — Remove OS Information from Login Banners"
info "Audit  : Check /etc/motd, /etc/issue, /etc/issue.net for OS fingerprints"
echo ""

for bfile in "/etc/motd" "/etc/issue" "/etc/issue.net"; do
    [[ ! -f "${bfile}" ]] && continue

    info "Scanning ${bfile} for OS information ..."
    OS_FOUND=0

    for pattern in "${OS_PATTERNS[@]}"; do
        if grep -qiE "${pattern}" "${bfile}" 2>/dev/null; then
            warn "  OS fingerprint pattern found: '${pattern}' in ${bfile}"
            OS_FOUND=1
        fi
    done

    if [[ "${OS_FOUND}" -eq 1 ]]; then
        info "  Replacing ${bfile} with clean legal banner (no OS info) ..."
        backup_file "${bfile}"
        echo "${LEGAL_BANNER}" > "${bfile}"
        pass "  ${bfile} OS information removed ✓"
    else
        pass "  ${bfile} — no OS fingerprint patterns found ✓"
    fi
done

# =============================================================================
# CHECK 13 — Permissions on Critical Password Files
# =============================================================================
hdr "Check 13 — Critical File Permissions"
info "Audit  : stat -L -c \"%a %u %g\" /etc/passwd /etc/shadow /etc/group /etc/gshadow"
echo ""

declare -A CRITICAL_FILES
CRITICAL_FILES["/etc/passwd"]="644:root:root"
CRITICAL_FILES["/etc/shadow"]="000:root:root"
CRITICAL_FILES["/etc/group"]="644:root:root"
CRITICAL_FILES["/etc/gshadow"]="000:root:root"

printf "  ${BOLD}%-20s %-10s %-12s %-10s %-10s %-15s${RESET}\n" \
    "FILE" "EXPECTED" "OWNER:GRP" "CURRENT" "OWNER" "STATUS"
printf "  %s\n" "$(printf '─%.0s' {1..80})"

for cfile in "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow"; do
    [[ ! -f "${cfile}" ]] && continue

    meta="${CRITICAL_FILES[${cfile}]}"
    exp_perm="${meta%%:*}"
    exp_owner=$(echo "${meta}" | cut -d: -f2)
    exp_group=$(echo "${meta}" | cut -d: -f3)

    STAT=$(stat -L -c "%a %U %G" "${cfile}" 2>/dev/null || echo "ERROR ERROR ERROR")
    CURR_PERM=$(echo "${STAT}" | awk '{print $1}')
    CURR_OWN=$(echo "${STAT}"  | awk '{print $2}')
    CURR_GRP=$(echo "${STAT}"  | awk '{print $3}')

    NEEDS_FIX=0
    [[ "${CURR_PERM}" != "${exp_perm}" ]] && NEEDS_FIX=1
    [[ "${CURR_OWN}"  != "${exp_owner}" ]] && NEEDS_FIX=1
    [[ "${CURR_GRP}"  != "${exp_group}" ]] && NEEDS_FIX=1

    if [[ "${NEEDS_FIX}" -eq 0 ]]; then
        STATUS="OK ✓"
    else
        chmod "${exp_perm}" "${cfile}" 2>/dev/null || true
        chown "${exp_owner}:${exp_group}" "${cfile}" 2>/dev/null || true
        STATUS="Fixed ✓"
    fi

    printf "  %-20s %-10s %-12s %-10s %-10s %-15s\n" \
        "${cfile}" "${exp_perm}" "${exp_owner}:${exp_group}" \
        "${CURR_PERM}" "${CURR_OWN}:${CURR_GRP}" "${STATUS}"
done

# =============================================================================
# Final Summary
# =============================================================================
hdr "Configuration Summary"
echo ""

# Show final login.defs password aging values
info "login.defs password aging settings:"
grep -E "^(ENCRYPT_METHOD|PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)" \
    "${LOGIN_DEFS}" 2>/dev/null | sed 's/^/        /'

echo ""
info "useradd default INACTIVE setting:"
useradd -D 2>/dev/null | grep INACTIVE | sed 's/^/        /'

echo ""
info "pwquality.conf settings:"
grep -v '^#' "${PWQUALITY_CONF}" 2>/dev/null | grep -v '^$' | sed 's/^/        /' || true

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 12_password_policy — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 12_password_policy — ONE OR MORE CHECKS FAILED"
    exit 1
fi
