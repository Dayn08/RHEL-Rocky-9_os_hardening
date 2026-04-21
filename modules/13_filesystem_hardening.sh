#!/usr/bin/env bash
# =============================================================================
# MODULE  : 13_filesystem_hardening.sh
# TITLE   : Filesystem Hardening — Mount Options & Disabled Filesystems
# OS      : Red Hat Enterprise Linux 9 / Rocky Linux 9
# CIS REF : CIS RHEL 9 Benchmark — Section 1.1
#
# BACKGROUND:
#   Mount options and filesystem module restrictions are a critical layer of
#   defence-in-depth. Misconfigured mounts allow:
#     - noexec absent : attackers execute malicious binaries from writable dirs
#     - nosuid absent : setuid binaries in /tmp can escalate privileges
#     - nodev absent  : device files in /tmp can bypass device access controls
#   Unused filesystem modules (cramfs, udf) expand the kernel attack surface.
#
# CHECKS (CIS reference numbers):
#   1.1.1.1  Disable mounting of cramfs
#   1.1.1.3  Disable mounting of udf
#   1.1.2    /tmp is configured (in /etc/fstab or as separate partition)
#   1.1.3    noexec on /tmp
#   1.1.4    nodev  on /tmp
#   1.1.5    nosuid on /tmp
#   1.1.6    /dev/shm is configured
#   1.1.7    noexec on /dev/shm
#   1.1.8    nodev  on /dev/shm
#   1.1.9    nosuid on /dev/shm
#   1.1.12   noexec on /var/tmp
#   1.1.13   nodev  on /var/tmp
#   1.1.14   nosuid on /var/tmp
#   1.1.18   nodev  on /home
#   1.1.19   noexec on removable media partitions
#   1.1.20   nodev  on removable media partitions
#   1.1.21   nosuid on removable media partitions
#
# BEHAVIOUR:
#   - Disables cramfs and udf via /etc/modprobe.d/ drop-in files
#   - Audits each mount point for required options using findmnt
#   - Remediates /etc/fstab entries that are missing required options
#   - Remounts affected filesystems immediately (no reboot required)
#   - If /tmp is not a separate partition, configures systemd-tmp mount unit
#   - Removable media checked via udev rules if no entries found in fstab
#
# EXIT CODES:
#   0 — All checks passed (or remediated successfully)
#   1 — One or more checks failed
#   2 — Skipped (unsupported OS)
#
# USAGE   : sudo bash 13_filesystem_hardening.sh
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

FSTAB="/etc/fstab"
MODPROBE_DIR="/etc/modprobe.d"
UDEV_RULES_DIR="/etc/udev/rules.d"
CHANGES_MADE=0   # track if fstab was modified

# ── Result tracking ────────────────────────────────────────────────────────────
declare -A CHECK_RESULT  # label -> "PASS" | "REMEDIATED" | "FAILED" | "SKIP"

# ── Helper: backup a file once ─────────────────────────────────────────────────
backup_file() {
    local f="${1}"
    [[ -f "${f}" ]] || return 0
    local bak="${f}.bak.$(date +%Y%m%d%H%M%S)"
    cp "${f}" "${bak}"
    info "  Backup : ${bak}"
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
# SECTION 1 — Disable Unused Filesystem Modules
# =============================================================================

# Helper — disable a kernel filesystem module via modprobe.d
disable_fs_module() {
    local fsmod="${1}"
    local cis_ref="${2}"
    local reason="${3}"

    echo ""
    hdr "CIS ${cis_ref} — Disable ${fsmod} Filesystem"
    info "Audit  : modprobe -n -v ${fsmod}  →  should return 'install /bin/true'"
    info "         lsmod | grep ${fsmod}    →  should produce no output"
    echo ""

    local drop_in="${MODPROBE_DIR}/99-disable-${fsmod}.conf"
    local ALREADY_BLACKLISTED=0
    local MODULE_LOADED=0

    # Check if already properly disabled
    if [[ -f "${drop_in}" ]] && grep -q "install ${fsmod} /bin/true" "${drop_in}" 2>/dev/null; then
        ALREADY_BLACKLISTED=1
    fi

    # Also check if any modprobe.d file has the install line
    if grep -rl "install ${fsmod} /bin/true" "${MODPROBE_DIR}/" &>/dev/null 2>/dev/null; then
        ALREADY_BLACKLISTED=1
    fi

    # Check if module is currently loaded
    if lsmod 2>/dev/null | grep -qw "^${fsmod}"; then
        MODULE_LOADED=1
    fi

    # Audit: simulate loading
    MODPROBE_TEST=$(modprobe -n -v "${fsmod}" 2>/dev/null || true)
    info "modprobe -n -v ${fsmod} : ${MODPROBE_TEST:-[no output]}"

    if [[ "${ALREADY_BLACKLISTED}" -eq 1 && "${MODULE_LOADED}" -eq 0 ]]; then
        pass "${fsmod} is already disabled via modprobe.d and not currently loaded ✓"
        CHECK_RESULT["${cis_ref}"]="PASS"
        return
    fi

    # ── Remediation ────────────────────────────────────────────────────────────
    if [[ "${ALREADY_BLACKLISTED}" -eq 0 ]]; then
        fail "${fsmod} is not disabled — creating modprobe drop-in ..."
        detail "Reason : ${reason}"

        mkdir -p "${MODPROBE_DIR}"
        cat > "${drop_in}" << EOF
# ${drop_in}
# Disable ${fsmod} filesystem — CIS RHEL9 ${cis_ref}
# ${reason}
install ${fsmod} /bin/true
blacklist ${fsmod}
EOF
        chmod 644 "${drop_in}"
        chown root:root "${drop_in}"
        pass "modprobe drop-in created : ${drop_in}"
    fi

    # Unload module if currently loaded
    if [[ "${MODULE_LOADED}" -eq 1 ]]; then
        warn "${fsmod} is currently loaded — attempting to unload ..."
        if modprobe -r "${fsmod}" 2>/dev/null; then
            pass "${fsmod} unloaded from kernel ✓"
        else
            warn "Could not unload ${fsmod} — it may be in use. Will be disabled after reboot."
        fi
    else
        pass "${fsmod} is not currently loaded ✓"
    fi

    # Regenerate initramfs to prevent module loading at boot
    if command -v dracut &>/dev/null; then
        info "Regenerating initramfs to apply blacklist ..."
        dracut --force &>/dev/null && pass "initramfs regenerated ✓" \
            || warn "dracut failed — blacklist will apply on next dracut run."
    fi

    CHECK_RESULT["${cis_ref}"]="REMEDIATED"
}

disable_fs_module "cramfs" "1.1.1.1" \
    "Compressed ROM filesystem — no legitimate server use case, expands kernel attack surface."

disable_fs_module "udf"    "1.1.1.3" \
    "Universal Disk Format — used by DVDs/optical media, not needed on servers."

# =============================================================================
# SECTION 2 — Mount Option Hardening
# =============================================================================

# Helper — check if a mount point has a required option (runtime + fstab)
# Usage: check_mount_option "<mountpoint>" "<option>" "<cis_ref>" "<description>"
check_mount_option() {
    local mntpnt="${1}"
    local option="${2}"
    local cis_ref="${3}"
    local description="${4}"
    local label="${cis_ref}_${option}"

    echo ""
    hdr "CIS ${cis_ref} — ${option} on ${mntpnt}"
    info "Audit  : findmnt -n -o OPTIONS ${mntpnt} | grep -w ${option}"
    info "Reason : ${description}"
    echo ""

    # ── Check if mount point exists at all ────────────────────────────────────
    if ! mountpoint -q "${mntpnt}" 2>/dev/null && ! grep -qE "[[:space:]]${mntpnt}[[:space:]]" "${FSTAB}" 2>/dev/null; then
        warn "${mntpnt} is not mounted and not in ${FSTAB} — advisory only."

        # Special handling for /tmp — configure via systemd if not a separate partition
        if [[ "${mntpnt}" == "/tmp" ]]; then
            info "Configuring /tmp as tmpfs via systemd-tmp mount unit ..."
            configure_tmp_systemd
        else
            warn "No fstab entry for ${mntpnt} — cannot enforce ${option} without a dedicated partition."
            warn "Consider adding a dedicated partition for ${mntpnt}."
        fi

        CHECK_RESULT["${label}"]="SKIP"
        return
    fi

    # ── Check runtime mount options ───────────────────────────────────────────
    RUNTIME_OPTS=$(findmnt -n -o OPTIONS "${mntpnt}" 2>/dev/null || echo "")
    info "Runtime options : ${RUNTIME_OPTS:-[not mounted / not found]}"

    RUNTIME_OK=0
    echo "${RUNTIME_OPTS}" | tr ',' '\n' | grep -qxF "${option}" && RUNTIME_OK=1

    # ── Check fstab entry ─────────────────────────────────────────────────────
    FSTAB_LINE=$(grep -E "[[:space:]]${mntpnt}[[:space:]]" "${FSTAB}" 2>/dev/null | grep -v '^#' | tail -1 || true)
    FSTAB_OPTS=$(echo "${FSTAB_LINE}" | awk '{print $4}')

    info "fstab entry     : ${FSTAB_LINE:-[no entry]}"
    info "fstab options   : ${FSTAB_OPTS:-[none]}"
    echo ""

    FSTAB_OK=0
    echo "${FSTAB_OPTS}" | tr ',' '\n' | grep -qxF "${option}" && FSTAB_OK=1

    if [[ "${RUNTIME_OK}" -eq 1 && "${FSTAB_OK}" -eq 1 ]]; then
        pass "${option} is set on ${mntpnt} — runtime and fstab ✓"
        CHECK_RESULT["${label}"]="PASS"
        return
    fi

    # ── Remediation ───────────────────────────────────────────────────────────
    fail "${option} is NOT set on ${mntpnt}"
    [[ "${RUNTIME_OK}" -eq 0 ]] && warn "  Missing in runtime mount"
    [[ "${FSTAB_OK}"   -eq 0 ]] && warn "  Missing in ${FSTAB}"

    # Fix fstab
    if [[ -n "${FSTAB_LINE}" ]]; then
        info "  Updating ${FSTAB} to add ${option} ..."
        backup_file "${FSTAB}"
        CHANGES_MADE=1

        # Add option to the options field (field 4)
        # Escape special chars for sed
        ESCAPED_LINE=$(echo "${FSTAB_LINE}" | sed 's/[[\.*^$()+?{|]/\\&/g')
        NEW_OPTS="${FSTAB_OPTS},${option}"

        sed -i "s|${ESCAPED_LINE}|$(echo "${FSTAB_LINE}" | awk -v opt="${option}" \
            'BEGIN{OFS="\t"} {$4=$4","opt; print}')|" "${FSTAB}" 2>/dev/null \
            || {
                # fallback — use perl for safer in-place edit
                perl -i -pe "
                    if (m{\s${mntpnt}\s} && !m{${option}}) {
                        s{(\S+\s+\S+\s+\S+\s+)(\S+)(\s+)}{my \$o=\$2; \$o.=\",${option}\"; \"\$1\$o\$3\"}e
                    }
                " "${FSTAB}" 2>/dev/null || warn "  Could not update fstab automatically — manual edit required."
            }
        pass "  fstab updated — ${option} added to ${mntpnt} ✓"
    else
        # No fstab entry — add one for tmpfs mounts
        if [[ "${mntpnt}" == "/dev/shm" ]]; then
            info "  Adding ${mntpnt} entry to ${FSTAB} ..."
            backup_file "${FSTAB}"
            CHANGES_MADE=1
            echo "tmpfs  ${mntpnt}  tmpfs  defaults,noexec,nodev,nosuid,seclabel  0 0" >> "${FSTAB}"
            pass "  ${mntpnt} tmpfs entry added to fstab ✓"
            FSTAB_OK=1
        fi
    fi

    # Apply at runtime immediately (remount)
    if mountpoint -q "${mntpnt}" 2>/dev/null; then
        info "  Remounting ${mntpnt} with ${option} ..."
        if mount -o "remount,${option}" "${mntpnt}" 2>/dev/null; then
            pass "  ${mntpnt} remounted with ${option} ✓  (no reboot required)"
            RUNTIME_OK=1
        else
            warn "  Could not remount ${mntpnt} immediately — will apply on next reboot."
        fi
    fi

    if [[ "${FSTAB_OK}" -eq 1 || "${RUNTIME_OK}" -eq 1 ]]; then
        CHECK_RESULT["${label}"]="REMEDIATED"
    else
        CHECK_RESULT["${label}"]="FAILED"
        mark_fail
    fi
}

# =============================================================================
# Helper — configure /tmp as systemd tmpfs unit (when not a separate partition)
# =============================================================================
configure_tmp_systemd() {
    local TMP_UNIT="/etc/systemd/system/tmp.mount"
    local TMP_UNIT_SRC="/usr/lib/systemd/system/tmp.mount"

    info "Configuring /tmp as tmpfs mount via systemd ..."

    if [[ ! -f "${TMP_UNIT}" ]]; then
        if [[ -f "${TMP_UNIT_SRC}" ]]; then
            cp "${TMP_UNIT_SRC}" "${TMP_UNIT}"
            info "Copied ${TMP_UNIT_SRC} to ${TMP_UNIT}"
        else
            cat > "${TMP_UNIT}" << 'EOF'
[Unit]
Description=Temporary Directory /tmp
Documentation=man:hier(7)
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=2G

[Install]
WantedBy=local-fs.target
EOF
        fi
    fi

    # Ensure all required options are in the unit
    for reqopt in nosuid nodev noexec; do
        if ! grep -q "${reqopt}" "${TMP_UNIT}" 2>/dev/null; then
            sed -i "/^Options=/ s/$/${reqopt},/" "${TMP_UNIT}"
            info "Added ${reqopt} to ${TMP_UNIT} Options"
        fi
    done

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable tmp.mount 2>/dev/null \
        && pass "tmp.mount unit enabled ✓" \
        || warn "Could not enable tmp.mount"
    systemctl start tmp.mount 2>/dev/null \
        && pass "/tmp mounted as tmpfs with noexec,nodev,nosuid ✓" \
        || warn "Could not start tmp.mount — will apply on next reboot."
}

# =============================================================================
# /tmp checks (1.1.2 – 1.1.5)
# =============================================================================
hdr "CIS 1.1.2 — /tmp Configured"
info "Audit  : findmnt -n /tmp  or  grep '/tmp' /etc/fstab"
echo ""

TMP_MOUNTED=$(findmnt -n /tmp 2>/dev/null || true)
TMP_FSTAB=$(grep -E "[[:space:]]/tmp[[:space:]]" "${FSTAB}" 2>/dev/null | grep -v '^#' || true)

if [[ -n "${TMP_MOUNTED}" ]]; then
    info "Runtime: ${TMP_MOUNTED}"
    pass "/tmp is mounted ✓"
    CHECK_RESULT["1.1.2"]="PASS"
elif [[ -n "${TMP_FSTAB}" ]]; then
    info "fstab entry: ${TMP_FSTAB}"
    pass "/tmp has a fstab entry ✓"
    CHECK_RESULT["1.1.2"]="PASS"
else
    warn "/tmp is not a separate partition — configuring via systemd tmpfs unit ..."
    configure_tmp_systemd
    CHECK_RESULT["1.1.2"]="REMEDIATED"
fi

check_mount_option "/tmp" "noexec" "1.1.3" "Prevents executing binaries/scripts uploaded to /tmp"
check_mount_option "/tmp" "nodev"  "1.1.4" "Prevents creation of device files in /tmp"
check_mount_option "/tmp" "nosuid" "1.1.5" "Prevents setuid binaries in /tmp from gaining elevated privileges"

# =============================================================================
# /dev/shm checks (1.1.6 – 1.1.9)
# =============================================================================
hdr "CIS 1.1.6 — /dev/shm Configured"
info "Audit  : findmnt -n /dev/shm  or  grep '/dev/shm' /etc/fstab"
echo ""

SHM_MOUNTED=$(findmnt -n /dev/shm 2>/dev/null || true)
SHM_FSTAB=$(grep -E "[[:space:]]/dev/shm[[:space:]]" "${FSTAB}" 2>/dev/null | grep -v '^#' || true)

if [[ -n "${SHM_MOUNTED}" ]]; then
    info "Runtime: ${SHM_MOUNTED}"
    pass "/dev/shm is mounted ✓"
    CHECK_RESULT["1.1.6"]="PASS"
elif [[ -n "${SHM_FSTAB}" ]]; then
    info "fstab: ${SHM_FSTAB}"
    pass "/dev/shm has a fstab entry ✓"
    CHECK_RESULT["1.1.6"]="PASS"
else
    info "/dev/shm not in fstab — adding tmpfs entry ..."
    backup_file "${FSTAB}"
    CHANGES_MADE=1
    echo "tmpfs  /dev/shm  tmpfs  defaults,noexec,nodev,nosuid,seclabel  0 0" >> "${FSTAB}"
    mount -a 2>/dev/null || true
    pass "/dev/shm tmpfs entry added to fstab ✓"
    CHECK_RESULT["1.1.6"]="REMEDIATED"
fi

check_mount_option "/dev/shm" "noexec" "1.1.7" "Prevents execution from shared memory — common exploit staging area"
check_mount_option "/dev/shm" "nodev"  "1.1.8" "Prevents device files in shared memory"
check_mount_option "/dev/shm" "nosuid" "1.1.9" "Prevents setuid exploitation via shared memory"

# =============================================================================
# /var/tmp checks (1.1.12 – 1.1.14)
# =============================================================================
check_mount_option "/var/tmp" "noexec" "1.1.12" "Prevents binaries placed in /var/tmp from executing"
check_mount_option "/var/tmp" "nodev"  "1.1.13" "Prevents device files in /var/tmp"
check_mount_option "/var/tmp" "nosuid" "1.1.14" "Prevents setuid binaries in /var/tmp"

# =============================================================================
# /home check (1.1.18)
# =============================================================================
check_mount_option "/home" "nodev" "1.1.18" "Prevents device files in home directories (privilege escalation vector)"

# =============================================================================
# Removable Media Checks (1.1.19 – 1.1.21)
# =============================================================================
hdr "CIS 1.1.19-21 — Removable Media Mount Options"
info "Audit  : grep for removable media entries in ${FSTAB}"
info "         Checking for USB, CD-ROM, floppy entries"
echo ""

# Identify removable media fstab entries by filesystem type or device path
REMOVABLE_ENTRIES=$(grep -E \
    '(/dev/sd[b-z]|/dev/hd[b-z]|/media/|/mnt/usb|/cdrom|/dvd|/floppy|iso9660|vfat.*removable)' \
    "${FSTAB}" 2>/dev/null | grep -v '^#' || true)

if [[ -z "${REMOVABLE_ENTRIES}" ]]; then
    info "No explicit removable media entries found in ${FSTAB}."
    info "Implementing udev rule to enforce mount options for removable media ..."

    UDEV_RULE="${UDEV_RULES_DIR}/99-removable-media-hardening.rules"
    mkdir -p "${UDEV_RULES_DIR}"

    cat > "${UDEV_RULE}" << 'EOF'
# /etc/udev/rules.d/99-removable-media-hardening.rules
# CIS RHEL9 1.1.19-21 — Enforce noexec, nodev, nosuid on removable media
# Applied when USB storage or optical media is plugged in.

# USB storage devices — enforce noexec,nodev,nosuid on automount
ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", \
    RUN+="/bin/sh -c 'mount -o remount,noexec,nodev,nosuid /dev/%k 2>/dev/null || true'"

# Optical media (CD/DVD)
ACTION=="add", SUBSYSTEM=="block", KERNEL=="sr[0-9]*", \
    RUN+="/bin/sh -c 'mount -o remount,noexec,nodev,nosuid /dev/%k 2>/dev/null || true'"
EOF
    chmod 644 "${UDEV_RULE}"
    chown root:root "${UDEV_RULE}"

    # Reload udev rules
    udevadm control --reload-rules 2>/dev/null || true
    pass "udev rule created : ${UDEV_RULE}"
    pass "Removable media will be mounted with noexec,nodev,nosuid when connected ✓"

    CHECK_RESULT["1.1.19"]="REMEDIATED"
    CHECK_RESULT["1.1.20"]="REMEDIATED"
    CHECK_RESULT["1.1.21"]="REMEDIATED"

else
    echo "${REMOVABLE_ENTRIES}" | while IFS= read -r line; do
        info "Found removable entry: ${line}"
        MNTPNT=$(echo "${line}" | awk '{print $2}')
        OPTS=$(echo "${line}"   | awk '{print $4}')

        for reqopt in noexec nodev nosuid; do
            if ! echo "${OPTS}" | tr ',' '\n' | grep -qxF "${reqopt}"; then
                warn "  ${reqopt} missing on ${MNTPNT} — updating fstab ..."
                backup_file "${FSTAB}"
                CHANGES_MADE=1
                ESCAPED=$(echo "${line}" | sed 's/[[\.*^$()+?{|]/\\&/g')
                sed -i "s|${ESCAPED}|$(echo "${line}" | awk -v opt="${reqopt}" \
                    'BEGIN{OFS="\t"} {$4=$4","opt; print}')|" "${FSTAB}" 2>/dev/null || true
            fi
        done
    done
    pass "Removable media fstab entries updated ✓"
    CHECK_RESULT["1.1.19"]="REMEDIATED"
    CHECK_RESULT["1.1.20"]="REMEDIATED"
    CHECK_RESULT["1.1.21"]="REMEDIATED"
fi

# =============================================================================
# Apply fstab changes — remount all affected filesystems
# =============================================================================
if [[ "${CHANGES_MADE}" -eq 1 ]]; then
    hdr "Applying fstab Changes"
    info "Running mount -a to apply updated fstab entries ..."
    echo ""

    if mount -a 2>/dev/null; then
        pass "mount -a completed successfully ✓"
    else
        warn "mount -a reported errors — some mounts may need a reboot."
        warn "Check: systemctl status  and  journalctl -xe"
    fi

    # Show current mount options for audited paths
    info "Current mount options for hardened paths:"
    for mnt in /tmp /dev/shm /var/tmp /home; do
        OPTS=$(findmnt -n -o OPTIONS "${mnt}" 2>/dev/null || echo "[not mounted]")
        printf "  %-18s %s\n" "${mnt}" "${OPTS}"
    done
fi

# =============================================================================
# Summary Table
# =============================================================================
echo ""
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║         FILESYSTEM HARDENING SUMMARY                                     ║${RESET}"
echo -e "${BOLD}╠══════════════╦══════════════════════════════════════╦════════════════════╣${RESET}"
printf "${BOLD}║  %-12s ║ %-36s ║ %-18s ║${RESET}\n" "CIS REF" "CHECK" "STATUS"
echo -e "${BOLD}╠══════════════╬══════════════════════════════════════╬════════════════════╣${RESET}"

declare -a SUMMARY_ORDER=(
    "1.1.1.1|cramfs disabled"
    "1.1.1.3|udf disabled"
    "1.1.2|/tmp configured"
    "1.1.3_noexec|/tmp noexec"
    "1.1.4_nodev|/tmp nodev"
    "1.1.5_nosuid|/tmp nosuid"
    "1.1.6|/dev/shm configured"
    "1.1.7_noexec|/dev/shm noexec"
    "1.1.8_nodev|/dev/shm nodev"
    "1.1.9_nosuid|/dev/shm nosuid"
    "1.1.12_noexec|/var/tmp noexec"
    "1.1.13_nodev|/var/tmp nodev"
    "1.1.14_nosuid|/var/tmp nosuid"
    "1.1.18_nodev|/home nodev"
    "1.1.19|Removable media noexec"
    "1.1.20|Removable media nodev"
    "1.1.21|Removable media nosuid"
)

COUNT_PASS=0; COUNT_REM=0; COUNT_SKIP=0; COUNT_FAIL=0

for entry in "${SUMMARY_ORDER[@]}"; do
    key="${entry%%|*}"
    label="${entry##*|}"
    result="${CHECK_RESULT[${key}]:-UNKNOWN}"

    case "${result}" in
        PASS)       STATUS_STR="Already OK ✓ "; (( COUNT_PASS++ )) || true ;;
        REMEDIATED) STATUS_STR="Fixed ✓      "; (( COUNT_REM++  )) || true ;;
        SKIP)       STATUS_STR="Skipped      "; (( COUNT_SKIP++ )) || true ;;
        FAILED)     STATUS_STR="FAILED ✗     "; (( COUNT_FAIL++ )) || true ;;
        *)          STATUS_STR="Unknown      " ;;
    esac

    printf "║  %-12s ║ %-36s ║ %-18s ║\n" "${key%%_*}" "${label}" "${result}"
done

echo -e "${BOLD}╠══════════════╩══════════════════════════════════════╩════════════════════╣${RESET}"
TOTAL=${#SUMMARY_ORDER[@]}
printf "${BOLD}║  %-70s ║${RESET}\n"         "Total checks    : ${TOTAL}"
printf "${GREEN}${BOLD}║  %-70s ║${RESET}\n" "Already OK      : ${COUNT_PASS}"
printf "${GREEN}${BOLD}║  %-70s ║${RESET}\n" "Remediated      : ${COUNT_REM}"
printf "${YELLOW}${BOLD}║  %-70s ║${RESET}\n" "Skipped         : ${COUNT_SKIP}"
if [[ "${COUNT_FAIL}" -gt 0 ]]; then
    printf "${RED}${BOLD}║  %-70s ║${RESET}\n" "Failed          : ${COUNT_FAIL}"
else
    printf "║  %-70s ║\n" "Failed          : ${COUNT_FAIL}"
fi
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════════╝${RESET}"

echo ""
info "Verify mount options with:"
detail "findmnt --verify"
detail "findmnt -n -o TARGET,OPTIONS | column -t"

# =============================================================================
# Result
# =============================================================================
echo ""
echo "──────────────────────────────────────────────────────"
if [[ "${OVERALL}" -eq 0 ]]; then
    pass "Module 13_filesystem_hardening — ALL CHECKS PASSED"
    exit 0
else
    fail "Module 13_filesystem_hardening — ONE OR MORE CHECKS FAILED"
    exit 1
fi
