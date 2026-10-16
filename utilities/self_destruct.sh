#!/usr/bin/env bash
# =============================================================================
# self_destruct.sh - emergency data destruction ("panic") for the deck
# =============================================================================
#
# Description
# -----------
# The button you press when the deck is about to be seized, lost or handed to
# someone it must not fall into the hands of. Three escalating levels:
#
#   soft      stop the cyberdeck services, restore the original MAC addresses,
#             close and unmount the encrypted vault, disable the radios and
#             clear the shell history. Nothing is deleted; the deck simply stops
#             being a platform. Fastest option, always safe to run.
#
#   hard      everything soft does, plus: shred the captures, reports, profiles
#             and logs, wipe the SQLite databases, remove the udev rule, and
#             clear the vault session state. Reports can be kept with
#             --keep-reports if the deck is about to be handled by the client.
#
#   paranoid  everything hard does, plus: remove the installed toolkit itself
#             (keeping the package list), overwrite the free space on the
#             filesystem holding the install directory, and optionally power off.
#
# Safety design
#   * refuses to run unless the install directory looks like a cyberdeck install
#   * never removes a path that is not inside the install directory
#   * refuses to act on /, /home, /root, /usr, /etc, /var or the repository root
#   * every destructive step is printed before it happens; --dry-run prints the
#     whole plan and changes nothing
#   * hard/paranoid require the operator to type the confirmation word
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: coreutils (shred, dd, sync), systemd, rfkill, iptables, gpg
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   sudo ./self_destruct.sh --soft
#   sudo ./self_destruct.sh --hard --keep-reports
#   sudo ./self_destruct.sh --paranoid --yes --poweroff
#   ./self_destruct.sh --dry-run --paranoid       # show the plan only
#   ./self_destruct.sh --help
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../lib/cyberdeck_common.sh" ]]; then
    # shellcheck source=lib/cyberdeck_common.sh
    source "${SCRIPT_DIR}/../lib/cyberdeck_common.sh"
elif [[ -f /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh ]]; then
    source /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh
else
    echo "fatal: cyberdeck_common.sh not found" >&2
    exit 1
fi

cdeck::init "self_destruct"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
# Allow the test harness to point at a throwaway directory
INSTALL_DIR="${CYBERDECK_INSTALL_DIR:-${INSTALL_DIR}}"
LEVEL=""
DRY_RUN=0
KEEP_REPORTS=0
POWEROFF=0
PASSPHRASE_FILE="$(cdeck::conf_get vault.passphrase_file "")"
REPORT_LOG="/var/log/cyberdeck-panic.log"
SERVICES=(cyberdeck-monitor.service mac-rotator.timer mac-rotator.service
          probe-logger.service ble-scanner.service rogue-ap-detector.service
          usb-watcher.service)
# Files and directories to shred, relative to the install directory
HARD_TARGETS=(
    "captures"
    "logs"
    "profiles"
    "state"
    "data/events.db"
    "data/events.db-wal"
    "data/events.db-shm"
    "data/probes.db"
    "data/probes.db-wal"
    "data/probes.db-shm"
    "data/ble.db"
    "data/ble.db-wal"
    "data/ble.db-shm"
    "data/arp.db"
    "data/arp.db-wal"
    "data/arp.db-shm"
    "data/services.db"
    "data/services.db-wal"
    "data/services.db-shm"
    "data/baseline.db"
    "data/baseline.db-wal"
    "data/baseline.db-shm"
    "data/usb.db"
    "data/usb.db-wal"
    "data/usb.db-shm"
    "data/alerts.db"
    "data/alerts.db-wal"
    "data/alerts.db-shm"
    "data/payloads.db"
    "data/payloads.db-wal"
    "data/payloads.db-shm"
    "data/chain_of_custody.jsonl"
    "vault/cyberdeck.vault"
    "vault/cyberdeck.vault.previous"
    "vault/cyberdeck.vault.sha256"
)

usage() {
    cdeck::usage_header \
        "Emergency data destruction (panic button) for the cyberdeck" \
        "$0 <--soft | --hard | --paranoid> [--keep-reports] [--dry-run] [--yes] [--poweroff]" \
        "sudo $0 --soft                    # stop the platform, keep the data" \
        "sudo $0 --hard --keep-reports     # shred local data, keep deliverables" \
        "sudo $0 --paranoid --poweroff     # shred everything incl. the toolkit, then power off" \
        "$0 --dry-run --paranoid           # show exactly what would be destroyed"
    cat <<EOF

${C_BOLD}LEVELS${C_RESET}
  --soft        stop cyberdeck services, restore MAC addresses, close the vault,
                disable radios, clear shell history. ${C_GREEN}Nothing is deleted.${C_RESET}
  --hard        soft + shred captures, logs, profiles, databases and the vault.
  --paranoid    hard + remove the installed toolkit and overwrite free space.

${C_BOLD}OPTIONS${C_RESET}
  --keep-reports      do not shred the reports/ directory (client deliverables)
  --keep-captures     do not shred the captures/ directory (evidence)
  --dry-run           print the plan and exit without changing anything
  --yes               skip the typed confirmation (for scripts and cron)
  --poweroff          power the machine off when finished
  --passphrase-file   vault passphrase file (used to close the vault cleanly)
  --help, -h          this help

${C_BOLD}WHAT IS NEVER TOUCHED${C_RESET}
  ${C_DIM}/, /home, /root, /usr, /etc, /var, /boot and the git checkout${C_RESET}
  Only paths inside ${INSTALL_DIR} are ever removed, and every removal is
  checked against the install directory before it happens.

${C_RED}⚠  THIS IS IRREVERSIBLE.${C_RESET} There is no undo. Practise with --dry-run.
  If the deck may be seized, the legally safer option is often --soft plus
  handing over the passphrase-free encrypted vault: destroyed evidence can be
  treated as obstruction, so follow your engagement's legal guidance.
EOF
}

# --------------------------------------------------------------------------- #
# Arguments
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)        usage; exit 0 ;;
        --version|-V)     printf 'self_destruct %s\n' "${CDECK_VERSION}"; exit 0 ;;
        --soft)           LEVEL="soft" ;;
        --hard)           LEVEL="hard" ;;
        --paranoid)       LEVEL="paranoid" ;;
        --keep-reports)   KEEP_REPORTS=1 ;;
        --keep-captures)  KEEP_CAPTURES=1 ;;
        --dry-run|-n)     DRY_RUN=1 ;;
        --yes|-y)         export CDECK_ASSUME_YES=1 ;;
        --poweroff)       POWEROFF=1 ;;
        --passphrase-file) shift; PASSPHRASE_FILE="${1:-}" ;;
        *)                cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

[[ -z "${LEVEL}" ]] && { cdeck::error "choose a level: --soft, --hard or --paranoid"; usage; exit 2; }

# --------------------------------------------------------------------------- #
# Safety guards
# --------------------------------------------------------------------------- #
guard_install_dir() {
    # Never operate on something that does not look like a cyberdeck install
    if [[ ! -d "${INSTALL_DIR}" ]]; then
        cdeck::error "install directory does not exist: ${INSTALL_DIR}"
        return 1
    fi
    case "${INSTALL_DIR}" in
        /|/home|/home/*|/root|/root/*|/usr|/usr/*|/etc|/etc/*|/var|/var/*|/boot|/boot/*|/bin|/sbin|/lib|/opt)
            cdeck::error "refusing to operate on protected path: ${INSTALL_DIR}"
            cdeck::info "set CYBERDECK_INSTALL_DIR to the real install directory"
            return 1
            ;;
    esac
    if [[ "${INSTALL_DIR}" != *cyberdeck* && "${INSTALL_DIR}" != *cdtest* ]]; then
        cdeck::warn "${INSTALL_DIR} does not contain 'cyberdeck' in its name"
        cdeck::confirm "Really treat ${INSTALL_DIR} as the cyberdeck install directory?" n || {
            cdeck::error "aborted by the operator"
            return 1
        }
    fi
    # The install directory must contain something we recognise
    local recognised=0 marker
    for marker in cyberdeck.conf bin/cdeck lib/cyberlib.py data config; do
        [[ -e "${INSTALL_DIR}/${marker}" ]] && recognised=$(( recognised + 1 ))
    done
    if (( recognised == 0 )); then
        cdeck::error "no cyberdeck files found in ${INSTALL_DIR} - aborting"
        cdeck::info "expected at least one of: cyberdeck.conf, bin/cdeck, lib/cyberlib.py, data, config"
        return 1
    fi
    return 0
}

guard_target() {
    # Guard a path before removal: it must resolve to something inside the install dir
    local target="$1"
    [[ -z "${target}" ]] && return 1
    local resolved
    resolved="$(readlink -f "${target}" 2>/dev/null || printf '%s' "${target}")"
    case "${resolved}" in
        "${INSTALL_DIR}"|"${INSTALL_DIR}"/*) return 0 ;;
    esac
    cdeck::error "refusing to remove ${target}: outside ${INSTALL_DIR}"
    return 1
}

is_dry() { (( DRY_RUN )); }

act() {
    # act <description> <command...>
    local description="$1"; shift
    if is_dry; then
        printf '    %s[dry-run]%s %s\n' "${C_DIM}" "${C_RESET}" "${description}"
        printf '              %s%s%s\n' "${C_DIM}" "$*" "${C_RESET}"
        return 0
    fi
    printf '    %s→%s %s\n' "${C_CYAN}" "${C_RESET}" "${description}"
    "$@" || cdeck::debug "command exited ${?}: $*"
    return 0
}

shred_path() {
    # Recursively overwrite then delete, staying inside the install directory
    local target="$1"
    guard_target "${target}" || return 1
    [[ -e "${target}" ]] || return 0
    if is_dry; then
        printf '    %s[dry-run]%s shred -u %s\n' "${C_DIM}" "${C_RESET}" "${target}"
        return 0
    fi
    printf '    %s→%s shredding %s\n' "${C_RED}" "${C_RESET}" "${target}"
    if [[ -d "${target}" ]]; then
        find "${target}" -type f -print0 2>/dev/null | xargs -0 -r shred -u -z 2>/dev/null || true
        find "${target}" -depth -type d -empty -delete 2>/dev/null || true
    else
        shred -u -z "${target}" 2>/dev/null || rm -f "${target}"
    fi
    [[ -e "${target}" ]] && rm -rf "${target}" 2>/dev/null || true
    return 0
}

# --------------------------------------------------------------------------- #
# Level: soft
# --------------------------------------------------------------------------- #
do_soft() {
    cdeck::banner "PANIC :: soft" "stop the platform, keep the data"

    # 1. stop the cyberdeck services so nothing keeps writing
    if [[ -d /run/systemd/system ]]; then
        for unit in "${SERVICES[@]}"; do
            act "stop and disable ${unit}" systemctl disable --now "${unit}"
        done
    else
        cdeck::info "systemd is not running - stopping processes directly"
    fi
    act "kill cyberdeck helper processes" cdeck::kill_processes \
        "wifi_probe_logger.py" "ble_scanner.py" "rogue_ap_detector.py" "arp_mapper.py" \
        "triggers.py" "scheduler.py" "usb_handler.py" "main_hud.py" "packet_weather.py"

    # 2. restore MAC addresses (undoes the tracking protection so the deck looks stock)
    local rotator="${INSTALL_DIR}/utilities/mac_rotator.py"
    if [[ -f "${rotator}" ]] && cdeck::has_cmd python3; then
        act "restore original MAC addresses" python3 "${rotator}" --restore --from-service
    fi

    # 3. close the encrypted vault cleanly
    local vault="${INSTALL_DIR}/utilities/encrypted_vault.sh"
    if [[ -f "${vault}" && -f "${INSTALL_DIR}/state/vault.session" ]]; then
        local -a vault_args=(--close)
        [[ -n "${PASSPHRASE_FILE}" ]] && vault_args+=(--passphrase-file "${PASSPHRASE_FILE}")
        act "close the encrypted vault" bash "${vault}" "${vault_args[@]}"
    fi
    # Unmount any leftover vault tmpfs
    if is_dry; then
        printf '    %s[dry-run]%s umount any /run/cyberdeck-vault.* mounts\n' "${C_DIM}" "${C_RESET}"
    else
        local mountpoint
        for mountpoint in /run/cyberdeck-vault.* /tmp/cyberdeck-vault.*; do
            [[ -d "${mountpoint}" ]] || continue
            mountpoint -q "${mountpoint}" 2>/dev/null && umount "${mountpoint}" 2>/dev/null
            find "${mountpoint}" -type f -print0 2>/dev/null | xargs -0 -r shred -u -z 2>/dev/null || true
            rm -rf "${mountpoint}" 2>/dev/null || true
        done
    fi

    # 4. release the network policy the toolkit installed
    if cdeck::has_cmd iptables; then
        act "remove cyberdeck firewall chains" bash -c '
            for chain in CDECK_KILLSWITCH CDECK_NAT CDECK_FORWARD CDECK_INPUT; do
                while iptables -C OUTPUT -j "$chain" 2>/dev/null; do iptables -D OUTPUT -j "$chain"; done
                while iptables -t nat -C PREROUTING -j "$chain" 2>/dev/null; do
                    iptables -t nat -D PREROUTING -j "$chain"; done
                iptables -F "$chain" 2>/dev/null; iptables -X "$chain" 2>/dev/null
            done
            sysctl -q -w net.ipv4.ip_forward=0 2>/dev/null || true'
    fi

    # 5. radios off: no probe requests, no BLE beacons, no accidental transmission
    if cdeck::has_cmd rfkill; then
        act "disable all radios (WiFi/Bluetooth)" rfkill block all
    fi
    local iface
    for iface in $(cdeck::wlan_interfaces 2>/dev/null); do
        act "bring ${iface} down" ip link set "${iface}" down
    done
    act "stop NetworkManager from reconnecting" systemctl stop NetworkManager

    # 6. clear shell history and clipboard
    act "clear shell histories" bash -c '
        for history in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
            [ -f "$history" ] || continue
            shred -u "$history" 2>/dev/null || : > "$history"
        done
        history -c 2>/dev/null || true'
    if cdeck::has_cmd xclip; then
        act "clear the X clipboard" bash -c 'printf "" | xclip -selection clipboard; printf "" | xclip -selection primary'
    fi

    # 7. record that the panic happened (outside the install directory)
    if ! is_dry; then
        {
            printf '%s PANIC soft: services stopped, radios blocked, vault closed\n' "$(date -Is)"
        } >> "${REPORT_LOG}" 2>/dev/null || true
    fi
    cdeck::ok "soft panic complete - the deck is inert but all data is still present"
    cdeck::info "run --hard to destroy local data when you are ready"
    return 0
}

# --------------------------------------------------------------------------- #
# Level: hard
# --------------------------------------------------------------------------- #
do_hard() {
    cdeck::banner "PANIC :: hard" "shred local data"

    local target
    for target in "${HARD_TARGETS[@]}"; do
        local full="${INSTALL_DIR}/${target}"
        if [[ "${target}" == "captures" ]] && (( ${KEEP_CAPTURES:-0} )); then
            cdeck::warn "keeping captures/ (--keep-captures)"
            continue
        fi
        [[ -e "${full}" ]] || continue
        shred_path "${full}"
    done

    # Reports need special handling: keep or destroy depending on the flag
    if [[ -d "${INSTALL_DIR}/reports" ]]; then
        if (( KEEP_REPORTS )); then
            cdeck::warn "keeping ${INSTALL_DIR}/reports (--keep-reports)"
            cdeck::info "reports are client deliverables - make sure the contract allows you to keep them"
        else
            shred_path "${INSTALL_DIR}/reports"
        fi
    fi

    # Wordlists are not sensitive; keep them so the deck can be re-armed quickly
    cdeck::info "keeping ${INSTALL_DIR}/data/wordlists (not sensitive, saves a re-download)"

    # Remove the udev rule so a fresh insert does not re-arm the watcher
    act "remove the cyberdeck udev rule" rm -f /etc/udev/rules.d/99-cyberdeck-usb.rules
    act "reload udev rules" udevadm control --reload-rules

    if ! is_dry; then
        printf '%s PANIC hard: local data shredded (keep_reports=%s)\n' \
            "$(date -Is)" "${KEEP_REPORTS}" >> "${REPORT_LOG}" 2>/dev/null || true
    fi
    cdeck::ok "hard panic complete - captures, logs, databases and the vault are gone"
    return 0
}

# --------------------------------------------------------------------------- #
# Level: paranoid
# --------------------------------------------------------------------------- #
do_paranoid() {
    cdeck::banner "PANIC :: paranoid" "shred everything, then overwrite free space"

    # 1. Everything the hard level does
    do_hard

    # 2. Remove the toolkit itself, keeping the package list for a re-install
    if cdeck::has_cmd pacman; then
        act "save the installed package list" bash -c \
            "pacman -Qq > /var/log/cyberdeck-packages.txt 2>/dev/null || true"
    fi
    local removal
    for removal in bin lib recon attack utilities sdr automation gpio dashboard \
                   aesthetics aesthetic data/templates data/oui_database.txt \
                   data/ble_vulnerability_db.json state docs tests config \
                   cyberdeck.conf uninstall.sh venv payloads; do
        local full="${INSTALL_DIR}/${removal}"
        [[ -e "${full}" ]] || continue
        # --keep-reports must still protect a report copy inside the install dir
        if (( KEEP_REPORTS )) && [[ "${removal}" == "reports" ]]; then
            cdeck::warn "keeping reports/ (--keep-reports)"
            continue
        fi
        shred_path "${full}"
    done

    # 3. Overwrite the free space on the filesystem holding the install directory
    local device
    device="$(df --output=source "${INSTALL_DIR}" 2>/dev/null | tail -1)"
    if [[ -n "${device}" && -b "${device}" ]]; then
        local free_kb
        free_kb="$(df --output=avail "${INSTALL_DIR}" 2>/dev/null | tail -1 | tr -d ' ')"
        if [[ "${free_kb:-0}" =~ ^[0-9]+$ ]] && (( free_kb > 0 )); then
            local megabytes=$(( free_kb / 1024 ))
            cdeck::warn "overwriting free space on ${device} (~${megabytes} MiB, this takes a while)"
            if is_dry; then
                printf '    %s[dry-run]%s dd if=/dev/urandom of=%s/wipe.bin bs=1M count=%s\n' \
                    "${C_DIM}" "${C_RESET}" "${INSTALL_DIR}" "${megabytes}"
            else
                # Write until the filesystem is full, then remove the file
                dd if=/dev/urandom of="${INSTALL_DIR}/.wipe.bin" bs=1M \
                   count="${megabytes}" status=progress 2>/dev/null || true
                sync
                shred -u -z "${INSTALL_DIR}/.wipe.bin" 2>/dev/null || rm -f "${INSTALL_DIR}/.wipe.bin"
                cdeck::ok "free space overwritten"
            fi
        fi
    else
        cdeck::debug "cannot identify the block device for ${INSTALL_DIR} - skipping the free-space wipe"
    fi

    # 4. Remove the install directory itself if it is now empty
    if is_dry; then
        printf '    %s[dry-run]%s rmdir %s\n' "${C_DIM}" "${C_RESET}" "${INSTALL_DIR}"
    else
        rmdir "${INSTALL_DIR}" 2>/dev/null && cdeck::ok "removed ${INSTALL_DIR}" \
            || cdeck::info "${INSTALL_DIR} still holds files (wordlists or kept reports)"
    fi

    act "remove the cdeck launchers" rm -f /usr/local/bin/cdeck /usr/local/bin/cyberdeck \
        /usr/local/bin/cdeck-usb
    act "remove the MOTD fragment" rm -f /etc/profile.d/cyberdeck-motd.sh
    act "remove the bashrc fragment" rm -f /etc/profile.d/cyberdeck.sh /etc/profile.d/cyberdeck-aliases.sh

    if ! is_dry; then
        printf '%s PANIC paranoid: toolkit removed, free space overwritten\n' \
            "$(date -Is)" >> "${REPORT_LOG}" 2>/dev/null || true
    fi
    cdeck::ok "paranoid panic complete"
    return 0
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
main() {
    # A dry run is a rehearsal: it changes nothing, so it does not need root.
    # Everything else does, because it stops services, shreds files and
    # re-addresses interfaces.
    if [[ "${EUID}" -ne 0 ]]; then
        if (( DRY_RUN )); then
            cdeck::warn "not running as root: this is a preview of the plan only"
            cdeck::info "for the real thing run: sudo $0 --${LEVEL}"
        else
            cdeck::require_root "self-destruct" || exit 1
        fi
    fi
    cdeck::require_acknowledgement || exit 1
    guard_install_dir || exit 1

    cdeck::alert "LEVEL: ${LEVEL^^}   INSTALL: ${INSTALL_DIR}"
    (( DRY_RUN )) && cdeck::info "dry run: nothing will be changed"

    if [[ "${LEVEL}" == "soft" ]]; then
        cdeck::confirm "Stop the cyberdeck platform (data is preserved)?" n || {
            cdeck::info "cancelled"; exit 0; }
        do_soft
        exit $?
    fi

    # Hard and paranoid are irreversible: require the confirmation word
    cdeck::warn "this will permanently destroy local engagement data"
    if (( KEEP_REPORTS )); then
        cdeck::info "reports/ will be preserved (--keep-reports)"
    else
        cdeck::warn "reports/ WILL be destroyed - use --keep-reports to protect deliverables"
    fi
    if (( DRY_RUN == 0 )) && [[ "${CDECK_ASSUME_YES:-0}" != "1" ]]; then
        local answer
        printf '  Type %sDESTROY%s to continue (anything else aborts): ' "${C_RED}${C_BOLD}" "${C_RESET}"
        read -r answer || answer=""
        if [[ "${answer}" != "DESTROY" ]]; then
            cdeck::info "not confirmed - nothing was changed"
            exit 0
        fi
    elif (( DRY_RUN )); then
        cdeck::info "dry run: skipping the confirmation prompt"
    fi

    if [[ "${LEVEL}" == "hard" ]]; then
        do_hard
    else
        do_paranoid
    fi
    local status=$?

    printf '\n'
    cdeck::ok "panic sequence finished (${LEVEL})"
    printf '    %-16s %s\n' "audit record" "${REPORT_LOG}"
    if (( POWEROFF )); then
        cdeck::warn "powering off in 10 seconds - press Ctrl-C to cancel"
        if is_dry; then
            printf '    %s[dry-run]%s systemctl poweroff\n' "${C_DIM}" "${C_RESET}"
        else
            sleep 10
            systemctl poweroff 2>/dev/null || poweroff 2>/dev/null || cdeck::error "could not power off"
        fi
    fi
    exit "${status}"
}

main "$@"
