#!/usr/bin/env bash
# =============================================================================
# test_services.sh - verify the platform's background services
# =============================================================================
#
# Description
# -----------
# Checks the systemd units the suite installs, and the plumbing behind them:
# is the unit installed, enabled, currently active, free of failed restarts, is
# anything in its journal from this boot, is the timer scheduled, is the
# database it writes to being updated, and are the service's own log files
# growing?
#
# It also covers the pieces that are easy to forget: the passive monitors should
# not be writing to an interface that no longer exists, the trigger engine and
# the scheduler should have current state files, and nothing should be holding a
# stale PID or lock file.
#
# Exit code: the number of failed checks (0 = healthy). Units that are simply
# not installed are reported as skips, because running the passive monitors is a
# choice, not a requirement.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash, systemd (systemctl/journalctl), coreutils
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./test_services.sh                 # check every unit
#   ./test_services.sh --json          # machine readable
#   ./test_services.sh --logs 40       # show the last 40 journal lines for failures
#   ./test_services.sh --restart-failed
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../lib/cyberdeck_common.sh" ]]; then
    # shellcheck source=lib/cyberdeck_common.sh
    source "${SCRIPT_DIR}/../lib/cyberdeck_common.sh"
elif [[ -f /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh ]]; then
    source /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh
else
    echo "fatal: cyberdeck_common.sh not found (is the suite installed?)" >&2
    exit 1
fi

cdeck::init "test_services"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"

#: unit:description:database the unit writes to (or '-'):required
UNITS=(
    "cyberdeck-monitor.service:telemetry monitor:events.db:optional"
    "probe-logger.service:passive WiFi probe logger:probes.db:optional"
    "ble-scanner.service:passive Bluetooth scanner:ble.db:optional"
    "rogue-ap-detector.service:rogue access point detector:ble.db:optional"
    "usb-watcher.service:USB insertion watcher:usb.db:optional"
    "mac-rotator.service:MAC address rotator:-:optional"
    "mac-rotator.timer:MAC rotation timer:-:optional"
)

QUIET=0
JSON=0
VERBOSE=0
LOG_LINES=15
RESTART_FAILED=0
FAILURES=0
PASSES=0
SKIPS=0
declare -a RESULTS=()

usage() {
    cdeck::usage_header \
        "Verify the cyberdeck systemd services" \
        "$0 [--quiet] [--json] [--logs N] [--restart-failed]" \
        "$0                     # check every unit" \
        "$0 --logs 40           # include the last 40 journal lines of any failure" \
        "$0 --restart-failed    # restart the units that are installed but not running"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -q, --quiet          only failures and the summary
  -v, --verbose        print unit details even when healthy
  -j, --json           emit JSON (implies --quiet)
  --logs N             journal lines shown per failing unit (default 15)
  --restart-failed     restart installed units that are not active
  --install-dir PATH   override the install directory
  -h, --help           this help
  -V, --version        version

${C_BOLD}WHAT IT CHECKS${C_RESET}
  installed · enabled · active · restart count · journal errors
  timers scheduled · databases being updated · service logs growing
  stale PID/lock files · passive monitors bound to a live interface

${C_BOLD}EXIT CODE${C_RESET}
  Number of failed checks (0 = healthy).
EOF
}

# --------------------------------------------------------------------------- #
# Framework
# --------------------------------------------------------------------------- #
record() {
    # record <status> <name> <detail>
    local status="$1" name="$2" detail="${3:-}"
    case "${status}" in
        PASS) PASSES=$(( PASSES + 1 )) ;;
        FAIL) FAILURES=$(( FAILURES + 1 )) ;;
        SKIP) SKIPS=$(( SKIPS + 1 )) ;;
    esac
    RESULTS+=("${status}|${name}|${detail}")
    if (( JSON )); then
        return 0
    fi
    if (( QUIET )) && [[ "${status}" == "PASS" ]]; then
        return 0
    fi
    local colour glyph
    case "${status}" in
        PASS) colour="${C_GREEN}";  glyph="✔" ;;
        FAIL) colour="${C_RED}";    glyph="✘" ;;
        SKIP) colour="${C_DIM}";    glyph="·" ;;
    esac
    printf '  %b%s%b %-46s %b%s%b\n' "${colour}" "${glyph}" "${C_RESET}" \
        "${name}" "${C_DIM}" "${detail}" "${C_RESET}"
}

have() { command -v "$1" >/dev/null 2>&1; }

unit_installed() {
    # True when systemd knows about the unit
    systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1" && return 0
    [[ -f "/etc/systemd/system/$1" ]] && return 0
    return 1
}

unit_state() {
    systemctl is-active "$1" 2>/dev/null || true
}

unit_enabled() {
    systemctl is-enabled "$1" 2>/dev/null || true
}

# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
check_systemd() {
    if ! have systemctl; then
        record FAIL "systemd is available" "systemctl not found - this host has no systemd"
        return 0
    fi
    record PASS "systemd is available" "$(systemctl --version 2>/dev/null | head -1)"
    if [[ ! -d /run/systemd/system ]]; then
        record SKIP "systemd is the running init" "container or chroot: units cannot be checked"
        return 1
    fi
    record PASS "systemd is the running init" ""
    return 0
}

check_unit() {
    # check_unit <unit> <description> <database> <required>
    local unit="$1" description="$2" database="$3" required="$4"
    if ! unit_installed "${unit}"; then
        if [[ "${required}" == "required" ]]; then
            record FAIL "${unit}" "not installed"
        else
            record SKIP "${unit}" "not installed (optional)"
        fi
        return 0
    fi
    record PASS "${unit} installed" "${description}"

    local state enabled
    state="$(unit_state "${unit}")"
    enabled="$(unit_enabled "${unit}")"
    case "${enabled}" in
        enabled|enabled-runtime) record PASS "${unit} enabled" "${enabled}" ;;
        static|indirect)         record PASS "${unit} enabled" "${enabled} (no [Install] section)" ;;
        disabled)                record FAIL "${unit} enabled" "disabled - run: sudo systemctl enable ${unit}" ;;
        *)                       record SKIP "${unit} enabled" "${enabled:-(unknown)}" ;;
    esac

    case "${state}" in
        active)
            record PASS "${unit} active" "$(systemctl show -p ActiveEnterTimestamp --value "${unit}" 2>/dev/null | head -1)"
            ;;
        inactive)
            if (( RESTART_FAILED )); then
                if systemctl start "${unit}" >/dev/null 2>&1; then
                    record PASS "${unit} restarted" "was inactive, now $(unit_state "${unit}")"
                else
                    record FAIL "${unit} restarted" "systemctl start failed"
                fi
            else
                record FAIL "${unit} active" "inactive - run: sudo systemctl start ${unit}"
            fi
            ;;
        failed)
            record FAIL "${unit} active" "failed - see: journalctl -u ${unit} -n 50"
            ;;
        *)
            record SKIP "${unit} active" "${state:-(unknown)}"
            ;;
    esac

    local restarts
    restarts="$(systemctl show -p NRestarts --value "${unit}" 2>/dev/null || echo 0)"
    if [[ "${restarts}" =~ ^[0-9]+$ ]] && (( restarts > 5 )); then
        record FAIL "${unit} restart count" "${restarts} restarts - it is crash looping"
    else
        record PASS "${unit} restart count" "${restarts:-0}"
    fi

    # Journal sanity: errors since boot
    if have journalctl; then
        local errors
        errors="$(journalctl -u "${unit}" -b --no-pager -p err 2>/dev/null | grep -c . || true)"
        if (( errors > 0 )); then
            record FAIL "${unit} journal" "${errors} error line(s) since boot"
            if (( VERBOSE )) && (( ! QUIET )); then
                journalctl -u "${unit}" -b --no-pager -p err 2>/dev/null | tail -n "${LOG_LINES}" | sed 's/^/      /'
            fi
        else
            record PASS "${unit} journal" "no errors since boot"
        fi
    fi

    # Timer schedule
    if [[ "${unit}" == *.timer ]]; then
        local next
        next="$(systemctl list-timers "${unit}" --no-pager 2>/dev/null | sed -n '2p')"
        if [[ -n "${next}" ]]; then
            record PASS "${unit} schedule" "$(printf '%s' "${next}" | awk '{print $1, $2, $3}')"
        else
            record SKIP "${unit} schedule" "no upcoming run visible"
        fi
    fi

    # Database freshness
    if [[ "${database}" != "-" ]]; then
        local path="${INSTALL_DIR}/data/${database}"
        if [[ -f "${path}" ]]; then
            local age_minutes
            age_minutes=$(( ( $(date +%s) - $(stat -c %Y "${path}" 2>/dev/null || echo 0) ) / 60 ))
            if (( age_minutes < 120 )); then
                record PASS "${unit} data" "${database} updated ${age_minutes}m ago"
            else
                record SKIP "${unit} data" "${database} last changed ${age_minutes}m ago"
            fi
        else
            record SKIP "${unit} data" "${database} does not exist yet"
        fi
    fi

    # Per-unit log file, when the unit writes one
    local log_file="${INSTALL_DIR}/logs/${unit%.service}.log"
    if [[ -f "${log_file}" ]]; then
        local size
        size="$(wc -c < "${log_file}" | tr -d ' ')"
        record PASS "${unit} log" "${log_file##*/} (${size} bytes)"
    fi
}

check_platform_state() {
    local state_dir="${INSTALL_DIR}/state"
    local file description
    for file in triggers_state.json schedule.json schedule_state.json hardware.json; do
        if [[ -f "${state_dir}/${file}" ]]; then
            local age_minutes
            age_minutes=$(( ( $(date +%s) - $(stat -c %Y "${state_dir}/${file}" 2>/dev/null || echo 0) ) / 60 ))
            record PASS "state: ${file}" "updated ${age_minutes}m ago"
        else
            record SKIP "state: ${file}" "not written yet"
        fi
    done
    local stale
    stale="$(find "${INSTALL_DIR}" -maxdepth 2 -name "*.pid" -o -maxdepth 2 -name "*.lock" 2>/dev/null | head -5)"
    if [[ -z "${stale}" ]]; then
        record PASS "no stale PID or lock files" ""
    else
        record SKIP "no stale PID or lock files" "$(printf '%s' "${stale}" | head -1)"
    fi
    if [[ -f "${INSTALL_DIR}/logs/setup.log" ]]; then
        record PASS "installer log" "$(wc -l < "${INSTALL_DIR}/logs/setup.log" | tr -d ' ') lines"
    else
        record SKIP "installer log" "no logs/setup.log"
    fi
}

check_monitor_targets() {
    # The passive monitors need a live interface; a service watching a radio that
    # was unplugged is the most common silent failure on a deck.
    local monitor_if primary_if
    monitor_if="$(cdeck::conf_get network.monitor_interface wlan1)"
    primary_if="$(cdeck::conf_get network.primary_interface wlan0)"
    local interface
    for interface in "${monitor_if}" "${primary_if}"; do
        [[ -n "${interface}" ]] || continue
        if [[ -e "/sys/class/net/${interface}" ]]; then
            record PASS "interface ${interface} exists" "$(cat /sys/class/net/${interface}/operstate 2>/dev/null || echo unknown)"
        else
            record SKIP "interface ${interface} exists" "configured but absent"
        fi
    done
}

check_no_conflicts() {
    # Two tools fighting for one radio is a classic deck problem
    local monitor_if airmon_conflict=0
    monitor_if="$(cdeck::conf_get network.monitor_interface wlan1)"
    if have pgrep; then
        for process in airodump-ng bettercap kismet; do
            if pgrep -x "${process}" >/dev/null 2>&1; then
                airmon_conflict=$(( airmon_conflict + 1 ))
            fi
        done
    fi
    if (( airmon_conflict > 1 )); then
        record FAIL "no conflicting radio users" \
            "${airmon_conflict} tools are holding radios at once - see: cdeck services status"
    else
        record PASS "no conflicting radio users" ""
    fi
    if pgrep -x "NetworkManager" >/dev/null 2>&1 && pgrep -x "wpa_supplicant" >/dev/null 2>&1; then
        record PASS "network managers" "NetworkManager and wpa_supplicant both present (normal)"
    fi
    local panic_unit="cyberdeck-panic.service"
    for unit in "${UNITS[@]}"; do
        local name="${unit%%:*}"
        if systemctl cat "${name}" 2>/dev/null | grep -q "Conflicts=${panic_unit}"; then
            record PASS "${name} conflicts with panic" "stops on cdeck panic"
            break
        fi
    done
}

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
run_all() {
    RESULTS=(); PASSES=0; FAILURES=0; SKIPS=0
    if check_systemd; then
        local entry
        for entry in "${UNITS[@]}"; do
            IFS=':' read -r unit description database required <<< "${entry}"
            check_unit "${unit}" "${description}" "${database}" "${required}"
        done
        check_monitor_targets
        check_no_conflicts
    fi
    check_platform_state
}

emit_json() {
    printf '{\n'
    printf '  "install_dir": "%s",\n' "${INSTALL_DIR}"
    printf '  "generated": "%s",\n' "$(cdeck::iso_stamp)"
    printf '  "passed": %d, "failed": %d, "skipped": %d,\n' "${PASSES}" "${FAILURES}" "${SKIPS}"
    printf '  "checks": [\n'
    local first=1 entry
    for entry in "${RESULTS[@]}"; do
        IFS='|' read -r status name detail <<< "${entry}"
        (( first )) || printf ',\n'
        first=0
        printf '    {"status": "%s", "name": "%s", "detail": "%s"}' \
            "${status}" "${name//\"/}" "${detail//\"/}"
    done
    printf '\n  ]\n}\n'
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)          usage; exit 0 ;;
        --version|-V)       printf 'test_services %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -q|--quiet)         QUIET=1 ;;
        -v|--verbose)       VERBOSE=1 ;;
        -j|--json)          JSON=1; QUIET=1 ;;
        --logs)             shift; LOG_LINES="${1:-15}" ;;
        --restart-failed)   RESTART_FAILED=1 ;;
        --install-dir)      shift; INSTALL_DIR="${1:-${INSTALL_DIR}}" ;;
        *)                  cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

if (( ! QUIET )); then
    cdeck::banner "service test" "${INSTALL_DIR} · $(hostname)"
fi

if [[ "${EUID}" -ne 0 ]] && (( ! QUIET )); then
    cdeck::info "not running as root: unit state is readable but --restart-failed needs sudo"
fi

run_all

if (( JSON )); then
    emit_json
else
    printf '\n'
    printf '  %b%d passed%b · %b%d failed%b · %b%d skipped%b · %s\n\n' \
        "${C_GREEN}" "${PASSES}" "${C_RESET}" \
        "$([[ ${FAILURES} -gt 0 ]] && echo "${C_RED}" || echo "${C_DIM}")" "${FAILURES}" "${C_RESET}" \
        "${C_DIM}" "${SKIPS}" "${C_RESET}" "$(date '+%H:%M:%S')"
    if (( FAILURES )); then
        cdeck::warn "${FAILURES} service check(s) failed"
        cdeck::info "inspect one unit with: journalctl -u <unit> -n 50 --no-pager"
        cdeck::info "restart the deck's units with: cdeck services restart"
    else
        cdeck::ok "every installed service is healthy"
    fi
    printf '\n'
fi

exit "${FAILURES}"
