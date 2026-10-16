#!/usr/bin/env bash
# =============================================================================
# motd.sh - the deck's message of the day
# =============================================================================
#
# Description
# -----------
# Prints the login banner: identity block, the active theme's art or banner,
# live vitals (uptime, load, memory, disk, battery, temperature), network and
# wireless state, SDR presence, service health, the newest alerts from the
# shared database and the day's key bindings.
#
# Every panel degrades on its own: a laptop with no SDR simply does not get the
# SDR line, a host without sysfs battery data skips it, and -short (used by the
# shell profiles) prints a four-line version that costs almost nothing.
#
# It is installed by setup.sh as /etc/profile.d/cyberdeck-motd.sh, which calls
# this script with --login so the full banner appears once per login shell, and
# --short for every other shell.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash, coreutils; optional: figlet/toilet, lolcat, sqlite3, python3
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./motd.sh              # full banner
#   ./motd.sh --short      # four lines (shell start-up)
#   ./motd.sh --quiet      # one line, machine friendly
#   ./motd.sh --json       # everything as JSON
#   ./motd.sh --no-colour  # for serial consoles and log capture
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../lib/cyberdeck_common.sh" ]]; then
    # shellcheck source=lib/cyberdeck_common.sh
    source "${SCRIPT_DIR}/../lib/cyberdeck_common.sh"
elif [[ -f /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh ]]; then
    source /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh
else
    # A MOTD must never break a login: fall back to plain output
    printf 'cyberdeck-arsenal: cyberdeck_common.sh not found - check the installation\n'
    exit 0
fi

cdeck::init "motd"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
CONF_FILE="${CDECK_CONFIG:-${INSTALL_DIR}/cyberdeck.conf}"
THEME_ENV="${INSTALL_DIR}/state/theme.env"
THEME_DIR="${INSTALL_DIR}/aesthetic/themes"

MODE="full"
USE_COLOUR=1
USE_ART=1
SHOW_ALERTS=1
SHOW_TIPS=1
JSON=0

usage() {
    cdeck::usage_header \
        "Print the cyberdeck login banner" \
        "$0 [--full | --short | --quiet | --json] [--no-colour] [--no-art] [--no-alerts]" \
        "$0                 # full banner" \
        "$0 --short         # four lines, used by the shell profiles" \
        "$0 --json          # machine-readable snapshot"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -f, --full             full banner (default)
  -s, --short            four-line summary
  -q, --quiet            a single status line
  --json                 emit the whole snapshot as JSON
  --no-colour            disable ANSI colour
  --no-art               skip the ASCII art
  --no-alerts            skip the alert feed
  --no-tips              skip the hint block
  -h, --help             this help
  -V, --version          version
EOF
}

# --------------------------------------------------------------------------- #
# Data collection
# --------------------------------------------------------------------------- #
theme_name() {
    local theme=""
    if [[ -f "${THEME_ENV}" ]]; then
        theme="$(grep -E '^THEME_NAME=' "${THEME_ENV}" | tail -1 | cut -d= -f2-)"
    fi
    [[ -n "${theme}" ]] || theme="$(cdeck::conf_get display.theme cyberpunk)"
    printf '%s' "${theme}"
}

theme_field() {
    local key="$1" default="${2:-}" theme file value
    theme="$(theme_name)"
    file="${THEME_DIR}/${theme}.theme"
    [[ -f "${file}" ]] || { printf '%s' "${default}"; return 0; }
    value="$(grep -E "^[[:space:]]*${key}=" "${file}" | tail -1 | cut -d= -f2-)"
    [[ -n "${value}" ]] || { printf '%s' "${default}"; return 0; }
    value="${value#\'}"; value="${value%\'}"
    value="${value#\"}"; value="${value%\"}"
    printf '%s' "${value}"
}

collect_vitals() {
    UPTIME_TEXT="$(uptime -p 2>/dev/null | sed 's/^up //' || echo unknown)"
    LOAD_AVG="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo '-')"
    MEM_TEXT="$(free -h 2>/dev/null | awk 'NR==2 {printf "%s/%s", $3, $2}' || echo '-')"
    DISK_TEXT="$(df -h "${INSTALL_DIR}" 2>/dev/null | awk 'NR==2 {printf "%s/%s (%s)", $3, $2, $5}' || echo '-')"
    DISK_PCT="$(df --output=pcent "${INSTALL_DIR}" 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)"
    BATTERY_TEXT=""; BATTERY_PCT=""
    local battery
    for battery in /sys/class/power_supply/BAT*/capacity; do
        [[ -r "${battery}" ]] || continue
        BATTERY_PCT="$(cat "${battery}" 2>/dev/null || echo '')"
        local status_file="${battery%capacity}status"
        local status=""
        [[ -r "${status_file}" ]] && status="$(cat "${status_file}" 2>/dev/null)"
        BATTERY_TEXT="${BATTERY_PCT}% ${status}"
        break
    done
    TEMP_TEXT=""
    local zone
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        [[ -r "${zone}" ]] || continue
        local raw; raw="$(cat "${zone}" 2>/dev/null || echo 0)"
        (( raw > 1000 )) && raw=$(( raw / 1000 ))
        TEMP_TEXT="${raw}C"
        break
    done
    KERNEL="$(uname -r)"
    BOARD="$(cdeck::conf_get general.operator_name operator)"
}

collect_network() {
    LOCAL_IP=""
    PRIMARY_IF=""
    PRIMARY_IF="$(cdeck::default_interface 2>/dev/null || true)"
    if [[ -z "${PRIMARY_IF}" ]]; then
        PRIMARY_IF="$(cd / && ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
    fi
    if [[ -n "${PRIMARY_IF}" ]]; then
        LOCAL_IP="$(cd / && ip -o -4 addr show dev "${PRIMARY_IF}" 2>/dev/null | awk '{print $4; exit}')"
    fi
    WIFI_STATE=""
    if [[ -n "${PRIMARY_IF}" ]]; then
        local essid
        essid="$(iwgetid -r "${PRIMARY_IF}" 2>/dev/null || true)"
        if [[ -n "${essid}" ]]; then
            WIFI_STATE="${essid}"
        elif cdeck::has_cmd iw; then
            WIFI_STATE="$(cd / && iw dev "${PRIMARY_IF}" link 2>/dev/null | awk '/SSID/ {print $2; exit}')"
        fi
    fi
    MONITOR_IF="$(cdeck::monitor_interface 2>/dev/null || true)"
    MONITOR_STATE="no"
    [[ -n "${MONITOR_IF}" ]] && MONITOR_STATE="yes (${MONITOR_IF})"
    [[ -n "${MONITOR_IF}" ]] || MONITOR_STATE="no"
    VPN_STATE="off"
    cd / 2>/dev/null || true
    if [[ -n "$(cdeck::wireguard_interfaces)" ]]; then
        VPN_STATE="wireguard"
    elif pgrep -x openvpn >/dev/null 2>&1; then
        VPN_STATE="openvpn"
    elif pgrep -x tor >/dev/null 2>&1; then
        VPN_STATE="tor"
    fi
    SDR_STATE="none"
    if [[ -e /dev/rtl_sdr ]] || lsusb 2>/dev/null | grep -qiE "RTL2838|RTL2832|Realtek.*DVB"; then
        SDR_STATE="rtl-sdr"
    elif lsusb 2>/dev/null | grep -qiE "HackRF|Great Scott"; then
        SDR_STATE="hackrf"
    fi
    TOR_STATE="off"
    if pgrep -x tor >/dev/null 2>&1; then TOR_STATE="on"; fi
}

collect_services() {
    SERVICE_LINES=""
    local -a units=(cyberdeck-monitor.service probe-logger.service ble-scanner.service
                    rogue-ap-detector.service usb-watcher.service mac-rotator.timer)
    local unit state
    for unit in "${units[@]}"; do
        state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
        [[ -z "${state}" ]] && state="absent"
        SERVICE_LINES+="${unit%% *}|${state}"$'\n'
    done
}

collect_alerts() {
    ALERT_LINES=""
    ALERT_COUNT=0
    local db="${INSTALL_DIR}/data/events.db"
    [[ -f "${db}" ]] || { db="${HOME}/.cyberdeck-arsenal/data/events.db"; }
    [[ -f "${db}" ]] || return 0
    if cdeck::has_cmd sqlite3; then
        ALERT_LINES="$(sqlite3 -separator '|' "file:${db}?mode=ro" \
            "SELECT ts, severity, message FROM alerts ORDER BY id DESC LIMIT 4;" 2>/dev/null || true)"
        ALERT_COUNT="$(sqlite3 "file:${db}?mode=ro" \
            "SELECT COUNT(*) FROM alerts WHERE ts >= datetime('now','-1 day');" 2>/dev/null || echo 0)"
    elif cdeck::has_cmd python3; then
        local output
        output="$(python3 - "${db}" <<'PYEOF' 2>/dev/null || true
import sqlite3, sys
try:
    with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as connection:
        rows = connection.execute(
            "SELECT ts, severity, message FROM alerts ORDER BY id DESC LIMIT 4").fetchall()
        count = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE ts >= datetime('now','-1 day')").fetchone()[0]
    for row in rows:
        print("|".join("" if value is None else str(value).replace("\n", " ") for value in row))
    print(f"@count={count}")
except Exception:
    pass
PYEOF
)"
        ALERT_LINES="$(printf '%s\n' "${output}" | grep -v '^@count=' || true)"
        ALERT_COUNT="$(printf '%s\n' "${output}" | sed -n 's/^@count=//p' | head -1)"
        ALERT_COUNT="${ALERT_COUNT:-0}"
    fi
}

collect_engagements() {
    ENGAGEMENT_LINES=""
    local dir="${INSTALL_DIR}/reports"
    [[ -d "${dir}" ]] || return 0
    local engagement
    while IFS= read -r engagement; do
        ENGAGEMENT_LINES+="${engagement}"$'\n'
    done < <(find "${dir}" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | sort -r | head -3)
}

collect_all() {
    collect_vitals
    collect_network
    collect_services
    collect_alerts
    collect_engagements
}

# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
colour_for_state() {
    case "$1" in
        active|yes|on|up)     printf '%s' "${C_GREEN}" ;;
        inactive|absent|off)  printf '%s' "${C_DIM}" ;;
        failed|down)          printf '%s' "${C_RED}" ;;
        *)                    printf '%s' "${C_YELLOW}" ;;
    esac
}

render_json() {
    collect_all
    local esc_alerts esc_services
    esc_alerts="$(printf '%s' "${ALERT_LINES}" | python3 -c 'import json,sys; print(json.dumps([l for l in sys.stdin.read().splitlines() if l]))' 2>/dev/null || echo '[]')"
    esc_services="$(printf '%s' "${SERVICE_LINES}" | python3 -c 'import json,sys; print(json.dumps(dict(l.split("|",1) for l in sys.stdin.read().splitlines() if "|" in l)))' 2>/dev/null || echo '{}')"
    cat <<EOF
{
  "version": "${CDECK_VERSION}",
  "theme": "$(theme_name)",
  "operator": "${BOARD}",
  "hostname": "$(hostname)",
  "kernel": "${KERNEL}",
  "uptime": "${UPTIME_TEXT}",
  "load": "${LOAD_AVG}",
  "memory": "${MEM_TEXT}",
  "disk": "${DISK_TEXT}",
  "disk_percent": ${DISK_PCT:-0},
  "battery": "${BATTERY_TEXT}",
  "temperature": "${TEMP_TEXT}",
  "interface": "${PRIMARY_IF}",
  "address": "${LOCAL_IP}",
  "wifi": "${WIFI_STATE}",
  "monitor": "${MONITOR_STATE}",
  "vpn": "${VPN_STATE}",
  "tor": "${TOR_STATE}",
  "sdr": "${SDR_STATE}",
  "alerts_24h": ${ALERT_COUNT:-0},
  "services": ${esc_services},
  "recent_alerts": ${esc_alerts}
}
EOF
}

render_quiet() {
    collect_all
    printf 'cyberdeck %s | %s | %s | %s | %s alerts/24h | vpn %s | sdr %s\n' \
        "$(hostname)" "${UPTIME_TEXT}" "${MEM_TEXT}" "${DISK_TEXT}" \
        "${ALERT_COUNT:-0}" "${VPN_STATE}" "${SDR_STATE}"
}

render_short() {
    collect_all
    local theme; theme="$(theme_name)"
    printf '%b◆ cyberdeck-arsenal%b %s · %s · theme %s\n' \
        "${C_GREEN}" "${C_RESET}" "$(hostname)" "${BOARD}" "${theme}"
    printf '  %bload%b %s   %bmem%b %s   %bdisk%b %s' \
        "${C_DIM}" "${C_RESET}" "${LOAD_AVG}" \
        "${C_DIM}" "${C_RESET}" "${MEM_TEXT}" \
        "${C_DIM}" "${C_RESET}" "${DISK_TEXT}"
    [[ -n "${BATTERY_PCT}" ]] && printf '   %bbattery%b %s' "${C_DIM}" "${C_RESET}" "${BATTERY_TEXT}"
    [[ -n "${TEMP_TEXT}" ]] && printf '   %btemp%b %s' "${C_DIM}" "${C_RESET}" "${TEMP_TEXT}"
    printf '\n'
    printf '  %bnet%b %s/%s' "${C_DIM}" "${C_RESET}" "${PRIMARY_IF:-none}" "${LOCAL_IP:-no address}"
    [[ -n "${WIFI_STATE}" ]] && printf ' (%s)' "${WIFI_STATE}"
    printf '   %bvpn%b %s   %balerts%b %s/24h\n' \
        "${C_DIM}" "${C_RESET}" "${VPN_STATE}" "${C_DIM}" "${C_RESET}" "${ALERT_COUNT:-0}"
    printf '  %btype%b %bcdeck%b for the HUD · %bcdeck help%b for commands · %bC-a ?%b in tmux\n' \
        "${C_DIM}" "${C_RESET}" "${C_BOLD}" "${C_RESET}" \
        "${C_BOLD}" "${C_RESET}" "${C_BOLD}" "${C_RESET}"
}

rule() {
    local width="${1:-78}" colour="${2:-${C_DIM}}"
    printf '%b%s%b\n' "${colour}" "$(printf '─%.0s' $(seq 1 "${width}"))" "${C_RESET}"
}

# theme_colour <#rrggbb> -> a true-colour escape, or nothing when colour is off
theme_colour() {
    local hex="${1#\#}"
    (( USE_COLOUR )) || { printf ''; return 0; }
    [[ "${hex}" =~ ^[0-9a-fA-F]{6}$ ]] || { printf ''; return 0; }
    printf '\033[38;2;%d;%d;%dm' "0x${hex:0:2}" "0x${hex:2:2}" "0x${hex:4:2}"
}

panel() {
    # panel <title> <body-file>
    local title="$1" body="$2"
    printf '  %b%s%b\n' "${C_BOLD}" "${title}" "${C_RESET}"
    sed 's/^/  /' "${body}"
    printf '\n'
}

render_full() {
    collect_all
    local theme primary secondary accent
    theme="$(theme_name)"
    primary="$(theme_colour "$(theme_field THEME_PRIMARY '#39ff14')")"
    secondary="$(theme_colour "$(theme_field THEME_SECONDARY '#00d9ff')")"
    accent="$(theme_colour "$(theme_field THEME_ACCENT '#ff2e88')")"

    if (( USE_ART )); then
        local art
        art="$(theme_field THEME_SPLASH_ART '')"
        if [[ -n "${art}" ]]; then
            printf '%b' "${primary}"
            printf '%s\n' "${art}"
            printf '%b' "${C_RESET}"
        else
            printf '\n  %b██%b cyberdeck-arsenal %b%s%b · %s\n\n' \
                "${primary}" "${C_RESET}" "${secondary}" "${CDECK_VERSION}" "${C_RESET}"
        fi
        local tagline
        tagline="$(theme_field THEME_SPLASH_TAGLINE '')"
        [[ -n "${tagline}" ]] && printf '  %b%s%b\n' "${C_DIM}" "${tagline}" "${C_RESET}"
    else
        printf '\n  %bcyberdeck-arsenal%b %s\n' "${C_BOLD}" "${C_RESET}" "${CDECK_VERSION}"
    fi
    printf '\n'

    printf '  %b◆ system%b\n' "${C_BOLD}" "${C_RESET}"
    rule
    printf '    %-14s %s\n' "host" "$(hostname) · ${BOARD}"
    printf '    %-14s %s\n' "kernel" "${KERNEL}"
    printf '    %-14s %s\n' "uptime" "${UPTIME_TEXT}"
    printf '    %-14s %s\n' "load" "${LOAD_AVG}"
    printf '    %-14s %s\n' "memory" "${MEM_TEXT}"
    if (( DISK_PCT >= 90 )); then
        printf '    %-14s %b%s%b\n' "disk" "${C_RED}" "${DISK_TEXT}" "${C_RESET}"
    else
        printf '    %-14s %s\n' "disk" "${DISK_TEXT}"
    fi
    [[ -n "${BATTERY_TEXT}" ]] && printf '    %-14s %s\n' "battery" "${BATTERY_TEXT}"
    [[ -n "${TEMP_TEXT}" ]] && printf '    %-14s %s\n' "temperature" "${TEMP_TEXT}"
    printf '\n'

    printf '  %b◆ network%b\n' "${C_BOLD}" "${C_RESET}"
    rule
    printf '    %-14s %s\n' "interface" "${PRIMARY_IF:-none} ${LOCAL_IP:+(}${LOCAL_IP}${LOCAL_IP:+)}"
    [[ -n "${WIFI_STATE}" ]] && printf '    %-14s %s\n' "ssid" "${WIFI_STATE}"
    printf '    %-14s %s\n' "monitor" "${MONITOR_STATE}"
    printf '    %-14s %b%s%b\n' "vpn" "$(colour_for_state "${VPN_STATE}")" "${VPN_STATE}" "${C_RESET}"
    printf '    %-14s %s\n' "tor" "${TOR_STATE}"
    if [[ "${SDR_STATE}" == "none" ]]; then
        printf '    %-14s %b%s%b\n' "sdr" "${C_DIM}" "not connected" "${C_RESET}"
    else
        printf '    %-14s %b%s%b\n' "sdr" "${C_GREEN}" "${SDR_STATE}" "${C_RESET}"
    fi
    printf '\n'

    printf '  %b◆ services%b\n' "${C_BOLD}" "${C_RESET}"
    rule
    local line unit state colour
    while IFS='|' read -r unit state; do
        [[ -n "${unit}" ]] || continue
        colour="$(colour_for_state "${state}")"
        printf '    %b%-7s%b %s\n' "${colour}" "${state}" "${C_RESET}" "${unit}"
    done <<< "${SERVICE_LINES}"
    printf '\n'

    if (( SHOW_ALERTS )); then
        printf '  %b◆ alerts%b %b(%s in the last 24h)%b\n' \
            "${C_BOLD}" "${C_RESET}" "${C_DIM}" "${ALERT_COUNT:-0}" "${C_RESET}"
        rule
        if [[ -z "${ALERT_LINES}" ]]; then
            printf '    %bno alerts recorded - see cdeck status%b\n' "${C_DIM}" "${C_RESET}"
        else
            local severity_colour
            while IFS='|' read -r ts severity message; do
                [[ -n "${message}" ]] || continue
                case "${severity}" in
                    CRITICAL|ALERT) severity_colour="${C_RED}" ;;
                    ERROR|HIGH)     severity_colour="${C_RED}" ;;
                    WARNING|MEDIUM) severity_colour="${C_YELLOW}" ;;
                    *)              severity_colour="${C_DIM}" ;;
                esac
                printf '    %b%-8s%b %s  %b%s%b\n' \
                    "${severity_colour}" "${severity}" "${C_RESET}" \
                    "${ts:0:19}" "${C_DIM}" "${message:0:54}" "${C_RESET}"
            done <<< "${ALERT_LINES}"
        fi
        printf '\n'
    fi

    if [[ -n "${ENGAGEMENT_LINES}" ]]; then
        printf '  %b◆ active engagements%b\n' "${C_BOLD}" "${C_RESET}"
        rule
        while IFS= read -r engagement; do
            [[ -n "${engagement}" ]] || continue
            printf '    %s\n' "${engagement}"
        done <<< "${ENGAGEMENT_LINES}"
        printf '\n'
    fi

    if (( SHOW_TIPS )); then
        printf '  %b◆ start here%b\n' "${C_BOLD}" "${C_RESET}"
        rule
        printf '    %bcdeck%b            launch the main HUD\n' "${C_BOLD}" "${C_RESET}"
        printf '    %bcdeck scan <ip>%b   discover hosts on the local segment\n' "${C_BOLD}" "${C_RESET}"
        printf '    %bcdeck status%b      full platform status\n' "${C_BOLD}" "${C_RESET}"
        printf '    %bcdeck help%b        every command\n' "${C_BOLD}" "${C_RESET}"
        printf '    %bengage <name>%b     start a timestamped engagement directory\n' "${C_BOLD}" "${C_RESET}"
        printf '\n'
        printf '  %b⚠  authorised use only%b - you must have written permission for every\n' \
            "${C_YELLOW}" "${C_RESET}"
        printf '     network, device and frequency you touch. See docs/LEGAL.md\n\n'
    fi
    rule 78 "${secondary}"
    printf '\n'
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)      usage; exit 0 ;;
        --version|-V)   printf 'motd %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -f|--full)      MODE="full" ;;
        -s|--short)     MODE="short" ;;
        -q|--quiet)     MODE="quiet" ;;
        --json)         JSON=1; MODE="json" ;;
        --no-art)       USE_ART=0 ;;
        --no-colour|--no-color) USE_COLOUR=0 ;;
        --no-alerts)    SHOW_ALERTS=0 ;;
        --no-tips)      SHOW_TIPS=0 ;;
        --login)        MODE="full" ;;
        *)              : ;;   # A stray argument must not break somebody's login
    esac
    shift
done

if (( USE_COLOUR == 0 )) || [[ ! -t 1 ]]; then
    # Keep it readable when piped, captured by a logger, or in a serial console
    if [[ ${JSON} -eq 0 ]]; then
        C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
        C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_WHITE=""
        USE_ART=0
    fi
fi

case "${MODE}" in
    json)  render_json ;;
    quiet) render_quiet ;;
    short) render_short ;;
    *)     render_full ;;
esac

exit 0
