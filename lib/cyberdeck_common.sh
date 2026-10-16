#!/usr/bin/env bash
# shellcheck shell=bash
#
# cyberdeck_common.sh - shared bash library for cyberdeck-arsenal
# =============================================================================
#
# Description : Colour output, logging, config access, dependency checks,
#               hardware probing, authorisation gating and small helpers used
#               by every bash component of cyberdeck-arsenal.
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash >= 5, coreutils. Optional: jq, python3+PyYAML, notify-send
# Licence     : MIT (see LICENSE)
#
# Usage:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=lib/cyberdeck_common.sh
#   source "${SCRIPT_DIR}/../lib/cyberdeck_common.sh"
#   cdeck::init "my_tool"
#   cdeck::require_root || exit 1
#   cdeck::require_cmds nmap whois || exit 1
#   cdeck::info "starting work"
#
# =============================================================================

# Prevent double-sourcing
[[ -n "${CYBERDECK_COMMON_SOURCED:-}" ]] && return 0
CYBERDECK_COMMON_SOURCED=1

set -o pipefail

# --------------------------------------------------------------------------- #
# Globals
# --------------------------------------------------------------------------- #
CDECK_VERSION="1.0.0"
CDECK_INSTALL_DIR="${CYBERDECK_INSTALL_DIR:-/opt/cyberdeck-arsenal}"
CDECK_REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CDECK_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDECK_CONFIG="${CYBERDECK_CONF:-${CDECK_INSTALL_DIR}/cyberdeck.conf}"
CDECK_LOG_DIR="${CDECK_INSTALL_DIR}/logs"
CDECK_DATA_DIR="${CDECK_INSTALL_DIR}/data"
CDECK_CAPTURE_DIR="${CDECK_INSTALL_DIR}/captures"
CDECK_REPORT_DIR="${CDECK_INSTALL_DIR}/reports"
CDECK_PROFILE_DIR="${CDECK_INSTALL_DIR}/profiles"
CDECK_SCRIPT_NAME="$(basename "${BASH_SOURCE[1]:-cyberdeck}")"
CDECK_LOG_FILE=""

# Colours (only when attached to a terminal and colour output is enabled)
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'
    C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""
    C_BOLD=""; C_DIM=""; C_RESET=""
fi

cdeck::no_colour() {
    # Blank every colour code for this process (used by --no-colour)
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""
    C_BOLD=""; C_DIM=""; C_RESET=""
}

cdeck::interactive() {
    # True when both stdin and stdout are terminals
    [[ -t 0 && -t 1 ]]
}

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
cdeck::timestamp() {
    # Filesystem-safe local timestamp used in directory/file names: 2026-10-16_142530
    date '+%Y-%m-%d_%H%M%S'
}

cdeck::stamp() {
    # Compact filename timestamp: 20261016_142530
    date '+%Y%m%d_%H%M%S'
}

cdeck::iso_stamp() {
    # Sortable filename timestamp: 2026-10-16T14-25-30
    date '+%Y-%m-%dT%H-%M-%S'
}

cdeck::human_time() {
    # Human-readable local timestamp for reports and log lines
    date '+%Y-%m-%d %H:%M:%S'
}

cdeck::logline() {
    # cdeck::logline <LEVEL> <colour> <symbol> <message...>
    local level="$1" colour="$2" symbol="$3"; shift 3
    local message="$*"
    local line
    line="$(date '+%H:%M:%S') ${symbol} [${CDECK_COMPONENT:-cyberdeck}] ${message}"
    printf '%b%s%b\n' "${colour}" "${line}" "${C_RESET}"
    if [[ -n "${CDECK_LOG_FILE}" ]]; then
        printf '%s %-8s [%s] %s\n' "$(cdeck::timestamp)" "${level}" \
            "${CDECK_COMPONENT:-cyberdeck}" "${message}" >> "${CDECK_LOG_FILE}" 2>/dev/null || true
    fi
}

cdeck::debug()   { [[ "${CDECK_LOG_LEVEL:-INFO}" == "DEBUG" ]] && cdeck::logline DEBUG   "${C_DIM}"   "·" "$*"; return 0; }
cdeck::info()    { cdeck::logline INFO    "${C_CYAN}"           "→" "$*"; }
cdeck::ok()      { cdeck::logline INFO    "${C_GREEN}"          "✔" "$*"; }
cdeck::warn()    { cdeck::logline WARNING "${C_YELLOW}"         "!" "$*"; }
cdeck::error()   { cdeck::logline ERROR   "${C_RED}"            "✘" "$*"; }
cdeck::alert()   { cdeck::logline ALERT   "${C_MAGENTA}${C_BOLD}" "⚠" "$*"; }
cdeck::die()     { cdeck::logline CRITICAL "${C_RED}${C_BOLD}"  "†" "$*"; exit 1; }

# --------------------------------------------------------------------------- #
# Initialisation
# --------------------------------------------------------------------------- #
cdeck::init() {
    # cdeck::init <component-name>
    local component="${1:-$(basename "$0" .sh)}"
    CDECK_COMPONENT="${component}"

    mkdir -p "${CDECK_LOG_DIR}" 2>/dev/null || {
        CDECK_LOG_DIR="${HOME}/.cyberdeck-arsenal/logs"
        mkdir -p "${CDECK_LOG_DIR}"
    }
    CDECK_LOG_FILE="${CDECK_LOG_DIR}/${component}.log"
    : >> "${CDECK_LOG_FILE}" 2>/dev/null || CDECK_LOG_FILE=""

    # Load configuration when present so paths/levels follow cyberdeck.conf
    if [[ -f "${CDECK_CONFIG}" ]]; then
        local level primary
        level="$(cdeck::conf_get general.log_level INFO)"
        CDECK_LOG_LEVEL="${level:-INFO}"
        primary="$(cdeck::conf_get network.primary_interface wlan0)"
        CDECK_PRIMARY_IFACE="${primary:-wlan0}"
        CDECK_MONITOR_IFACE="$(cdeck::conf_get network.monitor_interface wlan1)"
    else
        CDECK_LOG_LEVEL="${CDECK_LOG_LEVEL:-INFO}"
    fi
    cdeck::debug "session started for ${component} (pid $$)"
    return 0
}

cdeck::banner() {
    # cdeck::banner <title> [subtitle]
    local title="$1" subtitle="${2:-}"
    local width=$(( ${#title} > ${#subtitle} ? ${#title} : ${#subtitle} ))
    width=$(( width + 4 ))
    local bar
    bar="$(printf '═%.0s' $(seq 1 "${width}"))"
    printf '%b╔%s╗%b\n' "${C_CYAN}" "${bar}" "${C_RESET}"
    local inner=$(( width - 2 ))
    printf '%b║%b  %b%-*s%b%b║%b\n' "${C_CYAN}" "${C_RESET}" "${C_BOLD}" "${inner}" "${title}" "${C_RESET}" "${C_CYAN}" "${C_RESET}"
    if [[ -n "${subtitle}" ]]; then
        printf '%b║%b  %b%-*s%b%b║%b\n' "${C_CYAN}" "${C_RESET}" "${C_DIM}" "${inner}" "${subtitle}" "${C_RESET}" "${C_CYAN}" "${C_RESET}"
    fi
    printf '%b╚%s╝%b\n' "${C_CYAN}" "${bar}" "${C_RESET}"
}

# --------------------------------------------------------------------------- #
# Configuration access (YAML via python3, with a sed fallback)
# --------------------------------------------------------------------------- #
cdeck::conf_get() {
    # cdeck::conf_get <section.key> [default]
    # A few keys can be overridden from the environment so the suite can run
    # from a checkout or a relocated install without editing the config file.
    local key="$1" default="${2:-}"
    case "${key}" in
        general.install_dir) [[ -n "${CYBERDECK_INSTALL_DIR:-}" ]] && { printf '%s' "${CYBERDECK_INSTALL_DIR}"; return 0; } ;;
        general.log_level)   [[ -n "${CYBERDECK_LOG_LEVEL:-}" ]] && { printf '%s' "${CYBERDECK_LOG_LEVEL}"; return 0; } ;;
    esac
    if [[ ! -f "${CDECK_CONFIG}" ]]; then
        printf '%s' "${default}"; return 0
    fi
    local value
    if command -v python3 >/dev/null 2>&1; then
        value="$(python3 - "${CDECK_CONFIG}" "${key}" "${default}" <<'PYEOF' 2>/dev/null
import sys
path, dotted, default = sys.argv[1], sys.argv[2], sys.argv[3]


def load(path):
    """Parse the configuration with PyYAML, falling back to a tiny reader.

    The fallback understands the shipped layout (top-level ``section:`` blocks
    and two-space-indented ``key: value`` pairs), so the deck keeps honouring
    its configuration even where python-yaml is not installed.
    """
    try:
        import yaml
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        pass
    data, section = {}, None
    try:
        handle = open(path)
    except OSError:
        return {}
    with handle:
        for raw in handle:
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if not line[0].isspace() and line.rstrip().endswith(":"):
                section = line.strip()[:-1].strip()
                data.setdefault(section, {})
                continue
            if line[0].isspace() and ":" in line and section:
                leaf, _, value = line.strip().partition(":")
                value = value.strip()
                if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                elif value.lower() in ("true", "false"):
                    value = value.lower() == "true"
                elif value.replace(".", "", 1).isdigit():
                    value = float(value) if "." in value else int(value)
                elif value.startswith("[") and value.endswith("]"):
                    value = [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
                data[section][leaf.strip()] = value
    return data


data = load(path)
node = data
for part in dotted.split('.'):
    if isinstance(node, dict) and part in node:
        node = node[part]
    else:
        print(default); sys.exit(0)
if isinstance(node, bool):
    print('true' if node else 'false')
elif isinstance(node, list):
    print(','.join(str(x) for x in node))
else:
    print(node if node is not None else default)
PYEOF
)"
    else
        # Fallback: grep the section then the key
        local section="${key%%.*}" leaf="${key##*.}"
        value="$(awk -v s="${section}" -v k="${leaf}" '
            $0 ~ "^"s":" {in_section=1; next}
            /^[^[:space:]]/ {in_section=0}
            in_section && $0 ~ "^[[:space:]]+"k":" {
                sub(/^[[:space:]]*[^:]+:[[:space:]]*/, ""); gsub(/["#].*$/, "");
                gsub(/[[:space:]]+$/, ""); print; exit
            }' "${CDECK_CONFIG}" 2>/dev/null)"
    fi
    printf '%s' "${value:-${default}}"
}

cdeck::conf_set() {
    # cdeck::conf_set <section.key> <value>
    #
    # Writes through cyberlib.Config so the heavily commented configuration is
    # edited line by line: comments, blank lines and ordering all survive. Only
    # a key that cannot be found in the file triggers a whole-document rewrite.
    local key="$1" value="$2"
    [[ -f "${CDECK_CONFIG}" ]] || { cdeck::warn "no config file to update: ${CDECK_CONFIG}"; return 1; }
    local output status
    output="$(CDECK_CONFIG="${CDECK_CONFIG}" python3 - "${CDECK_CONFIG}" "${key}" "${value}" \
        "${CDECK_LIB_DIR}" <<'PYEOF' 2>&1
import os
import sys

path, dotted, value, lib_dir = sys.argv[1], sys.argv[2], sys.argv[3], (sys.argv[4] if len(sys.argv) > 4 else "")
for candidate in (lib_dir, os.path.join(os.path.dirname(os.path.abspath(path)), "lib"),
                  "/opt/cyberdeck-arsenal/lib"):
    if candidate and os.path.isdir(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)
try:
    from cyberlib import Config
except ImportError as exc:                                    # pragma: no cover
    print(f"cyberlib is required for configuration writes: {exc}", file=sys.stderr)
    sys.exit(1)

low = value.lower()
if low in ("true", "false"):
    parsed = low == "true"
elif value.lstrip("-").replace(".", "", 1).isdigit():
    parsed = float(value) if "." in value else int(value)
elif value.startswith("[") and value.endswith("]"):
    parsed = [item.strip() for item in value[1:-1].split(",") if item.strip()]
elif value == "":
    parsed = ""
else:
    parsed = value

os.environ["CYBERDECK_CONF"] = path
config = Config(path).load(path)
config.set(dotted, parsed)
config.save(path)
print(dotted)
PYEOF
)"
    status=$?
    if (( status == 0 )); then
        cdeck::ok "config ${key} set to '${value}'"
    else
        cdeck::error "could not update ${key}: ${output##*$'\n'}"
        return 1
    fi
}

cdeck::conf_list() {
    # cdeck::conf_list <section.key> -> newline separated items
    local raw; raw="$(cdeck::conf_get "$1" "")"
    [[ -z "${raw}" ]] && return 0
    tr ',' '\n' <<< "${raw}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$' || true
}

# --------------------------------------------------------------------------- #
# Guards and checks
# --------------------------------------------------------------------------- #
cdeck::require_root() {
    # cdeck::require_root [what-you-were-doing]
    if [[ "${EUID}" -ne 0 ]]; then
        cdeck::error "root privileges required${1:+ for $1} (re-run with: sudo $0)"
        return 1
    fi
    return 0
}

cdeck::require_cmds() {
    # cdeck::require_cmds <cmd> [cmd...]
    local missing=() cmd
    for cmd in "$@"; do
        command -v "${cmd}" >/dev/null 2>&1 || missing+=("${cmd}")
    done
    if (( ${#missing[@]} )); then
        cdeck::error "missing required tool(s): ${missing[*]}"
        cdeck::info "install with: sudo pacman -S ${missing[*]}"
        return 1
    fi
    return 0
}

cdeck::has_cmd() { command -v "$1" >/dev/null 2>&1; }

cdeck::have_connectivity() {
    local host="${1:-1.1.1.1}" port="${2:-53}"
    if cdeck::has_cmd nc; then
        timeout 3 nc -z "${host}" "${port}" >/dev/null 2>&1 && return 0
    fi
    if cdeck::has_cmd ping; then
        ping -c1 -W2 "${host}" >/dev/null 2>&1 && return 0
    fi
    timeout 3 bash -c ": > /dev/tcp/${host}/${port}" >/dev/null 2>&1 && return 0
    return 1
}

cdeck::require_connectivity() {
    if ! cdeck::have_connectivity; then
        cdeck::warn "no internet connectivity detected (${1:-1.1.1.1})"
        return 1
    fi
    return 0
}

cdeck::confirm() {
    # cdeck::confirm <prompt> [default: y|n] [--force-flag]
    local prompt="$1" default="${2:-n}" force="${3:-}"
    if [[ "${force}" == "--yes" || "${CDECK_ASSUME_YES:-0}" == "1" ]]; then
        cdeck::debug "auto-confirmed: ${prompt}"
        return 0
    fi
    [[ -t 0 ]] || { cdeck::warn "not a terminal - defaulting to '${default}' for: ${prompt}"; [[ "${default}" == "y" ]]; }
    local reply
    read -r -p "${C_YELLOW}${prompt} $( [[ "${default}" == "y" ]] && echo '[Y/n]' || echo '[y/N]' ) ${C_RESET}" reply || return 1
    reply="${reply,,}"
    [[ -z "${reply}" ]] && reply="${default}"
    [[ "${reply}" == "y" || "${reply}" == "yes" ]]
}

cdeck::require_acknowledgement() {
    # Gate destructive/attack modules behind a recorded authorisation step.
    local ack
    ack="$(cdeck::conf_get general.authorised_use_acknowledged false)"
    if [[ "${ack}" == "true" ]]; then
        return 0
    fi
    cat <<'EOF'
┌───────────────────────────────────────────────────────────────────────────┐
│  ⚠  AUTHORISED USE ONLY                                                    │
│                                                                           │
│  Active and attack modules may only be used against systems, networks      │
│  and radio spectrum you own or have explicit written authorisation for.    │
│  Unauthorised use is a criminal offence (UK CMA 1990 / US CFAA 1986).      │
└───────────────────────────────────────────────────────────────────────────┘
EOF
    local reply
    [[ -t 0 ]] || { cdeck::warn "non-interactive session - acknowledgement skipped"; return 1; }
    read -r -p "${C_RED}${C_BOLD}Type 'I AGREE' to confirm you are authorised: ${C_RESET}" reply
    if [[ "${reply^^}" == "I AGREE" ]]; then
        cdeck::conf_set general.authorised_use_acknowledged true >/dev/null 2>&1 || true
        cdeck::ok "authorisation acknowledged"
        return 0
    fi
    cdeck::error "authorisation not confirmed - aborting"
    return 1
}

cdeck::legal_warning() {
    # cdeck::legal_warning <action description>
    cdeck::alert "LEGAL NOTICE: ${1:-this action} is intrusive."
    cdeck::warn "Only proceed against assets you own or are contracted to test in writing."
}

# --------------------------------------------------------------------------- #
# Hardware helpers
# --------------------------------------------------------------------------- #
cdeck::interfaces() {
    # List non-loopback interface names
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -v '^lo$' || true
}

cdeck::wlan_interfaces() {
    if cdeck::has_cmd iw; then
        iw dev 2>/dev/null | awk '/Interface/ {print $2}' || true
    else
        for iface in $(cdeck::interfaces); do
            [[ -d "/sys/class/net/${iface}/wireless" ]] && echo "${iface}"
        done
    fi
}

cdeck::monitor_capable_interfaces() {
    local iface
    for iface in $(cdeck::wlan_interfaces); do
        if cdeck::has_cmd iw; then
            if iw phy "$(cat "/sys/class/net/${iface}/phy80211/name" 2>/dev/null)" info 2>/dev/null \
                | grep -A12 'Supported interface modes' | grep -q '\* monitor'; then
                echo "${iface}"
            fi
        else
            echo "${iface}"
        fi
    done
}

cdeck::wireguard_interfaces() {
    # Names of live WireGuard interfaces. `ip link show type wireguard` reports
    # success with empty output on some iproute2 builds, so the link detail is
    # checked explicitly (and the configured name is honoured first).
    local configured iface
    configured="$(cdeck::conf_get network.wireguard_interface '')"
    if [[ -n "${configured}" && -e "/sys/class/net/${configured}" ]]; then
        printf '%s\n' "${configured}"
    fi
    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
        [[ "${iface}" == "${configured}" ]] && continue
        [[ "${iface}" == "lo" ]] && continue
        if ip -d link show dev "${iface}" 2>/dev/null | grep -qi 'wireguard'; then
            printf '%s\n' "${iface}"
        fi
    done
    return 0
}

cdeck::wireguard_up() {
    # True when at least one WireGuard interface exists
    [[ -n "$(cdeck::wireguard_interfaces)" ]]
}

cdeck::default_iface() {
    # The interface carrying the default route, or - when there is no default
    # route (isolated lab, statically addressed deck) - the first interface that
    # holds a globally routable address.
    local iface
    iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    if [[ -z "${iface}" ]]; then
        iface="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2; exit}')"
    fi
    if [[ -z "${iface}" ]]; then
        iface="$(cdeck::interfaces | head -1)"
    fi
    [[ -n "${iface}" ]] && printf '%s\n' "${iface}"
    return 0
}

cdeck::primary_interface() {
    # Configured primary interface, falling back to whatever is really in use
    local configured
    configured="$(cdeck::conf_get network.primary_interface '')"
    if [[ -n "${configured}" && -e "/sys/class/net/${configured}" ]]; then
        printf '%s\n' "${configured}"
        return 0
    fi
    cdeck::default_iface
}

cdeck::monitor_interface() {
    # Configured monitor interface when it exists, otherwise the first radio
    # that looks usable. Prints nothing when the deck has no wireless hardware.
    local configured
    configured="$(cdeck::conf_get network.monitor_interface '')"
    if [[ -n "${configured}" && -e "/sys/class/net/${configured}" ]]; then
        printf '%s\n' "${configured}"
        return 0
    fi
    local candidate
    for candidate in $(cdeck::wlan_interfaces); do
        [[ -d "/sys/class/net/${candidate}/wireless" ]] || continue
        printf '%s\n' "${candidate}"
        return 0
    done
    return 1
}

cdeck::iface_mac() { cat "/sys/class/net/${1}/address" 2>/dev/null || echo "unknown"; }

cdeck::iface_state() { cat "/sys/class/net/${1}/operstate" 2>/dev/null || echo "unknown"; }

cdeck::sdr_present() {
    cdeck::has_cmd rtl_test && rtl_test -t >/dev/null 2>&1 && return 0
    lsusb 2>/dev/null | grep -qiE 'rtl|hackrf|airspy|limesdr|sdrplay|nooelec' && return 0
    return 1
}

cdeck::gps_device() {
    local candidate
    for candidate in /dev/ttyACM0 /dev/ttyACM1 /dev/ttyUSB0 /dev/gps0; do
        [[ -e "${candidate}" ]] && { echo "${candidate}"; return 0; }
    done
    return 1
}

cdeck::gpio_available() {
    [[ -d /sys/class/gpio && -e /proc/device-tree/model ]] && return 0
    grep -qiE 'raspberry|banana|orange pi|rock pi|jetson' /proc/device-tree/model 2>/dev/null && return 0
    return 1
}

cdeck::battery_percent() {
    local bat
    for bat in /sys/class/power_supply/BAT*; do
        [[ -r "${bat}/capacity" ]] && { cat "${bat}/capacity"; return 0; }
    done
    return 1
}

cdeck::temperature() {
    local zone max_temp=""
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        [[ -r "${zone}" ]] || continue
        local value; value="$(cat "${zone}" 2>/dev/null)" || continue
        (( value > 1000 )) && value=$(( value / 1000 ))
        if [[ -z "${max_temp}" || "${value}" -gt "${max_temp}" ]]; then max_temp="${value}"; fi
    done
    [[ -n "${max_temp}" ]] && echo "${max_temp}" || echo "n/a"
}

# --------------------------------------------------------------------------- #
# Process / filesystem helpers
# --------------------------------------------------------------------------- #
cdeck::kill_processes() {
    # cdeck::kill_processes <pattern> [pattern...]
    local pattern killed=0 pid
    for pattern in "$@"; do
        while read -r pid; do
            [[ -z "${pid}" ]] && continue
            kill -TERM "${pid}" 2>/dev/null && { cdeck::info "terminated pid ${pid} (${pattern})"; killed=$(( killed + 1 )); }
        done < <(pgrep -f "${pattern}" 2>/dev/null | grep -v "^$$\$" || true)
        sleep 0.3
        while read -r pid; do
            [[ -z "${pid}" ]] && continue
            kill -KILL "${pid}" 2>/dev/null && cdeck::warn "force-killed pid ${pid} (${pattern})"
        done < <(pgrep -f "${pattern}" 2>/dev/null | grep -v "^$$\$" || true)
    done
    return $(( killed > 0 ? 0 : 1 ))
}

cdeck::count_packets() {
    # cdeck::count_packets <pcap> -> number of packets (0 when it cannot be read)
    local pcap="$1" count=0
    if [[ ! -f "${pcap}" ]]; then
        printf '0'
        return 0
    fi
    if cdeck::has_cmd capinfos; then
        count="$(capinfos -c -M "${pcap}" 2>/dev/null | awk '/Number of packets/ {print $NF}' | head -1)"
    fi
    if [[ -z "${count}" || "${count}" == "0" ]]; then
        count="$(tcpdump -r "${pcap}" -nn 2>/dev/null | wc -l | tr -d ' ')"
    fi
    printf '%s' "${count:-0}"
}

cdeck::engagement_dir() {
    # cdeck::engagement_dir <target> -> prints created directory
    local target="$1"
    local slug
    slug="$(tr -c '[:alnum:]._-' '-' <<< "${target}" | sed 's/--*/-/g;s/^-//;s/-$//')"
    [[ -z "${slug}" ]] && slug="target"
    local dir="${2:-${CDECK_REPORT_DIR}}/${slug}_$(cdeck::stamp)"
    mkdir -p "${dir}"/{raw,logs,evidence}
    printf '%s' "${dir}"
}

cdeck::notify() {
    # cdeck::notify <title> <body> [severity]
    local title="$1" body="${2:-}" severity="${3:-normal}"
    cdeck::has_cmd notify-send && notify-send -a "cyberdeck-arsenal" -u "${severity}" "${title}" "${body}" 2>/dev/null || true
    local webhook; webhook="$(cdeck::conf_get alerts.webhook_url "")"
    if [[ -n "${webhook}" && "${webhook}" == http* ]] && cdeck::has_cmd curl; then
        curl -sS -m 6 -X POST -H 'Content-Type: application/json' \
            -d "{\"source\":\"${CDECK_COMPONENT:-cyberdeck}\",\"severity\":\"${severity}\",\"title\":\"${title}\",\"body\":\"${body}\"}" \
            "${webhook}" >/dev/null 2>&1 || true
    fi
}

cdeck::require_user_dir() {
    mkdir -p "$1" 2>/dev/null || cdeck::die "cannot create directory: $1"
}

cdeck::which_or_warn() {
    # Echo the path to a tool, or an empty string plus a warning
    local tool="$1" package="${2:-$1}"
    if path="$(command -v "${tool}" 2>/dev/null)"; then
        printf '%s' "${path}"
    else
        cdeck::warn "'${tool}' not installed (sudo pacman -S ${package})" >&2
        printf ''
    fi
}

cdeck::usage_header() {
    # cdeck::usage_header <description> <usage> <examples...>
    printf '%s\n' "${C_BOLD}$1${C_RESET}"
    printf '\n%s\n  %s\n\n' "${C_BOLD}USAGE${C_RESET}" "$2"
    shift 2
    if (( $# )); then
        printf '%s\n' "${C_BOLD}EXAMPLES${C_RESET}"
        for example in "$@"; do printf '  %s\n' "${example}"; done
        printf '\n'
    fi
    printf '%s\n' "${C_DIM}cyberdeck-arsenal ${CDECK_VERSION} - authorised use only (see docs/LEGAL.md)${C_RESET}"
}

cdeck::spin() {
    # cdeck::spin <message> <command...>  - run a command with a spinner
    local message="$1"; shift
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    "$@" >/dev/null 2>&1 &
    local pid=$!
    while kill -0 "${pid}" 2>/dev/null; do
        printf '\r%b%s%b %s' "${C_CYAN}" "${frames[$((i % 10))]}" "${C_RESET}" "${message}"
        i=$(( i + 1 ))
        sleep 0.1
    done
    wait "${pid}"; local rc=$?
    printf '\r\033[K'
    (( rc == 0 )) && cdeck::ok "${message}" || cdeck::error "${message} (exit ${rc})"
    return ${rc}
}
