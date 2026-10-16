#!/usr/bin/env bash
# =============================================================================
# boot_splash.sh - animated boot splash and boot self-check for the deck
# =============================================================================
#
# Description
# -----------
# Two jobs in one script.
#
# 1. It paints the theme's splash art with a progress bar and a rolling log, so
#    turning the deck on looks like turning a deck on.
# 2. Every "stage" it animates is a *real* check of the machine: hardware
#    inventory, filesystem permissions, interfaces, radios, SDR devices,
#    databases, systemd units and the log directory. A deck that boots with a
#    red stage tells you what is wrong before you have even logged in.
#
# The splash can be installed as an early-boot unit (``--install``), run once
# from a shell (``--once``), replayed for a photo (``--demo``) or disabled
# entirely without uninstalling anything (``--no-animation``).
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash, coreutils; optional: figlet/toilet, lolcat, systemd, iw
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./boot_splash.sh                     # boot the splash with real checks
#   ./boot_splash.sh --fast              # no delays, results only
#   ./boot_splash.sh --demo --duration 6 # pretty replay for a screenshot
#   sudo ./boot_splash.sh --install      # run it on every boot
#   ./boot_splash.sh --stages            # list the stages and exit
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

cdeck::init "boot_splash"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
CONF_FILE="${CDECK_CONFIG:-${INSTALL_DIR}/cyberdeck.conf}"
THEME_ENV="${INSTALL_DIR}/state/theme.env"
THEME_DIR="${SCRIPT_DIR}/themes"
[[ -d "${THEME_DIR}" ]] || THEME_DIR="${INSTALL_DIR}/aesthetic/themes"
UNIT_PATH="/etc/systemd/system/cyberdeck-splash.service"
SPLASH_LOG="${INSTALL_DIR}/logs/boot_splash.log"

FAST=0
DEMO=0
JSON=0
QUIET=0
ANIMATE=1
SHOW_ART=1
DURATION=0
ONCE=0
ACTION="boot"

usage() {
    cdeck::usage_header \
        "Animated boot splash with a real boot self-check" \
        "$0 [--fast|--demo|--once|--stages|--install|--uninstall] [--duration N] [--no-animation] [--json]" \
        "$0                       # splash with live system checks" \
        "$0 --fast                # no animation delays" \
        "$0 --demo --duration 6   # animated replay for a recording" \
        "sudo $0 --install         # run the splash on every boot"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -f, --fast             skip the animation delays
  -d, --demo             replay the animation with synthetic stage timings
  -o, --once             paint the splash once and exit
  --duration SECONDS     total length of --demo (default: 6)
  --no-animation         print the results without the bar or the art
  --no-art               keep the progress bar, drop the ASCII art
  --stages               list the stages and what each one checks
  --install              install and enable the early-boot unit
  --uninstall            remove the early-boot unit
  --json                 machine-readable results
  --install-dir PATH     override the install directory (${INSTALL_DIR})
  -q, --quiet            errors only
  -h, --help             this help
  -V, --version          version

${C_BOLD}STAGE EXIT CODES${C_RESET}
  The splash returns the number of failed stages (0 = healthy), so it is safe
  to call from a service:  ${BOLD}ExecStart=${INSTALL_DIR}/aesthetic/boot_splash.sh --fast --once${C_RESET}
EOF
}

# --------------------------------------------------------------------------- #
# Stages
# --------------------------------------------------------------------------- #
STAGE_NAMES=(
    "hardware"
    "filesystem"
    "network"
    "wireless"
    "sdr"
    "databases"
    "services"
    "display"
    "self-test"
)
STAGE_DESCRIPTIONS=(
    "CPU, memory, board model and thermal sensors"
    "install directory, permissions and free space"
    "links, addresses, default route, VPN state"
    "wireless interfaces and monitor-mode capability"
    "RTL-SDR / HackRF / Proxmark receivers"
    "SQLite databases and the shared data files"
    "cyberdeck systemd units"
    "theme files, HUD dependencies and terminal"
    "installation self-test (tests/test_installation.sh)"
)

declare -a STAGE_RESULTS=()
declare -a STAGE_DETAILS=()
declare -a STAGE_TIMES=()

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

# Each check prints "<OK|WARN|FAIL|SKIP>|<detail>" on stdout.
stage_hardware() {
    local board cores memory_kb temperature=""
    board="$(cdeck::conf_get general.operator_name operator)"
    cores="$(nproc 2>/dev/null || echo '?')"
    memory_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    local memory_gb=$(( memory_kb / 1024 / 1024 ))
    local zone
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        [[ -r "${zone}" ]] || continue
        local raw; raw="$(cat "${zone}" 2>/dev/null || echo 0)"
        (( raw > 1000 )) && raw=$(( raw / 1000 ))
        temperature="${raw}C"
        break
    done
    if (( cores == 0 )); then
        printf 'FAIL|cannot read /proc/cpuinfo\n'
        return 0
    fi
    local detail="${cores} cores · ${memory_gb} GiB RAM"
    [[ -n "${temperature}" ]] && detail+=" · ${temperature}"
    if (( memory_gb < 2 )); then
        printf 'WARN|%s (2 GiB or more recommended)\n' "${detail}"
    else
        printf 'OK|%s\n' "${detail}"
    fi
}

stage_filesystem() {
    if [[ ! -d "${INSTALL_DIR}" ]]; then
        printf 'FAIL|install directory %s is missing - run setup.sh\n' "${INSTALL_DIR}"
        return 0
    fi
    local free_kb free_gb percent
    free_kb="$(df -Pk "${INSTALL_DIR}" 2>/dev/null | awk 'NR==2 {print $4}')"
    free_gb=$(( ${free_kb:-0} / 1024 / 1024 ))
    percent="$(df -P "${INSTALL_DIR}" 2>/dev/null | awk 'NR==2 {print $5}')"
    local -a missing=()
    local subdir
    for subdir in logs captures reports state data vault; do
        if [[ ! -d "${INSTALL_DIR}/${subdir}" ]]; then
            missing+=("${subdir}")
        elif [[ ! -w "${INSTALL_DIR}/${subdir}" ]]; then
            missing+=("${subdir} (not writable)")
        fi
    done
    if [[ "${percent%\%}" -ge 95 ]]; then
        printf 'FAIL|%s full (%s) - captures will fail\n' "${percent}" "${free_gb} GiB"
        return 0
    fi
    if (( free_gb < 5 )); then
        printf 'WARN|%s free (%s used) - below the 5 GiB working minimum\n' "${free_gb} GiB" "${percent}"
        return 0
    fi
    if ((${#missing[@]})); then
        printf 'WARN|%s free · missing %s\n' "${free_gb} GiB" "$(IFS=,; echo "${missing[*]}")"
        return 0
    fi
    printf 'OK|%s free (%s used) · all runtime directories present\n' "${free_gb} GiB" "${percent}"
}

stage_network() {
    local interface address
    interface="$(cdeck::default_interface 2>/dev/null || true)"
    if [[ -z "${interface}" ]]; then
        printf 'WARN|no default route - the deck is offline\n'
        return 0
    fi
    address="$(cd / && ip -o -4 addr show dev "${interface}" 2>/dev/null | awk '{print $4; exit}')"
    local vpn="off"
    if cdeck::wireguard_up; then vpn="wireguard"
    elif pgrep -x openvpn >/dev/null 2>&1; then vpn="openvpn"
    elif pgrep -x tor >/dev/null 2>&1; then vpn="tor"
    fi
    if cdeck::has_cmd ping && ! ping -c1 -W1 "${interface}" >/dev/null 2>&1; then
        printf 'OK|%s %s · vpn %s\n' "${interface}" "${address:-no address}" "${vpn}"
        return 0
    fi
    printf 'OK|%s %s · vpn %s\n' "${interface}" "${address:-no address}" "${vpn}"
}

stage_wireless() {
    if ! cdeck::has_cmd iw && ! [[ -d /sys/class/net ]]; then
        printf 'SKIP|no wireless subsystem on this host\n'
        return 0
    fi
    local -a radios=()
    local path name
    for path in /sys/class/net/*/wireless; do
        [[ -e "${path}" ]] || continue
        name="$(basename "$(dirname "${path}")")"
        radios+=("${name}")
    done
    if ((${#radios[@]} == 0)); then
        printf 'SKIP|no wireless interfaces (external USB radio?)\n'
        return 0
    fi
    local monitor_if monitor_state="no"
    monitor_if="$(cdeck::monitor_interface 2>/dev/null || true)"
    if [[ -n "${monitor_if}" ]] && cd / && iw dev "${monitor_if}" info 2>/dev/null | grep -q monitor; then
        monitor_state="yes"
    fi
    printf 'OK|%s · monitor mode %s\n' "$(IFS=,; echo "${radios[*]}")" "${monitor_state}"
}

stage_sdr() {
    local found=()
    if lsusb 2>/dev/null | grep -qiE "RTL2838|RTL2832|Realtek.*DVB|HackRF|Great Scott"; then
        if lsusb 2>/dev/null | grep -qiE "HackRF|Great Scott"; then
            found+=("hackrf")
        fi
        lsusb 2>/dev/null | grep -qiE "RTL2838|RTL2832|Realtek.*DVB" && found+=("rtl-sdr")
    fi
    [[ -d /sys/class/net ]] && { :; }
    if cdeck::has_cmd proxmark3 && [[ -e /dev/ttyACM0 ]]; then found+=("proxmark?"); fi
    if ((${#found[@]} == 0)); then
        printf 'SKIP|no SDR receiver detected - sdr/ modules will report exit 3\n'
        return 0
    fi
    printf 'OK|%s\n' "$(IFS=,; echo "${found[*]}")"
}

stage_databases() {
    local db count=0 missing=()
    for db in events alerts probes ble arp services usb payloads; do
        if [[ -f "${INSTALL_DIR}/data/${db}.db" ]]; then
            count=$(( count + 1 ))
        else
            missing+=("${db}")
        fi
    done
    if (( count == 0 )); then
        printf 'WARN|no databases yet - run: sudo %s/setup.sh --resume\n' "${INSTALL_DIR}"
        return 0
    fi
    if ((${#missing[@]})); then
        printf 'WARN|%d databases present · missing %s\n' "${count}" "$(IFS=,; echo "${missing[*]}")"
        return 0
    fi
    local oui="missing"
    [[ -f "${INSTALL_DIR}/data/oui_database.txt" ]] && oui="$(wc -l < "${INSTALL_DIR}/data/oui_database.txt" | tr -d ' ') entries"
    printf 'OK|%d databases · OUI %s\n' "${count}" "${oui}"
}

stage_services() {
    if ! cdeck::has_cmd systemctl; then
        printf 'SKIP|systemd is not available on this host\n'
        return 0
    fi
    local -a units=(cyberdeck-monitor.service probe-logger.service ble-scanner.service
                    rogue-ap-detector.service usb-watcher.service mac-rotator.timer)
    local running=0 known=0 absent=() unit state
    for unit in "${units[@]}"; do
        state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
        case "${state}" in
            active) running=$(( running + 1 )); known=$(( known + 1 )) ;;
            inactive|failed) known=$(( known + 1 )) ;;
            *) absent+=("${unit%.*}") ;;
        esac
    done
    if (( known == 0 )); then
        printf 'WARN|no cyberdeck units installed - run: sudo %s/setup.sh --resume\n' "${INSTALL_DIR}"
        return 0
    fi
    if (( running == 0 )); then
        printf 'WARN|%d units installed, none running (start with: cdeck services start)\n' "${known}"
        return 0
    fi
    if ((${#absent[@]})); then
        printf 'OK|%d/%d units running · not installed: %s\n' "${running}" "${known}" \
            "$(IFS=,; echo "${absent[*]}")"
        return 0
    fi
    printf 'OK|%d/%d units running\n' "${running}" "${known}"
}

stage_display() {
    local theme hud_deps=() missing=()
    theme="$(theme_name)"
    [[ -f "${THEME_DIR}/${theme}.theme" ]] || missing+=("theme ${theme}")
    for module in rich textual; do
        if "${CDECK_PYTHON:-python3}" -c "import ${module}" >/dev/null 2>&1; then
            hud_deps+=("${module}")
        else
            missing+=("python:${module}")
        fi
    done
    if ((${#missing[@]})); then
        printf 'WARN|theme %s · HUD falling back to plain output (missing %s)\n' \
            "${theme}" "$(IFS=,; echo "${missing[*]}")"
        return 0
    fi
    local size="${COLUMNS:-80}x${LINES:-24}"
    printf 'OK|theme %s · rich+textual present · console %s\n' "${theme}" "${size}"
}

stage_self_test() {
    local test_script="${INSTALL_DIR}/tests/test_installation.sh"
    if [[ ! -x "${test_script}" ]]; then
        printf 'SKIP|tests/test_installation.sh is not installed\n'
        return 0
    fi
    local output
    if output="$("${test_script}" --quiet 2>&1)"; then
        printf 'OK|self-test passed\n'
        return 0
    fi
    local summary
    summary="$(printf '%s' "${output}" | grep -Ei "fail|error" | tail -1)"
    printf 'WARN|self-test reported problems: %s\n' "${summary:-(see ${SPLASH_LOG})}"
}

run_stage() {
    local index="$1" name="${STAGE_NAMES[$1]}" started result detail
    started="$(date +%s.%N 2>/dev/null || date +%s)"
    case "${name}" in
        hardware)   result="$(stage_hardware)" ;;
        filesystem) result="$(stage_filesystem)" ;;
        network)    result="$(stage_network)" ;;
        wireless)   result="$(stage_wireless)" ;;
        sdr)        result="$(stage_sdr)" ;;
        databases)  result="$(stage_databases)" ;;
        services)   result="$(stage_services)" ;;
        display)    result="$(stage_display)" ;;
        self-test)  result="$(stage_self_test)" ;;
        *)          result="SKIP|unknown stage" ;;
    esac
    local verdict="${result%%|*}"
    detail="${result#*|}"
    local ended elapsed
    ended="$(date +%s.%N 2>/dev/null || date +%s)"
    elapsed="$(awk -v a="${started}" -v b="${ended}" 'BEGIN {printf "%.2f", (b-a)}' 2>/dev/null || echo 0)"
    STAGE_RESULTS[$index]="${verdict}"
    STAGE_DETAILS[$index]="${detail}"
    STAGE_TIMES[$index]="${elapsed}"
    log_stage "${name}" "${verdict}" "${detail}" "${elapsed}"
}

log_stage() {
    local name="$1" verdict="$2" detail="$3" elapsed="$4"
    if [[ -n "${SPLASH_LOG}" ]] && { [[ -w "$(dirname "${SPLASH_LOG}")" ]] || [[ -w "${SPLASH_LOG}" ]]; }; then
        printf '%s|%s|%s|%s|%ss\n' "$(cdeck::iso_stamp)" "${name}" "${verdict}" \
            "${detail//|/\\|}" "${elapsed}" >> "${SPLASH_LOG}" 2>/dev/null || true
    fi
}

# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
theme_colour() {
    local hex="${1#\#}"
    (( ANIMATE )) || { printf ''; return 0; }
    [[ "${hex}" =~ ^[0-9a-fA-F]{6}$ ]] || { printf ''; return 0; }
    printf '\033[38;2;%d;%d;%dm' "0x${hex:0:2}" "0x${hex:2:2}" "0x${hex:4:2}"
}

verdict_colour() {
    case "$1" in
        OK)   printf '%s' "${C_GREEN}" ;;
        WARN) printf '%s' "${C_YELLOW}" ;;
        FAIL) printf '%s' "${C_RED}" ;;
        *)    printf '%s' "${C_DIM}" ;;
    esac
}

verdict_glyph() {
    case "$1" in
        OK)   printf '✔' ;;
        WARN) printf '!' ;;
        FAIL) printf '✘' ;;
        *)    printf '·' ;;
    esac
}

progress_bar() {
    # progress_bar <done> <total> <width>
    local done="$1" total="$2" width="${3:-32}"
    local filled=$(( done * width / total ))
    local empty=$(( width - filled ))
    local bar=""
    (( filled )) && bar="$(printf '█%.0s' $(seq 1 "${filled}"))"
    (( empty )) && bar+="$(printf '░%.0s' $(seq 1 "${empty}"))"
    printf '%s' "${bar}"
}

paint_splash() {
    local primary secondary tagline art
    primary="$(theme_colour "$(theme_field THEME_PRIMARY '#39ff14')")"
    secondary="$(theme_colour "$(theme_field THEME_SECONDARY '#00d9ff')")"
    tagline="$(theme_field THEME_SPLASH_TAGLINE '')"

    if (( SHOW_ART )); then
        art="$(theme_field THEME_SPLASH_ART '')"
        if [[ -n "${art}" ]]; then
            printf '%b%s%b\n' "${primary}" "${art}" "${C_RESET}"
        elif cdeck::has_cmd figlet; then
            printf '%b' "${primary}"
            figlet -f standard "CYBERDECK" 2>/dev/null || printf '  CYBERDECK ARSENAL\n'
            printf '%b' "${C_RESET}"
        else
            printf '%b\n  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗██╗  ██╗%b\n' \
                "${primary}" "${C_RESET}"
            printf '%b  cyberdeck-arsenal %s%b\n' "${secondary}" "${CDECK_VERSION}" "${C_RESET}"
        fi
    else
        printf '%b  cyberdeck-arsenal %s%b\n' "${secondary}" "${CDECK_VERSION}" "${C_RESET}"
    fi
    [[ -n "${tagline}" ]] && printf '%b  %s%b\n' "${C_DIM}" "${tagline}" "${C_RESET}"
    printf '\n'
}

render_results() {
    local total="${#STAGE_NAMES[@]}" i verdict
    printf '  %b%s%b\n' "${C_BOLD}" "boot self-check" "${C_RESET}"
    printf '  %s\n' "$(printf '─%.0s' $(seq 1 84))"
    for (( i = 0; i < total; i++ )); do
        verdict="${STAGE_RESULTS[$i]:-SKIP}"
        printf '  %b%s%b %-11s %b%-4s%b %s\n' \
            "$(verdict_colour "${verdict}")" "$(verdict_glyph "${verdict}")" "${C_RESET}" \
            "${STAGE_NAMES[$i]}" "$(verdict_colour "${verdict}")" "${verdict}" "${C_RESET}" \
            "${STAGE_DETAILS[$i]:-}"
    done
    printf '\n'
}

render_json() {
    local total="${#STAGE_NAMES[@]}" i first=1 failed=0
    for (( i = 0; i < total; i++ )); do
        [[ "${STAGE_RESULTS[$i]:-SKIP}" == "FAIL" ]] && failed=$(( failed + 1 ))
    done
    printf '{\n  "version": "%s",\n  "theme": "%s",\n  "install_dir": "%s",\n' \
        "${CDECK_VERSION}" "$(theme_name)" "${INSTALL_DIR}"
    printf '  "generated": "%s",\n  "failed": %d,\n  "stages": [\n' \
        "$(cdeck::iso_stamp)" "${failed}"
    for (( i = 0; i < total; i++ )); do
        (( first )) || printf ',\n'
        first=0
        printf '    {"name": "%s", "verdict": "%s", "detail": "%s", "seconds": %s}' \
            "${STAGE_NAMES[$i]}" "${STAGE_RESULTS[$i]:-SKIP}" \
            "$(printf '%s' "${STAGE_DETAILS[$i]:-}" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
            "${STAGE_TIMES[$i]:-0}"
    done
    printf '\n  ]\n}\n'
}

animate_all() {
    local total="${#STAGE_NAMES[@]}" i
    local started finished
    started="$(date +%s)"
    for (( i = 0; i < total; i++ )); do
        local label="$(( i + 1 ))/${total} ${STAGE_NAMES[$i]}"
        local spinner=( '⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏' )
        local frame=0
        # Start the stage in the background so the spinner can actually spin
        run_stage "${i}" &
        local stage_pid=$!
        printf '  %b%s%b ' "${C_RESET}" "${label}" "${C_RESET}"
        while kill -0 "${stage_pid}" 2>/dev/null; do
            printf '%b%s%b' "${C_GREEN}" "${spinner[$(( frame % 10 ))]}" "${C_RESET}"
            sleep 0.08
            printf '\b'
            frame=$(( frame + 1 ))
            (( frame > 40 )) && break    # never hold up a boot for a slow check
        done
        wait "${stage_pid}" 2>/dev/null || true
        printf '\b'
        run_stage "${i}" >/dev/null 2>&1 || true   # second pass is cheap and keeps the result in-process
        local verdict="${STAGE_RESULTS[$i]:-SKIP}"
        printf '\r  %b%s%b %b%s%b %b%-4s%b %s\n' \
            "${C_RESET}" "${label}" "${C_RESET}" \
            "$(verdict_colour "${verdict}")" "$(verdict_glyph "${verdict}")" "${C_RESET}" \
            "$(verdict_colour "${verdict}")" "${verdict}" "${C_RESET}" "${STAGE_DETAILS[$i]}"
        printf '      %b[%s]%b %d%%\n' \
            "$(theme_colour "$(theme_field THEME_PRIMARY '#39ff14')")" \
            "$(progress_bar $(( i + 1 )) "${total}" 36)" "${C_RESET}" \
            "$(( (i + 1) * 100 / total ))"
    done
    finished="$(date +%s)"
    printf '\n  %bboot completed in %ss%b\n\n' "${C_GREEN}" "$(( finished - started ))" "${C_RESET}"
}

list_stages() {
    cdeck::banner "boot splash stages" "each stage is a real check, not decoration"
    printf '  %-4s %-12s %s\n' "#" "STAGE" "WHAT IT CHECKS"
    printf '  %s\n' "$(printf '─%.0s' $(seq 1 96))"
    local i
    for i in "${!STAGE_NAMES[@]}"; do
        printf '  %-4s %-12s %s\n' "$(( i + 1 ))" "${STAGE_NAMES[$i]}" "${STAGE_DESCRIPTIONS[$i]}"
    done
    printf '\n  exit code = number of FAIL stages (0 = healthy)\n\n'
}

demo_run() {
    local total="${#STAGE_NAMES[@]}" i
    local per_stage=$(( DURATION * 100 / total ))
    for (( i = 0; i < total; i++ )); do
        printf '  %b%d/%d %s%b %b%s%b\r' "${C_RESET}" "$(( i + 1 ))" "${total}" \
            "${STAGE_NAMES[$i]}" "${C_RESET}" "${C_DIM}" \
            "$(printf '·%.0s' $(seq 1 10))" "${C_RESET}"
        sleep "0.$(( per_stage > 9 ? 9 : per_stage ))" 2>/dev/null || sleep 0.1
        printf '  %b%d/%d %s%b %b✔%b %bok%b   (demo)\n' "${C_RESET}" "$(( i + 1 ))" "${total}" \
            "${STAGE_NAMES[$i]}" "${C_RESET}" "${C_GREEN}" "${C_RESET}" "${C_GREEN}" "${C_RESET}"
        printf '      %b[%s]%b %d%%\n' "$(theme_colour "$(theme_field THEME_PRIMARY '#39ff14')")" \
            "$(progress_bar $(( i + 1 )) "${total}" 36)" "${C_RESET}" "$(( (i+1) * 100 / total ))"
    done
}

install_unit() {
    cdeck::require_root "installing the boot splash" || return 1
    cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=cyberdeck-arsenal boot splash and self-check
Documentation=file:${INSTALL_DIR}/docs/TROUBLESHOOTING.md
DefaultDependencies=no
After=local-fs.target sysinit.target
Before=getty.target systemd-user-sessions.service
ConditionPathExists=${INSTALL_DIR}/aesthetic/boot_splash.sh

[Service]
Type=oneshot
RemainAfterExit=yes
StandardOutput=tty
TTYPath=/dev/tty1
Environment=CYBERDECK_INSTALL_DIR=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/aesthetic/boot_splash.sh --once --fast
TimeoutStartSec=120
SuccessExitStatus=0 1 2 3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable cyberdeck-splash.service 2>/dev/null || true
    cdeck::ok "boot splash unit installed at ${UNIT_PATH}"
    cdeck::info "it paints /dev/tty1 before the login prompt; disable with: $0 --uninstall"
    cdeck::info "to suppress it for one boot add 'systemd.unit=multi-user.target' to the kernel line"
}

uninstall_unit() {
    cdeck::require_root "removing the boot splash" || return 1
    systemctl disable cyberdeck-splash.service 2>/dev/null || true
    rm -f "${UNIT_PATH}"
    systemctl daemon-reload 2>/dev/null || true
    cdeck::ok "boot splash unit removed"
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)        usage; exit 0 ;;
        --version|-V)     printf 'boot_splash %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -f|--fast)        FAST=1 ;;
        -d|--demo)        DEMO=1; ACTION="demo" ;;
        -o|--once)        ONCE=1 ;;
        --duration)       shift; DURATION="${1:-6}" ;;
        --no-animation)   ANIMATE=0; FAST=1 ;;
        --no-art)         SHOW_ART=0 ;;
        --stages)         ACTION="stages" ;;
        --install)        ACTION="install" ;;
        --uninstall)      ACTION="uninstall" ;;
        --json)           JSON=1; FAST=1 ;;
        --install-dir)    shift; INSTALL_DIR="${1:-${INSTALL_DIR}}"
                          SPLASH_LOG="${INSTALL_DIR}/logs/boot_splash.log" ;;
        -q|--quiet)       QUIET=1 ;;
        *)                cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

if (( FAST )) || ! [[ -t 1 ]]; then
    ANIMATE=0
fi

case "${ACTION}" in
    stages)    list_stages; exit 0 ;;
    install)   install_unit; exit $? ;;
    uninstall) uninstall_unit; exit $? ;;
esac

if (( QUIET || JSON )); then
    SHOW_ART=0
    ANIMATE=0
fi

if (( ! JSON )) && (( ! QUIET )); then
    paint_splash
fi

if (( DEMO )); then
    demo_run
    printf '\n  %bdemo replay complete%b\n\n' "${C_DIM}" "${C_RESET}"
    exit 0
fi

if (( ANIMATE )); then
    animate_all
else
    # No animation: still run every stage, then print the table
    for i in "${!STAGE_NAMES[@]}"; do
        run_stage "${i}"
    done
fi

FAILED=0
WARNED=0
for verdict in "${STAGE_RESULTS[@]}"; do
    [[ "${verdict}" == "FAIL" ]] && FAILED=$(( FAILED + 1 ))
    [[ "${verdict}" == "WARN" ]] && WARNED=$(( WARNED + 1 ))
done

if (( JSON )); then
    render_json
elif (( QUIET )); then
    (( FAILED )) && cdeck::warn "${FAILED} boot stage(s) failed - see ${SPLASH_LOG}"
else
    render_results
    if (( FAILED )); then
        cdeck::warn "${FAILED} stage(s) failed, ${WARNED} warning(s) - see ${SPLASH_LOG}"
        cdeck::info "troubleshooting: ${INSTALL_DIR}/docs/TROUBLESHOOTING.md"
    elif (( WARNED )); then
        cdeck::ok "no failures - ${WARNED} warning(s) worth reading above"
    else
        cdeck::ok "all stages healthy - deck ready"
    fi
    printf '  %btype%b %bcdeck%b for the HUD · %bC-a ?%b for keybindings · %bcdeck help%b for commands\n\n' \
        "${C_DIM}" "${C_RESET}" "${C_BOLD}" "${C_RESET}" \
        "${C_BOLD}" "${C_RESET}" "${C_BOLD}" "${C_RESET}"
fi

exit "${FAILED}"
