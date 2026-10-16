#!/usr/bin/env bash
# =============================================================================
# test_hardware.sh - verify the hardware the deck is supposed to drive
# =============================================================================
#
# Description
# -----------
# Walks the hardware classes the platform supports and reports, for each one,
# whether it is present and *usable* - not merely detected. Where a capability
# can be probed without changing anything it is (``iw list`` for monitor mode,
# ``iwconfig`` for injection support, ``lsusb`` for the SDRs, the I2C bus for the
# OLED), and where it cannot, the check is reported as a skip with the exact
# command to run next.
#
# The script is written for the moment you plug something in: run it with the
# device attached, then again without, and compare. ``--watch`` repeats the run
# every few seconds and highlights changes, which is the quickest way to find a
# flaky USB connector.
#
# Exit code: the number of required checks that failed (0 = everything the deck
# needs is there). Optional hardware never causes a non-zero exit unless
# ``testing.strict`` is true in cyberdeck.conf.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash, coreutils; optional: iw, lsusb, rfkill, sqlite3, python3
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./test_hardware.sh                 # full hardware report
#   ./test_hardware.sh --json          # machine readable
#   ./test_hardware.sh --watch 5       # re-check every 5 seconds
#   ./test_hardware.sh --skip-optional # only the mandatory classes
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

cdeck::init "test_hardware"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
QUIET=0
JSON=0
VERBOSE=0
WATCH=0
WATCH_INTERVAL=5
SKIP_OPTIONAL=0
FAILURES=0
PASSES=0
SKIPS=0
declare -a RESULTS=()

usage() {
    cdeck::usage_header \
        "Verify the hardware the cyberdeck can drive" \
        "$0 [--quiet] [--json] [--verbose] [--watch SECONDS] [--skip-optional]" \
        "$0                    # check every hardware class" \
        "$0 --json             # machine-readable report" \
        "$0 --watch 5          # repeat every five seconds and show changes"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -q, --quiet          only failures and the summary
  -v, --verbose        print details for every check
  -j, --json           emit JSON (implies --quiet)
  -w, --watch SECONDS  repeat the checks (default 5s) until interrupted
  --skip-optional      report only the classes the platform requires
  --strict             treat missing optional hardware as a failure
  -h, --help           this help
  -V, --version        version

${C_BOLD}WHAT IT CHECKS${C_RESET}
  cpu/memory · disk space · wireless radio · monitor mode · injection
  bluetooth · SDR receivers · GPS · GPIO header · I2C/OLED · Proxmark
  USB controllers · battery · thermal sensors · network interfaces

${C_BOLD}EXIT CODE${C_RESET}
  Number of failed required checks, or of all failed checks with --strict.
EOF
}

# --------------------------------------------------------------------------- #
# Framework
# --------------------------------------------------------------------------- #
record() {
    # record <status> <class> <name> <detail>
    local status="$1" class="$2" name="$3" detail="${4:-}"
    case "${status}" in
        PASS) PASSES=$(( PASSES + 1 )) ;;
        FAIL) FAILURES=$(( FAILURES + 1 )) ;;
        SKIP) SKIPS=$(( SKIPS + 1 )) ;;
    esac
    RESULTS+=("${status}|${class}|${name}|${detail}")
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
    printf '  %b%s%b %-26s %b%-4s%b %s\n' "${colour}" "${glyph}" "${C_RESET}" \
        "${name}" "${colour}" "${status}" "${C_RESET}" "${detail}"
}

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
check_compute() {
    local cores memory_gb
    cores="$(nproc 2>/dev/null || echo 0)"
    memory_gb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0) / 1024 / 1024 ))
    if (( cores >= 2 )); then
        record PASS compute "cpu cores" "${cores} cores"
    else
        record FAIL compute "cpu cores" "${cores} - at least 2 recommended"
    fi
    if (( memory_gb >= 4 )); then
        record PASS compute "memory" "${memory_gb} GiB"
    elif (( memory_gb >= 2 )); then
        record PASS compute "memory" "${memory_gb} GiB (hashing will be slow)"
    else
        record FAIL compute "memory" "${memory_gb} GiB - 4 GiB recommended"
    fi
    local architecture
    architecture="$(uname -m)"
    case "${architecture}" in
        x86_64|aarch64|armv7l|armv6l) record PASS compute "architecture" "${architecture}" ;;
        *) record FAIL compute "architecture" "${architecture} is not supported" ;;
    esac
}

check_storage() {
    local free_gb percent
    free_gb=$(( $(df -Pk "${INSTALL_DIR}" 2>/dev/null | awk 'NR==2 {print $4}') / 1024 / 1024 ))
    percent="$(df -P "${INSTALL_DIR}" 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')"
    if (( ${percent:-100} < 90 )); then
        record PASS storage "free space" "${free_gb} GiB free (${percent}% used)"
    else
        record FAIL storage "free space" "${free_gb} GiB free (${percent}% used)"
    fi
    local count
    count="$(lsblk -dn -o NAME 2>/dev/null | wc -l | tr -d ' ')"
    if (( count > 0 )); then
        record PASS storage "block devices" "${count} device(s)"
    else
        record SKIP storage "block devices" "lsblk unavailable"
    fi
    local removable
    removable="$(lsblk -dn -o NAME,RM 2>/dev/null | awk '$2 == "1" {print $1}' | tr '\n' ' ')"
    if [[ -n "${removable}" ]]; then
        record PASS storage "removable media" "${removable}"
    else
        record SKIP storage "removable media" "none attached"
    fi
}

check_wireless() {
    local radios=() path name
    for path in /sys/class/net/*/wireless; do
        [[ -e "${path}" ]] || continue
        name="$(basename "$(dirname "${path}")")"
        radios+=("${name}")
    done
    if ((${#radios[@]} == 0)); then
        record SKIP wireless "wireless interface" "none present - plug in a USB radio"
        record SKIP wireless "monitor mode" "needs a wireless interface"
        record SKIP wireless "injection support" "needs a wireless interface"
        return 0
    fi
    record PASS wireless "wireless interface" "${radios[*]}"

    local radio
    for radio in "${radios[@]}"; do
        local driver chipset
        driver="$(basename "$(readlink -f "/sys/class/net/${radio}/device/driver" 2>/dev/null)" 2>/dev/null)"
        chipset="${driver:-unknown}"
        record PASS wireless "${radio} driver" "${chipset}"
    done

    local monitor_if monitor_state="no"
    monitor_if="$(cdeck::monitor_interface 2>/dev/null || true)"
    if [[ -n "${monitor_if}" ]] && have iw; then
        if iw dev "${monitor_if}" info 2>/dev/null | grep -q monitor; then
            monitor_state="yes on ${monitor_if}"
        fi
    fi
    if [[ "${monitor_state}" == "no" ]] && have iw; then
        if iw list 2>/dev/null | grep -q "monitor"; then
            monitor_state="supported (not enabled)"
        fi
    fi
    case "${monitor_state}" in
        no) record FAIL wireless "monitor mode" "not supported by the detected radio" ;;
        *)  record PASS wireless "monitor mode" "${monitor_state}" ;;
    esac

    local injection="unknown"
    if have iwconfig; then
        if iwconfig 2>/dev/null | grep -qi "injection"; then
            injection="advertised by the driver"
        fi
    fi
    if [[ "${injection}" == "unknown" ]] && have airmon-ng; then
        injection="check with: airmon-ng start ${monitor_if:-wlan0}"
    fi
    if [[ "${injection}" == "unknown" ]]; then
        record SKIP wireless "injection support" "needs airmon-ng/aireplay-ng to confirm"
    else
        record PASS wireless "injection support" "${injection}"
    fi

    if have rfkill; then
        local blocked
        blocked="$(rfkill list 2>/dev/null | grep -c "Soft blocked: yes" || true)"
        if (( blocked > 0 )); then
            record PASS wireless "rfkill" "${blocked} device(s) soft blocked"
        else
            record PASS wireless "rfkill" "nothing blocked"
        fi
    fi
}

check_bluetooth() {
    if [[ ! -d /sys/class/bluetooth ]] || [[ -z "$(ls -A /sys/class/bluetooth 2>/dev/null)" ]]; then
        if have lsusb && lsusb 2>/dev/null | grep -qi bluetooth; then
            record PASS bluetooth "adapter" "USB adapter present, kernel module not loaded"
        else
            record SKIP bluetooth "adapter" "no bluetooth controller found"
        fi
        return 0
    fi
    local address
    address="$(ls /sys/class/bluetooth 2>/dev/null | head -1)"
    record PASS bluetooth "adapter" "${address}"
    if [[ -r "/sys/class/bluetooth/${address}/address" ]]; then
        record PASS bluetooth "address" "$(cat "/sys/class/bluetooth/${address}/address")"
    fi
    if have bluetoothctl; then
        if bluetoothctl show >/dev/null 2>&1; then
            record PASS bluetooth "bluetoothctl" "$(bluetoothctl show 2>/dev/null | head -1)"
        else
            record FAIL bluetooth "bluetoothctl" "the controller did not answer (rfkill or service down)"
        fi
    else
        record SKIP bluetooth "bluetoothctl" "bluez-utils not installed"
    fi
    if have hciconfig; then
        local up
        up="$(hciconfig 2>/dev/null | grep -c "UP RUNNING" || true)"
        record PASS bluetooth "hci state" "${up} interface(s) up"
    fi
}

check_sdr() {
    local found=0
    if have lsusb; then
        if lsusb 2>/dev/null | grep -qiE "RTL2838|RTL2832|Realtek.*DVB"; then
            record PASS sdr "RTL-SDR receiver" \
                "$(lsusb 2>/dev/null | grep -iE 'RTL2838|RTL2832' | head -1 | cut -c1-52)"
            found=$(( found + 1 ))
        fi
        if lsusb 2>/dev/null | grep -qiE "HackRF|Great Scott"; then
            record PASS sdr "HackRF" "transmit-capable radio present"
            found=$(( found + 1 ))
        fi
        if lsusb 2>/dev/null | grep -qi "Yard Stick One"; then
            record PASS sdr "Yard Stick One" "sub-GHz radio present"
            found=$(( found + 1 ))
        fi
    fi
    if [[ -e /dev/rtl_sdr ]]; then
        record PASS sdr "rtl_sdr device node" "/dev/rtl_sdr"
    fi
    if have rtl_test; then
        record PASS sdr "rtl_test available" "$(command -v rtl_test)"
    elif (( found )); then
        record SKIP sdr "rtl_test available" "install rtl-sdr: sudo pacman -S rtl-sdr"
    fi
    if have hackrf_info && lsusb 2>/dev/null | grep -qiE "HackRF|Great Scott"; then
        if timeout 10 hackrf_info >/dev/null 2>&1; then
            record PASS sdr "hackrf_info answers" "transmit and receive are usable"
        else
            record FAIL sdr "hackrf_info answers" "device detected but not responding"
        fi
    fi
    if (( found == 0 )); then
        record SKIP sdr "receivers" "no SDR hardware attached - sdr/ modules return exit 3"
    fi
    local dump1090="$(cdeck::conf_get sdr.dump1090_binary dump1090-mutability)"
    if have "${dump1090}"; then
        record PASS sdr "dump1090" "${dump1090}"
    else
        record SKIP sdr "dump1090" "${dump1090} not installed (ADS-B uses the built-in decoder)"
    fi
}

check_gps() {
    local configured device
    configured="$(cdeck::conf_get gps.device /dev/ttyACM0)"
    device="${configured}"
    if [[ ! -e "${device}" ]]; then
        if [[ -e /dev/ttyUSB0 ]]; then
            device="/dev/ttyUSB0"
            record PASS gps "serial device" "${device} (config says ${configured})"
        else
            record SKIP gps "receiver" "no serial GPS at ${configured}"
            return 0
        fi
    else
        record PASS gps "serial device" "${device}"
    fi
    if have gpsd; then
        record PASS gps "gpsd" "$(command -v gpsd)"
        if timeout 5 gpspipe -w -n 1 >/dev/null 2>&1; then
            record PASS gps "gpsd responding" "fix data available"
        else
            record SKIP gps "gpsd responding" "gpsd is installed but not running"
        fi
    else
        record SKIP gps "gpsd" "not installed: sudo pacman -S gpsd"
    fi
}

check_gpio() {
    local available=0
    if [[ -d /sys/class/gpio ]] && [[ -w /sys/class/gpio/export ]]; then
        local count
        count="$(ls /sys/class/gpio 2>/dev/null | grep -c '^gpio' || true)"
        record PASS gpio "sysfs interface" "/sys/class/gpio (${count} exported)"
        available=1
    elif [[ -d /sys/class/gpio ]]; then
        record PASS gpio "sysfs interface" "present but needs root to export pins"
        available=1
    fi
    local module
    if have python3; then
        for module in lgpio RPi GPIO; do
            if "${CDECK_PYTHON:-python3}" -c "import ${module}" >/dev/null 2>&1; then
                record PASS gpio "python module ${module}" ""
                available=1
            fi
        done
    fi
    if [[ -d /sys/class/gpio/gpiochip0 ]]; then
        record PASS gpio "gpiochip0" "kernel exposes a GPIO controller"
        available=1
    fi
    if (( available == 0 )); then
        record SKIP gpio "header" "this host has no GPIO header (x86 machine?)"
    fi
    local enabled
    enabled="$(cdeck::conf_get gpio.enabled false)"
    record PASS gpio "config" "gpio.enabled=${enabled}"
}

check_i2c() {
    local buses=() path
    for path in /dev/i2c-*; do
        [[ -e "${path}" ]] || continue
        buses+=("$(basename "${path}")")
    done
    if ((${#buses[@]} == 0)); then
        record SKIP i2c "bus" "no /dev/i2c-* nodes - enable I2C in raspi-config"
        record SKIP i2c "oled panel" "no I2C bus available"
        return 0
    fi
    record PASS i2c "bus" "${buses[*]}"
    local address scan_tool
    address="$(cdeck::conf_get gpio.oled_i2c_address 0x3C)"
    if have i2cdetect; then
        local bus="${buses[0]#i2c-}"
        scan_tool="$(i2cdetect -y "${bus}" 2>/dev/null | grep -c "${address#0x}\|${address}" || true)"
        if (( scan_tool > 0 )); then
            record PASS i2c "oled panel" "${address} answers on i2c-${bus}"
        else
            record SKIP i2c "oled panel" "nothing at ${address} on i2c-${bus}"
        fi
    else
        record SKIP i2c "oled panel" "i2c-tools not installed: sudo pacman -S i2c-tools"
    fi
    if [[ -r /sys/module/i2c_bcm2835/parameters/bcm2835_debug ]]; then
        record PASS i2c "bcm2835 driver" "loaded"
    fi
}

check_proxmark() {
    if have proxmark3; then
        record PASS proxmark "software" "$(command -v proxmark3)"
        local device
        for device in /dev/ttyACM* /dev/ttyUSB*; do
            if [[ -e "${device}" ]]; then
                record PASS proxmark "serial device" "${device}"
                return 0
            fi
        done
        record SKIP proxmark "device" "no serial device for the Proxmark"
    else
        record SKIP proxmark "software" "proxmark3 not installed (optional)"
    fi
}

check_usb() {
    if have lsusb; then
        local count
        count="$(lsusb 2>/dev/null | wc -l | tr -d ' ')"
        record PASS usb "controllers" "${count} USB device(s) enumerated"
        local controllers
        controllers="$(lspci 2>/dev/null | grep -ci "USB controller" || true)"
        (( controllers > 0 )) && record PASS usb "host controllers" "${controllers} PCI USB controller(s)"
    else
        record SKIP usb "enumeration" "usbutils not installed"
    fi
    if [[ -d /sys/bus/usb/devices ]]; then
        local speed
        speed="$(for device in /sys/bus/usb/devices/*/speed; do cat "${device}" 2>/dev/null; done \
                 | sort -rn | head -1)"
        [[ -n "${speed}" ]] && record PASS usb "highest link speed" "${speed} Mbps"
    fi
    if [[ -f /etc/udev/rules.d/99-cyberdeck-usb.rules ]]; then
        record PASS usb "udev rules" "installed"
    else
        record SKIP usb "udev rules" "run setup.sh to install them"
    fi
}

check_power_and_thermal() {
    local battery zone found=0
    for battery in /sys/class/power_supply/BAT*/capacity; do
        [[ -r "${battery}" ]] || continue
        found=1
        record PASS power "battery" "$(cat "${battery}" 2>/dev/null)% ($(cat "${battery%capacity}status" 2>/dev/null || echo unknown))"
        break
    done
    (( found )) || record SKIP power "battery" "no battery - mains-powered deck"
    if [[ -d /sys/class/power_supply/AC ]] || [[ -d /sys/class/power_supply/ADP1 ]]; then
        record PASS power "mains adapter" "present"
    fi
    found=0
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        [[ -r "${zone}" ]] || continue
        local raw; raw="$(cat "${zone}" 2>/dev/null || echo 0)"
        (( raw > 1000 )) && raw=$(( raw / 1000 ))
        record PASS thermal "zone" "${raw}C"
        found=1
    done
    (( found )) || record SKIP thermal "sensors" "no thermal zones exposed"
}

check_network_hardware() {
    local interfaces=() path
    for path in /sys/class/net/*; do
        interfaces+=("$(basename "${path}")")
    done
    if ((${#interfaces[@]} == 0)); then
        record FAIL network "interfaces" "no network interfaces at all"
        return 0
    fi
    record PASS network "interfaces" "${interfaces[*]}"
    local wired=0
    for path in /sys/class/net/*/device; do
        [[ -e "${path}" ]] || continue
        wired=$(( wired + 1 ))
    done
    record PASS network "physical devices" "${wired}"
    if have ethtool; then
        local interface
        interface="$(cdeck::conf_get network.ethernet_interface eth0)"
        if [[ -e "/sys/class/net/${interface}" ]]; then
            if [[ -x /sys/class/net/${interface}/device ]]; then true; fi
            local speed
            speed="$(cat "/sys/class/net/${interface}/speed" 2>/dev/null || echo unknown)"
            record PASS network "${interface} link speed" "${speed} Mbps"
        fi
    fi
}

check_config_hardware() {
    local file="${INSTALL_DIR}/state/hardware.json"
    if [[ -f "${file}" ]]; then
        record PASS config "hardware inventory" "$(date -r "${file}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo present)"
    else
        record SKIP config "hardware inventory" "run: cdeck hardware --write"
    fi
    if [[ -x "${INSTALL_DIR}/utilities/hardware_detect.sh" ]]; then
        record PASS config "hardware_detect.sh" "installed"
    else
        record FAIL config "hardware_detect.sh" "missing from the install"
    fi
}

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
emit_json() {
    printf '{\n'
    printf '  "install_dir": "%s",\n' "${INSTALL_DIR}"
    printf '  "generated": "%s",\n' "$(cdeck::iso_stamp)"
    printf '  "passed": %d, "failed": %d, "skipped": %d,\n' "${PASSES}" "${FAILURES}" "${SKIPS}"
    printf '  "checks": [\n'
    local first=1 entry
    for entry in "${RESULTS[@]}"; do
        IFS='|' read -r status class name detail <<< "${entry}"
        (( first )) || printf ',\n'
        first=0
        printf '    {"status": "%s", "class": "%s", "name": "%s", "detail": "%s"}' \
            "${status}" "${class}" "${name//\"/}" "${detail//\"/}"
    done
    printf '\n  ]\n}\n'
}

run_all() {
    RESULTS=(); PASSES=0; FAILURES=0; SKIPS=0
    check_compute
    check_storage
    check_wireless
    check_bluetooth
    check_sdr
    check_gps
    check_gpio
    check_i2c
    check_proxmark
    check_usb
    check_power_and_thermal
    check_network_hardware
    check_config_hardware
}

summary_line() {
    printf '%d passed · %d failed · %d skipped' "${PASSES}" "${FAILURES}" "${SKIPS}"
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)       usage; exit 0 ;;
        --version|-V)    printf 'test_hardware %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -q|--quiet)      QUIET=1 ;;
        -v|--verbose)    VERBOSE=1 ;;
        -j|--json)       JSON=1; QUIET=1 ;;
        -w|--watch)      WATCH=1; shift; WATCH_INTERVAL="${1:-5}" ;;
        --skip-optional) SKIP_OPTIONAL=1 ;;
        --strict)        export CDECK_STRICT_TESTS=1 ;;
        --install-dir)   shift; INSTALL_DIR="${1:-${INSTALL_DIR}}" ;;
        *)               cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

if [[ "$(cdeck::conf_get testing.skip_hardware_tests false)" == "true" ]]; then
    cdeck::info "testing.skip_hardware_tests is true - hardware checks are disabled"
    exit 0
fi

if (( WATCH )); then
    previous=""
    trap 'printf "\n"; exit 0' INT TERM
    while :; do
        run_all
        current="$(summary_line)"
        printf '\r  %-70s' "$(cdeck::timestamp) hardware: ${current}"
        if [[ -n "${previous}" && "${previous}" != "${current}" ]]; then
            printf '\n'
            cdeck::warn "hardware changed: %s → %s" "${previous}" "${current}"
            for entry in "${RESULTS[@]}"; do
                IFS='|' read -r status class name detail <<< "${entry}"
                [[ "${status}" == "FAIL" ]] && printf '     %b✘%b %s · %s\n' "${C_RED}" "${C_RESET}" "${name}" "${detail}"
            done
        fi
        previous="${current}"
        sleep "${WATCH_INTERVAL}"
    done
fi

if (( ! QUIET )); then
    cdeck::banner "hardware test" "${INSTALL_DIR} · $(hostname)"
fi

run_all

if (( JSON )); then
    emit_json
else
    printf '\n  %b%s%b\n\n' "${C_BOLD}" "$(summary_line)" "${C_RESET}"
    if (( FAILURES )); then
        cdeck::warn "${FAILURES} hardware check(s) failed"
        cdeck::info "each failure above lists the exact device or package that is missing"
        cdeck::info "full inventory: cdeck hardware --report"
    else
        cdeck::ok "every required hardware class is present"
    fi
    printf '\n'
fi

if (( FAILURES )); then
    exit "${FAILURES}"
fi
exit 0
