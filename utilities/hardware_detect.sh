#!/usr/bin/env bash
# =============================================================================
# hardware_detect.sh - hardware inventory and capability report
# =============================================================================
#
# Description
# -----------
# Produces a complete inventory of the deck: board, CPU, memory, storage,
# WiFi and Ethernet adapters (with driver and monitor-mode capability), SDR
# receivers, Bluetooth, GPIO/I2C/SPI, GPS, displays, battery, thermal zones and
# USB topology. Two output modes:
#
#   --report   human-readable, colour-coded capability table (default)
#   --json     machine-readable, consumed by setup.sh and `cdeck status`
#
# The JSON schema is stable and is the contract used elsewhere in the toolkit:
#   board      : string   - SBC model, DMI product name, or architecture
#   wifi[]     : {interface, driver, chipset, monitor_capable, bands, mac}
#   sdr[]      : [{name, kind, id, detail}]  (RTL-SDR, HackRF, Proxmark, ...)
#   gpio       : {available, chip, pins[]}
#   ...plus cpu, memory, disks[], ethernet[], bluetooth, gps, displays[],
#   battery, thermal{}, kernel, distro, arch, generated.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash, coreutils; optional: lspci, lsusb, iw, lshw, jq, python3
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./hardware_detect.sh                 # human-readable report
#   ./hardware_detect.sh --json          # JSON inventory (used by setup.sh)
#   ./hardware_detect.sh --write         # write state/hardware.json
#   ./hardware_detect.sh --check wifi    # exit 3 when WiFi is missing
#   ./hardware_detect.sh --check sdr,gpio
#   ./hardware_detect.sh --help
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

cdeck::init "hardware_detect"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
STATE_FILE="${CDECK_INSTALL_DIR}/state/hardware.json"
MODE="report"
EXPLICIT_MODE=0
WRITE_FILE=""
CHECKS=""
VERBOSE=0
QUIET=0

usage() {
    cdeck::usage_header \
        "Hardware inventory and capability report" \
        "$0 [--report | --json | --write [file] | --check <component>[,...]]" \
        "$0                          # human-readable capability report" \
        "$0 --json                   # JSON inventory (stable schema)" \
        "$0 --write                  # refresh state/hardware.json" \
        "$0 --check wifi,sdr,gpio    # exit 3 if any listed component is missing" \
        "$0 --json | jq .wifi"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -r, --report            human-readable report (default)
  -j, --json              machine-readable inventory
  -w, --write [FILE]      write the JSON inventory (default: ${STATE_FILE})
  -c, --check LIST        comma-separated: wifi, sdr, gpio, gps, bluetooth,
                          battery, ethernet, display, proxmark, i2c
  -v, --verbose           include raw probe details
  -n, --no-colour         disable colour codes
  --quiet                 only emit errors (with --json: emits nothing else)
  --help, -h              this help

${C_BOLD}EXIT CODES${C_RESET}
  0  requested hardware (or the report) completed successfully
  2  bad usage
  3  a component named by --check is absent
EOF
}

while (( $# )); do
    case "$1" in
        --help|-h)      usage; exit 0 ;;
        --version|-V)   printf 'hardware_detect %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -r|--report)    MODE="report"; EXPLICIT_MODE=1 ;;
        -j|--json)      MODE="json"; EXPLICIT_MODE=1 ;;
        -w|--write)     MODE="write"; EXPLICIT_MODE=1
                        if [[ -n "${2:-}" && "${2:0:1}" != "-" ]]; then WRITE_FILE="$2"; shift; fi ;;
        -c|--check)     shift; CHECKS="${1:-}"; MODE="${MODE}" ;;
        -v|--verbose)   VERBOSE=1 ;;
        -n|--no-colour) NO_COLOR=1; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""; C_DIM=""; C_MAGENTA=""; C_RESET="" ;;
        --quiet)        QUIET=1 ;;
        *)              cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

[[ -z "${WRITE_FILE}" ]] && WRITE_FILE="${STATE_FILE}"

# --------------------------------------------------------------------------- #
# Probe helpers
# --------------------------------------------------------------------------- #
board_model() {
    if [[ -r /proc/device-tree/model ]]; then
        tr -d '\0' < /proc/device-tree/model
    elif [[ -r /sys/firmware/devicetree/base/model ]]; then
        tr -d '\0' < /sys/firmware/devicetree/base/model
    elif cdeck::has_cmd dmidecode && [[ "${EUID}" -eq 0 ]]; then
        dmidecode -s system-product-name 2>/dev/null | head -1
    elif [[ -r /sys/class/dmi/id/product_name ]]; then
        cat /sys/class/dmi/id/product_name
    else
        printf '%s (%s)' "$(uname -m)" "$(uname -r)"
    fi
}

cpu_model() {
    awk -F': ' '/^model name|^Model/ {print $2; exit}' /proc/cpuinfo 2>/dev/null \
        || uname -p
}

cpu_cores() {
    local count
    count="$(nproc 2>/dev/null)" || count="$(grep -c ^processor /proc/cpuinfo 2>/dev/null)"
    printf '%s' "${count:-1}"
}

memory_total() {
    awk '/^MemTotal:/ {printf "%.1f GB", $2 / 1024 / 1024; exit}' /proc/meminfo 2>/dev/null \
        || printf 'unknown'
}

disks_json() {
    # name|size|model  for every whole disk
    if cdeck::has_cmd lsblk; then
        lsblk -d -n -o NAME,SIZE,MODEL 2>/dev/null \
            | awk 'NF {name=$1; size=$2; $1=""; $2=""; sub(/^  */,""); printf "%s|%s|%s\n", name, size, $0}'
    elif [[ -r /proc/partitions ]]; then
        awk 'NR>2 && $4 !~ /[0-9]$/ {printf "%s|%s|\n", $4, $3}' /proc/partitions
    fi
}

wifi_json() {
    # interface|driver|chipset|monitor|bands|mac|vendor
    local iface dir driver chipset monitor bands mac vendor
    for dir in /sys/class/net/*; do
        iface="$(basename "${dir}")"
        [[ -d "${dir}/wireless" || -d "${dir}/phy80211" ]] || continue
        driver="virtual"
        if [[ -e "${dir}/device/driver" ]]; then
            driver="$(basename "$(readlink -f "${dir}/device/driver")" 2>/dev/null)"
        fi
        chipset="unknown"
        if cdeck::has_cmd lspci && [[ -e "${dir}/device" ]]; then
            local pci
            pci="$(basename "$(readlink -f "${dir}/device")" 2>/dev/null)"
            chipset="$(lspci -s "${pci#0000:}" 2>/dev/null | sed 's/.*: //' | head -1)"
            # USB adapters are not on the PCI bus: look them up in lsusb instead
            if [[ -z "${chipset}" && -e "${dir}/device/../idVendor" ]]; then
                local vid pid
                vid="$(cat "${dir}/device/../idVendor" 2>/dev/null)"
                pid="$(cat "${dir}/device/../idProduct" 2>/dev/null)"
                chipset="$(lsusb -d "${vid}:${pid}" 2>/dev/null | sed 's/.*ID [0-9a-f:]* //' | head -1)"
            fi
        fi
        [[ -z "${chipset}" ]] && chipset="${driver}"
        monitor="false"
        bands=""
        if cdeck::has_cmd iw; then
            if iw "${iface}" info 2>/dev/null | grep -q 'type monitor'; then
                monitor="true"
            fi
            local phy
            phy="$(cat "${dir}/phy80211/name" 2>/dev/null)"
            if [[ -n "${phy}" ]]; then
                if iw phy "${phy}" info 2>/dev/null | grep -A20 'Supported interface modes' | grep -q '\* monitor'; then
                    monitor="true"
                fi
                bands="$(iw phy "${phy}" info 2>/dev/null \
                    | grep -oE '^[[:space:]]+\* [0-9]{4} MHz' | awk '{print $2}' \
                    | awk '{ if ($1 < 3000) band["2.4GHz"]=1; else if ($1 < 6000) band["5GHz"]=1; else band["6GHz"]=1 }
                             END { for (b in band) printf "%s ", b }' | sed 's/ $//')"
            fi
        fi
        mac="$(cat "${dir}/address" 2>/dev/null)"
        vendor="unknown"
        if cdeck::has_cmd python3; then
            vendor="$(python3 - "${mac}" <<'PYEOF' 2>/dev/null || echo unknown
import sys
try:
    sys.path.insert(0, "/opt/cyberdeck-arsenal/lib")
    import os
    os.environ.setdefault("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal")
    from cyberlib import OuiLookup
    print(OuiLookup().vendor(sys.argv[1]))
except Exception:
    print("unknown")
PYEOF
)"
        fi
        printf '%s|%s|%s|%s|%s|%s|%s\n' "${iface}" "${driver}" "${chipset}" "${monitor}" \
            "${bands:-unknown}" "${mac}" "${vendor}"
    done
}

ethernet_json() {
    local iface dir driver mac speed
    for dir in /sys/class/net/*; do
        iface="$(basename "${dir}")"
        [[ "${iface}" == "lo" ]] && continue
        [[ -d "${dir}/wireless" || -d "${dir}/phy80211" ]] && continue
        # Skip virtual bridges/veths: they have no device directory
        [[ -e "${dir}/device" ]] || continue
        driver="virtual"
        [[ -e "${dir}/device/driver" ]] && driver="$(basename "$(readlink -f "${dir}/device/driver")" 2>/dev/null)"
        mac="$(cat "${dir}/address" 2>/dev/null)"
        speed="$(cat "${dir}/speed" 2>/dev/null || echo unknown)"
        # The kernel reports -1 for "unknown/not negotiated" on some drivers
        [[ "${speed}" =~ ^-?[0-9]+$ ]] && (( speed < 0 )) && speed="unknown"
        printf '%s|%s|%s|%s\n' "${iface}" "${driver}" "${mac}" "${speed}"
    done
}

sdr_json() {
    # name|kind|id|detail
    if ! cdeck::has_cmd lsusb; then
        return 0
    fi
    lsusb 2>/dev/null | while IFS= read -r line; do
        local vid_pid="${line#*ID }"; vid_pid="${vid_pid%% *}"
        local vid="${vid_pid%%:*}" pid="${vid_pid##*:}"
        local name
        name="$(sed 's/.*ID [0-9a-f:]* //' <<< "${line}")"
        case "${vid}:${pid}" in
            0bda:2838|0bda:2832) printf '%s|RTL-SDR|%s|%s\n' "RTL2838 DVB-T" "${vid}:${pid}" "${name}" ;;
            0bda:2831)           printf '%s|RTL-SDR|%s|%s\n' "RTL2832U" "${vid}:${pid}" "${name}" ;;
            1d50:6089)           printf '%s|HackRF|%s|%s\n' "Great Scott Gadgets HackRF One" "${vid}:${pid}" "${name}" ;;
            1d50:60a1)           printf '%s|GreatFET|%s|%s\n' "Great Scott Gadgets GreatFET" "${vid}:${pid}" "${name}" ;;
            1d50:604b)           printf '%s|YARD Stick One|%s|%s\n' "YARD Stick One (sub-GHz)" "${vid}:${pid}" "${name}" ;;
            0456:0002|0456:0003) printf '%s|PlutoSDR|%s|%s\n' "ADALM-PLUTO (TX/RX)" "${vid}:${pid}" "${name}" ;;
            04d8:000a)           printf '%s|FlipperZero|%s|%s\n' "Flipper Zero" "${vid}:${pid}" "${name}" ;;
            0483:5740|0483:df11) printf '%s|STM32/Proxmark|%s|%s\n' "STM32 device (Proxmark3 possible)" "${vid}:${pid}" "${name}" ;;
            1d6b:*|1a86:*|0bda:8153) : ;;  # hubs, serial bridges, Ethernet: not SDRs
            2a03:0001|2a03:0011) printf '%s|Airspy|%s|%s\n' "Airspy R2/Mini" "${vid}:${pid}" "${name}" ;;
            2500:0020)           printf '%s|Airspy HF+|%s|%s\n' "Airspy HF+ Discovery" "${vid}:${pid}" "${name}" ;;
            1d50:60e2|1d50:6108) printf '%s|Faraday|%s|%s\n' "Faraday SDR" "${vid}:${pid}" "${name}" ;;
        esac
    done
    # Proxmark3 exposes a CDC-ACM serial port; also catch it by name
    if cdeck::has_cmd lsusb && lsusb 2>/dev/null | grep -qi proxmark; then
        printf '%s|Proxmark3|proxmark3|%s\n' "Proxmark3" "RFID/NFC research device"
    fi
}

bluetooth_json() {
    # present|name|version|hci
    if [[ -d /sys/class/bluetooth ]] && [[ -n "$(ls -A /sys/class/bluetooth 2>/dev/null)" ]]; then
        local hci
        hci="$(ls /sys/class/bluetooth 2>/dev/null | head -1)"
        local name="unknown" version="unknown"
        if cdeck::has_cmd hciconfig; then
            name="$(hciconfig -a 2>/dev/null | awk -F'Bus: ' '/Bus:/ {print "bus " $2; exit}')"
        fi
        if [[ -r /sys/kernel/debug/bluetooth/"${hci}"/features ]]; then
            version="$(cat /sys/kernel/debug/bluetooth/"${hci}"/version 2>/dev/null || echo unknown)"
        fi
        printf 'true|%s|%s|%s\n' "${name:-unknown}" "${version:-unknown}" "${hci}"
    else
        printf 'false|||\n'
    fi
}

gps_json() {
    # present|device
    local device
    for device in /dev/ttyACM* /dev/ttyUSB* /dev/ttyAMA*; do
        [[ -e "${device}" ]] || continue
        if cdeck::has_cmd udevadm; then
            if udevadm info -q property -n "${device}" 2>/dev/null | grep -qi 'gps\|u-blox\|nmea'; then
                printf 'true|%s\n' "${device}"; return 0
            fi
        fi
        # A GPS is usually the only thing talking NMEA on a serial port
        if timeout 1 head -c 64 "${device}" 2>/dev/null | grep -q '\$GP'; then
            printf 'true|%s\n' "${device}"; return 0
        fi
    done
    if cdeck::has_cmd gpsd && pgrep -x gpsd >/dev/null 2>&1; then
        printf 'true|gpsd\n'
    else
        printf 'false|\n'
    fi
}

gpio_json() {
    # available|chip|pin_count
    local chips=() chip
    for chip in /dev/gpiochip*; do
        [[ -e "${chip}" ]] && chips+=("${chip}")
    done
    if (( ${#chips[@]} )); then
        local pins="unknown"
        if cdeck::has_cmd gpioinfo; then
            pins="$(gpioinfo "${chips[0]}" 2>/dev/null | grep -c 'line' || echo unknown)"
        fi
        printf 'true|%s|%s\n' "${chips[0]}" "${pins}"
    else
        printf 'false||0\n'
    fi
}

i2c_json() {
    # present|buses
    local buses=()
    for bus in /dev/i2c-*; do
        [[ -e "${bus}" ]] && buses+=("$(basename "${bus}")")
    done
    if (( ${#buses[@]} )); then
        printf 'true|%s\n' "$(IFS=,; echo "${buses[*]}")"
    else
        printf 'false|\n'
    fi
}

displays_json() {
    # name|resolution|status
    if [[ -d /sys/class/drm ]]; then
        local connector
        for connector in /sys/class/drm/card*/card*; do
            [[ -e "${connector}/status" ]] || continue
            local name status modes
            name="$(basename "${connector}" | sed 's/^card[0-9]*-//')"
            status="$(cat "${connector}/status" 2>/dev/null)"
            modes="$(head -1 "${connector}/modes" 2>/dev/null || echo unknown)"
            printf '%s|%s|%s\n' "${name}" "${modes:-unknown}" "${status:-unknown}"
        done
    elif [[ -e /dev/fb0 ]]; then
        # Small SPI/I2C panels on SBCs
        printf 'framebuffer|%s|active\n' "$(cat /sys/class/graphics/fb0/virtual_size 2>/dev/null || echo unknown)"
    fi
}

battery_json() {
    # present|percent|status|capacity
    local supply name
    for supply in /sys/class/power_supply/*; do
        [[ -e "${supply}/capacity" ]] || continue
        name="$(basename "${supply}")"
        printf 'true|%s|%s|%s\n' \
            "$(cat "${supply}/capacity" 2>/dev/null)" \
            "$(cat "${supply}/status" 2>/dev/null || echo unknown)" \
            "${name}"
        return 0
    done
    printf 'false|||\n'
}

thermal_json() {
    # zone|temp_c
    local zone index temp
    index=0
    for zone in /sys/class/thermal/thermal_zone*; do
        [[ -e "${zone}/temp" ]] || continue
        temp="$(cat "${zone}/temp" 2>/dev/null)"
        [[ -z "${temp}" ]] && continue
        printf '%s|%s\n' "$(cat "${zone}/type" 2>/dev/null || echo "zone${index}")" \
            "$(awk -v t="${temp}" 'BEGIN { printf "%.1f", t / 1000 }')"
        index=$(( index + 1 ))
    done
}

usb_summary() {
    # count|hubs|storage|hid
    local total=0 hubs=0 storage=0 hid=0
    if [[ -d /sys/bus/usb/devices ]]; then
        local device class
        for device in /sys/bus/usb/devices/*/; do
            [[ -r "${device}bDeviceClass" ]] || continue
            total=$(( total + 1 ))
            class="$(cat "${device}bDeviceClass" 2>/dev/null)"
            case "${class}" in
                09) hubs=$(( hubs + 1 )) ;;
                08) storage=$(( storage + 1 )) ;;
                03) hid=$(( hid + 1 )) ;;
            esac
        done
    fi
    printf '%s|%s|%s|%s\n' "${total}" "${hubs}" "${storage}" "${hid}"
}

# --------------------------------------------------------------------------- #
# JSON assembly
# --------------------------------------------------------------------------- #
emit_json() {
    local wifi_lines ethernet_lines sdr_lines disk_lines display_lines thermal_lines
    wifi_lines="$(wifi_json)"
    ethernet_lines="$(ethernet_json)"
    sdr_lines="$(sdr_json)"
    disk_lines="$(disks_json)"
    display_lines="$(displays_json)"
    thermal_lines="$(thermal_json)"
    local bluetooth_line gpio_line i2c_line gps_line battery_line usb_line
    bluetooth_line="$(bluetooth_json)"
    gpio_line="$(gpio_json)"
    i2c_line="$(i2c_json)"
    gps_line="$(gps_json)"
    battery_line="$(battery_json)"
    usb_line="$(usb_summary)"

    if cdeck::has_cmd python3; then
        CYBERDECK_JSON_WIFI="${wifi_lines}" \
        CYBERDECK_JSON_ETH="${ethernet_lines}" \
        CYBERDECK_JSON_SDR="${sdr_lines}" \
        CYBERDECK_JSON_DISK="${disk_lines}" \
        CYBERDECK_JSON_DISPLAY="${display_lines}" \
        CYBERDECK_JSON_THERMAL="${thermal_lines}" \
        CYBERDECK_JSON_BT="${bluetooth_line}" \
        CYBERDECK_JSON_GPIO="${gpio_line}" \
        CYBERDECK_JSON_I2C="${i2c_line}" \
        CYBERDECK_JSON_GPS="${gps_line}" \
        CYBERDECK_JSON_BATTERY="${battery_line}" \
        CYBERDECK_JSON_USB="${usb_line}" \
        CYBERDECK_BOARD="$(board_model)" \
        CYBERDECK_CPU="$(cpu_model)" \
        CYBERDECK_CORES="$(cpu_cores)" \
        CYBERDECK_MEMORY="$(memory_total)" \
        CYBERDECK_PROXMAK="$(cdeck::has_cmd proxmark3 && echo true || echo false)" \
        python3 - <<'PYEOF'
"""Assemble the hardware inventory JSON from the shell probes."""
import json
import os
import platform
import shutil
import time


def rows(value: str):
    """Split a pipe-delimited multi-line probe result into row lists."""
    return [line.split("|") for line in value.strip().splitlines() if line.strip()]


def field(row, index, default=""):
    """Return a field from a row, or a default when absent."""
    return row[index] if len(row) > index and row[index] else default


env = os.environ

wifi = []
for row in rows(env.get("CYBERDECK_JSON_WIFI", "")):
    wifi.append({
        "interface": field(row, 0, "unknown"),
        "driver": field(row, 1, "unknown"),
        "chipset": field(row, 2, "unknown"),
        "monitor_capable": field(row, 3, "false") == "true",
        "bands": field(row, 4, "unknown"),
        "mac": field(row, 5, ""),
        "vendor": field(row, 6, "unknown"),
        "injection_capable": field(row, 3, "false") == "true" and any(
            name in field(row, 1, "") for name in
            ("ath9k", "ath9k_htc", "ath10k", "rt2800usb", "rt73usb", "rtl8187",
             "rtl8812au", "rtl8814au", "rtl88xxau", "mt76", "mt7601u", "carl9170")),
    })

ethernet = [{
    "interface": field(row, 0, "unknown"),
    "driver": field(row, 1, "unknown"),
    "mac": field(row, 2, ""),
    "speed_mbps": field(row, 3, "unknown"),
} for row in rows(env.get("CYBERDECK_JSON_ETH", ""))]

sdr = [{
    "name": field(row, 0, "unknown"),
    "kind": field(row, 1, "unknown"),
    "usb_id": field(row, 2, ""),
    "detail": field(row, 3, ""),
} for row in rows(env.get("CYBERDECK_JSON_SDR", ""))]

disks = [{
    "device": field(row, 0, "unknown"),
    "size": field(row, 1, "unknown"),
    "model": field(row, 2, "").strip(),
} for row in rows(env.get("CYBERDECK_JSON_DISK", ""))]

displays = [{
    "connector": field(row, 0, "unknown"),
    "modes": field(row, 1, "unknown"),
    "status": field(row, 2, "unknown"),
} for row in rows(env.get("CYBERDECK_JSON_DISPLAY", ""))]

thermal = {}
for row in rows(env.get("CYBERDECK_JSON_THERMAL", "")):
    try:
        thermal[field(row, 0, "zone")] = float(field(row, 1, "0"))
    except ValueError:
        continue

bluetooth_row = rows(env.get("CYBERDECK_JSON_BT", ""))
bluetooth_row = bluetooth_row[0] if bluetooth_row else ["false", "", ""]
gpio_row = rows(env.get("CYBERDECK_JSON_GPIO", ""))
gpio_row = gpio_row[0] if gpio_row else ["false", "", "0"]
i2c_row = rows(env.get("CYBERDECK_JSON_I2C", ""))
i2c_row = i2c_row[0] if i2c_row else ["false", ""]
gps_row = rows(env.get("CYBERDECK_JSON_GPS", ""))
gps_row = gps_row[0] if gps_row else ["false", ""]
battery_row = rows(env.get("CYBERDECK_JSON_BATTERY", ""))
battery_row = battery_row[0] if battery_row else ["false", "", "", ""]
usb_row = rows(env.get("CYBERDECK_JSON_USB", ""))
usb_row = usb_row[0] if usb_row else ["0", "0", "0", "0"]

try:
    with open("/etc/os-release") as handle:
        distro = next((line.split("=", 1)[1].strip().strip('"')
                       for line in handle if line.startswith("PRETTY_NAME=")), "unknown")
except OSError:
    distro = platform.platform()

inventory = {
    "board": env.get("CYBERDECK_BOARD", "unknown"),
    "arch": platform.machine(),
    "kernel": platform.release(),
    "distro": distro,
    "cpu": {
        "model": env.get("CYBERDECK_CPU", "unknown"),
        "cores": int(env.get("CYBERDECK_CORES", "1") or 1),
        "load": [round(value, 2) for value in os.getloadavg()],
    },
    "memory_total": env.get("CYBERDECK_MEMORY", "unknown"),
    "disks": disks,
    "wifi": wifi,
    "ethernet": ethernet,
    "sdr": sdr,
    "proxmark": env.get("CYBERDECK_PROXMAK", "false") == "true",
    "bluetooth": {
        "present": field(bluetooth_row, 0, "false") == "true",
        "name": field(bluetooth_row, 1, ""),
        "version": field(bluetooth_row, 2, ""),
        "hci": field(bluetooth_row, 3, ""),
    },
    "gps": {
        "present": field(gps_row, 0, "false") == "true",
        "device": field(gps_row, 1, ""),
    },
    "gpio": {
        "available": field(gpio_row, 0, "false") == "true",
        "chip": field(gpio_row, 1, ""),
        "pin_count": (field(gpio_row, 2, "0") if field(gpio_row, 2, "0").isdigit() else 0),
    },
    "i2c": {
        "present": field(i2c_row, 0, "false") == "true",
        "buses": [bus for bus in field(i2c_row, 1, "").split(",") if bus],
    },
    "displays": displays,
    "battery": {
        "present": field(battery_row, 0, "false") == "true",
        "percent": int(field(battery_row, 1, "0") or 0),
        "status": field(battery_row, 2, ""),
        "device": field(battery_row, 3, ""),
    },
    "thermal": thermal,
    "usb": {
        "total": int(field(usb_row, 0, "0") or 0),
        "hubs": int(field(usb_row, 1, "0") or 0),
        "storage": int(field(usb_row, 2, "0") or 0),
        "hid": int(field(usb_row, 3, "0") or 0),
    },
    "tools": {name: bool(shutil.which(name)) for name in (
        "aircrack-ng", "bettercap", "nmap", "hashcat", "responder", "msfconsole",
        "rtl_sdr", "gqrx", "proxmark3", "bluetoothctl", "iw", "tcpdump")},
    "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "version": "1.0.0",
}

print(json.dumps(inventory, indent=2, sort_keys=True))
PYEOF
    else
        # No python3: emit a small but valid JSON document rather than failing
        printf '{\n'
        printf '  "board": "%s",\n' "$(board_model | sed 's/"/\\\\"/g')"
        printf '  "arch": "%s",\n' "$(uname -m)"
        printf '  "kernel": "%s",\n' "$(uname -r)"
        printf '  "wifi": [],\n  "sdr": [],\n  "ethernet": [],\n  "disks": [],\n'
        printf '  "note": "python3 unavailable - install it for the full inventory",\n'
        printf '  "generated": "%s",\n' "$(date -Is)"
        printf '  "version": "1.0.0"\n}\n'
        cdeck::warn "python3 not found - emitting a reduced inventory"
    fi
}

# --------------------------------------------------------------------------- #
# Human-readable report
# --------------------------------------------------------------------------- #
emit_report() {
    local board cpu cores memory
    board="$(board_model)"
    cpu="$(cpu_model)"
    cores="$(cpu_cores)"
    memory="$(memory_total)"

    cdeck::banner "hardware inventory" "${board}"

    printf '\n%s  SYSTEM%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    printf '    %-14s %s\n' "board" "${board}"
    printf '    %-14s %s\n' "architecture" "$(uname -m) ($(getconf LONG_BIT 2>/dev/null || echo '?')-bit)"
    printf '    %-14s %s\n' "kernel" "$(uname -sr)"
    printf '    %-14s %s\n' "cpu" "${cpu} (${cores} cores)"
    printf '    %-14s %s\n' "memory" "${memory}"
    local disk
    while IFS='|' read -r name size model; do
        [[ -z "${name}" ]] && continue
        printf '    %-14s %s %s %s\n' "disk" "/dev/${name}" "${size}" "${model}"
    done < <(disks_json)

    printf '\n%s  WIFI ADAPTERS%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    local count=0 monitor_count=0
    while IFS='|' read -r iface driver chipset monitor bands mac vendor; do
        [[ -z "${iface}" ]] && continue
        count=$(( count + 1 ))
        local flag="${C_DIM}no${C_RESET}"
        if [[ "${monitor}" == "true" ]]; then
            flag="${C_GREEN}yes${C_RESET}"
            monitor_count=$(( monitor_count + 1 ))
        fi
        printf '    %s%-12s%s %s\n' "${C_BOLD}" "${iface}" "${C_RESET}" "${chipset}"
        printf '      driver %-14s bands %-16s monitor %s\n' "${driver}" "${bands}" "${flag}"
        printf '      mac    %-14s vendor %s\n' "${mac}" "${vendor}"
    done < <(wifi_json)
    (( count )) || printf '    %snone detected%s - WiFi features will skip gracefully\n' "${C_YELLOW}" "${C_RESET}"
    if (( count )) && (( monitor_count == 0 )); then
        printf '    %s! no monitor-capable adapter: injection/attack modules are limited%s\n' \
            "${C_YELLOW}" "${C_RESET}"
        printf '      recommended: Alfa AWUS036ACH, AWUS036NHA, TP-Link TL-WN722N (v1)\n'
    fi

    printf '\n%s  ETHERNET / OTHER INTERFACES%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    while IFS='|' read -r iface driver mac speed; do
        [[ -z "${iface}" ]] && continue
        printf '    %-12s %-14s %-18s %s Mb/s\n' "${iface}" "${driver}" "${mac}" "${speed}"
    done < <(ethernet_json)

    printf '\n%s  RADIO / SDR%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    local sdr_found=0
    while IFS='|' read -r name kind usb_id detail; do
        [[ -z "${name}" ]] && continue
        sdr_found=1
        printf '    %s%-20s%s %-12s %s\n' "${C_BOLD}" "${name}" "${C_RESET}" "${kind}" "${detail}"
    done < <(sdr_json)
    (( sdr_found )) || printf '    %snone detected%s - SDR modules will skip gracefully\n' "${C_DIM}" "${C_RESET}"
    if cdeck::has_cmd proxmark3 || [[ "${sdr_found}" == "1" ]] && lsusb 2>/dev/null | grep -qi proxmark; then
        printf '    %sProxmark3 client present%s\n' "${C_GREEN}" "${C_RESET}"
    fi

    printf '\n%s  BLUETOOTH%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    IFS='|' read -r present name version hci <<< "$(bluetooth_json)"
    if [[ "${present}" == "true" ]]; then
        printf '    %sadapter present%s (%s%s)\n' "${C_GREEN}" "${C_RESET}" "${hci}" \
            "${version:+ · ${version}}"
    else
        printf '    %snone detected%s - BLE scanning will skip gracefully\n' "${C_DIM}" "${C_RESET}"
    fi

    printf '\n%s  GPIO / I2C / GPS%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    IFS='|' read -r gpio_present gpio_chip gpio_pins <<< "$(gpio_json)"
    if [[ "${gpio_present}" == "true" ]]; then
        printf '    gpio   %s%s%s (%s lines)\n' "${C_GREEN}" "${gpio_chip}" "${C_RESET}" "${gpio_pins}"
    else
        printf '    gpio   %snot available%s (needs /dev/gpiochip*)\n' "${C_DIM}" "${C_RESET}"
    fi
    IFS='|' read -r i2c_present i2c_buses <<< "$(i2c_json)"
    if [[ "${i2c_present}" == "true" ]]; then
        printf '    i2c    %sbuses %s%s\n' "${C_GREEN}" "${i2c_buses}" "${C_RESET}"
    else
        printf '    i2c    %snot available%s\n' "${C_DIM}" "${C_RESET}"
    fi
    IFS='|' read -r gps_present gps_device <<< "$(gps_json)"
    if [[ "${gps_present}" == "true" ]]; then
        printf '    gps    %s%s%s\n' "${C_GREEN}" "${gps_device}" "${C_RESET}"
    else
        printf '    gps    %snot detected%s\n' "${C_DIM}" "${C_RESET}"
    fi

    printf '\n%s  POWER / THERMAL%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    IFS='|' read -r battery_present battery_percent battery_status battery_device <<< "$(battery_json)"
    if [[ "${battery_present}" == "true" ]]; then
        printf '    battery %s%s%%%s (%s) %s\n' "${C_GREEN}" "${battery_percent}" "${C_RESET}" \
            "${battery_status}" "${battery_device}"
    else
        printf '    battery %snot present%s (mains powered)\n' "${C_DIM}" "${C_RESET}"
    fi
    local thermal_found=0
    while IFS='|' read -r zone temp; do
        [[ -z "${zone}" ]] && continue
        thermal_found=1
        printf '    thermal %-18s %s°C\n' "${zone}" "${temp}"
    done < <(thermal_json)
    (( thermal_found )) || printf '    thermal %sno thermal zones exposed%s\n' "${C_DIM}" "${C_RESET}"

    printf '\n%s  USB%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    IFS='|' read -r usb_total usb_hubs usb_storage usb_hid <<< "$(usb_summary)"
    printf '    %s device(s) · %s hub(s) · %s storage · %s HID\n' \
        "${usb_total}" "${usb_hubs}" "${usb_storage}" "${usb_hid}"

    printf '\n%s  CAPABILITY SUMMARY%s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    local capability
    for capability in "wifi:WiFi recon" "sdr:SDR/RF" "gpio:GPIO buttons+LEDs" \
                      "bluetooth:BLE scanning" "gps:GPS tagging" "battery:battery monitoring"; do
        local key="${capability%%:*}" label="${capability#*:}"
        if component_present "${key}"; then
            printf '    %s✔%s %-24s available\n' "${C_GREEN}" "${C_RESET}" "${label}"
        else
            printf '    %s·%s %-24s not present (modules skip gracefully)\n' "${C_DIM}" "${C_RESET}" "${label}"
        fi
    done
    printf '\n'
}

# --------------------------------------------------------------------------- #
# Component checks
# --------------------------------------------------------------------------- #
component_present() {
    case "$1" in
        wifi)      [[ -n "$(wifi_json)" ]] ;;
        ethernet)  [[ -n "$(ethernet_json)" ]] ;;
        sdr)       [[ -n "$(sdr_json)" ]] ;;
        proxmark)  cdeck::has_cmd proxmark3 || lsusb 2>/dev/null | grep -qi proxmark ;;
        gpio)      [[ -n "$(ls /dev/gpiochip* 2>/dev/null)" ]] ;;
        i2c)       [[ -n "$(ls /dev/i2c-* 2>/dev/null)" ]] ;;
        gps)       [[ "$(gps_json | cut -d'|' -f1)" == "true" ]] ;;
        bluetooth) [[ "$(bluetooth_json | cut -d'|' -f1)" == "true" ]] ;;
        battery)   [[ "$(battery_json | cut -d'|' -f1)" == "true" ]] ;;
        display)   [[ -n "$(displays_json)" ]] ;;
        monitor)   wifi_json | awk -F'|' '$4 == "true" {found = 1} END {exit !found}' ;;
        *)         return 4 ;;
    esac
}

run_checks() {
    local missing=() component unknown=()
    local IFS=','
    for component in ${CHECKS}; do
        [[ -z "${component}" ]] && continue
        case "$(component_present "${component}"; echo $?)" in
            0) cdeck::ok "${component}: present" ;;
            3|1) missing+=("${component}") ;;
            4) unknown+=("${component}") ;;
            *) missing+=("${component}") ;;
        esac
    done
    local entry
    for entry in "${missing[@]:-}"; do
        [[ -z "${entry}" ]] && continue
        cdeck::warn "${entry}: NOT present"
    done
    if (( ${#unknown[@]} )); then
        cdeck::error "unknown component(s): ${unknown[*]}"
        cdeck::info "valid components: wifi ethernet sdr proxmark gpio i2c gps bluetooth battery display monitor"
        return 2
    fi
    if (( ${#missing[@]} )); then
        return 3
    fi
    return 0
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
# `--check` alone should not print a full report: it is used by scripts.
if (( EXPLICIT_MODE == 0 )) && [[ -n "${CHECKS}" ]] && (( VERBOSE == 0 )); then
    :
else
case "${MODE}" in
    json)   emit_json ;;
    write)
        mkdir -p "$(dirname "${WRITE_FILE}")"
        emit_json > "${WRITE_FILE}.tmp"
        if python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${WRITE_FILE}.tmp" 2>/dev/null; then
            mv "${WRITE_FILE}.tmp" "${WRITE_FILE}"
            cdeck::ok "hardware inventory written to ${WRITE_FILE}"
        else
            mv "${WRITE_FILE}.tmp" "${WRITE_FILE}"
            cdeck::warn "inventory written to ${WRITE_FILE} but it did not validate as JSON"
        fi
        if (( VERBOSE )); then
            emit_report
        fi
        ;;
    report) emit_report ;;
esac
fi

if [[ -n "${CHECKS}" ]]; then
    if (( QUIET )); then
        run_checks >/dev/null 2>&1
    else
        run_checks
    fi
    exit $?
fi

exit 0
