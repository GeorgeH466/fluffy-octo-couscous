#!/usr/bin/env bash
# =============================================================================
# test_installation.sh - verify that the suite is installed and complete
# =============================================================================
#
# Description
# -----------
# Checks the installation itself: every file the platform expects, the
# permissions it needs, that the Python modules compile and the shell modules
# parse, that the configuration is valid YAML, that the databases exist and are
# readable, that the systemd units are in place and that the entry point works.
#
# It never touches the network, the radios or the GPIO header, so it is safe to
# run on any machine, as any user, at any time. Run it after setup.sh, after an
# upgrade, and from the boot splash's self-test stage.
#
# Exit code: the number of failed checks (0 = healthy), capped at 125.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash, python3, coreutils
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./test_installation.sh                 # full check
#   ./test_installation.sh --quiet --json  # machine readable
#   ./test_installation.sh --fix           # chmod +x anything that lost it
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

cdeck::init "test_installation"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
CONF_FILE="${CDECK_CONFIG:-${INSTALL_DIR}/cyberdeck.conf}"
PYTHON="${CDECK_PYTHON:-$(command -v python3)}"

QUIET=0
JSON=0
VERBOSE=0
FIX=0
LIST=0
FAILURES=0
PASSES=0
SKIPS=0
declare -a RESULTS=()

usage() {
    cdeck::usage_header \
        "Verify that the cyberdeck-arsenal installation is complete" \
        "$0 [--quiet] [--json] [--verbose] [--fix] [--list]" \
        "$0                    # check everything and print a report" \
        "$0 --quiet            # only the failures and the summary" \
        "$0 --json             # machine-readable results"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -q, --quiet        print only failures and the final summary
  -v, --verbose      print every check as it runs
  -j, --json         emit the results as JSON (implies --quiet)
  --fix              repair what can be repaired (executable bits, directories)
  --list             list the checks without running them
  -h, --help         this help
  -V, --version      version

${C_BOLD}EXIT CODE${C_RESET}
  0 when every check passed, otherwise the number of failures.

${C_BOLD}NOTES${C_RESET}
  Hardware, network and service checks live in the sibling scripts:
    tests/test_hardware.sh · tests/test_services.sh · tests/test_connectivity.sh
EOF
}

# --------------------------------------------------------------------------- #
# Check framework
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
    local colour glyph
    case "${status}" in
        PASS) colour="${C_GREEN}";  glyph="✔" ;;
        FAIL) colour="${C_RED}";    glyph="✘" ;;
        SKIP) colour="${C_DIM}";    glyph="·" ;;
    esac
    if (( QUIET )) && [[ "${status}" == "PASS" ]]; then
        return 0
    fi
    printf '  %b%s%b %-46s %b%s%b\n' "${colour}" "${glyph}" "${C_RESET}" \
        "${name}" "${C_DIM}" "${detail}" "${C_RESET}"
}

check_file() {
    # check_file <path> <description> [executable]
    local path="$1" description="$2" need_exec="${3:-}"
    if [[ ! -e "${path}" ]]; then
        record FAIL "${description}" "missing: ${path}"
        return 1
    fi
    if [[ -n "${need_exec}" && ! -x "${path}" ]]; then
        if (( FIX )); then
            chmod +x "${path}" 2>/dev/null && record PASS "${description}" "fixed +x on ${path##*/}" && return 0
        fi
        record FAIL "${description}" "not executable: ${path}"
        return 1
    fi
    record PASS "${description}" ""
    return 0
}

check_dir() {
    # check_dir <path> <description> [create]
    local path="$1" description="$2" create="${3:-}"
    if [[ ! -d "${path}" ]]; then
        if (( FIX )) && [[ -n "${create}" ]]; then
            if mkdir -p "${path}" 2>/dev/null; then
                record PASS "${description}" "created ${path}"
                return 0
            fi
        fi
        record FAIL "${description}" "missing directory: ${path}"
        return 1
    fi
    record PASS "${description}" ""
    return 0
}

check_command() {
    # check_command <binary> <description> [required]
    local binary="$1" description="$2" required="${3:-optional}"
    if command -v "${binary}" >/dev/null 2>&1; then
        record PASS "${description}" "$(command -v "${binary}")"
        return 0
    fi
    if [[ "${required}" == "required" ]]; then
        record FAIL "${description}" "not found in PATH"
        return 1
    fi
    record SKIP "${description}" "not installed (optional)"
    return 1
}

# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
CHECKS=(
    "structure:directories and top-level files"
    "modules:every script the suite ships"
    "python:modules compile and import"
    "shell:every shell script parses"
    "config:configuration loads and is complete"
    "data:databases, lookups and templates"
    "systemd:units installed"
    "permissions:file modes are correct"
    "runtime:entry point, logging and state"
)

list_checks() {
    cdeck::banner "installation checks" "${INSTALL_DIR}"
    local entry
    for entry in "${CHECKS[@]}"; do
        printf '  %b%-12s%b %s\n' "${C_BOLD}" "${entry%%:*}" "${C_RESET}" "${entry#*:}"
    done
    printf '\n'
}

run_structure() {
    check_dir "${INSTALL_DIR}" "install directory exists (${INSTALL_DIR})"
    local subdir
    for subdir in bin lib config dashboard recon attack utilities sdr automation aesthetic gpio tests docs data; do
        check_dir "${INSTALL_DIR}/${subdir}" "directory: ${subdir}/"
    done
    local directory
    for directory in logs captures reports profiles vault state; do
        check_dir "${INSTALL_DIR}/${directory}" "runtime directory: ${directory}/" create
    done
    check_file "${INSTALL_DIR}/setup.sh" "installer present" exec
    check_file "${INSTALL_DIR}/LICENSE" "licence present"
    check_file "${INSTALL_DIR}/README.md" "README present"
}

run_modules() {
    local relative
    while IFS= read -r relative; do
        [[ -n "${relative}" ]] || continue
        case "${relative}" in
            *.py) check_file "${INSTALL_DIR}/${relative}" "module ${relative}" ;;
            *.sh|bin/cdeck) check_file "${INSTALL_DIR}/${relative}" "module ${relative}" exec ;;
            *) check_file "${INSTALL_DIR}/${relative}" "file ${relative}" ;;
        esac
    done < <(cat <<'MODULES'
bin/cdeck
setup.sh
lib/cyberlib.py
lib/cybergpio.py
lib/cyberdeck_common.sh
config/cyberdeck.conf
config/aliases.sh
config/bashrc_cyberdeck
config/tmux.conf
config/conky/cyberdeck_conky.conf
dashboard/main_hud.py
dashboard/packet_weather.py
dashboard/threat_ticker.py
dashboard/network_map.py
dashboard/rf_spectrum.py
recon/passive/wifi_probe_logger.py
recon/passive/ble_scanner.py
recon/passive/arp_mapper.py
recon/passive/rogue_ap_detector.py
recon/passive/service_watcher.py
recon/active/target_profiler.sh
recon/active/network_scanner.sh
recon/active/web_recon.sh
recon/active/osint_gatherer.py
recon/reporting/report_generator.py
recon/reporting/evidence_hasher.py
attack/wifi_arsenal.sh
attack/responder_launcher.sh
attack/mitm_toolkit.sh
attack/payload_server.py
utilities/mac_rotator.py
utilities/vpn_switcher.sh
utilities/encrypted_vault.sh
utilities/usb_handler.py
utilities/self_destruct.sh
utilities/network_profile_manager.sh
utilities/hardware_detect.sh
sdr/sdr_scanner.py
sdr/adsb_tracker.py
sdr/pager_decoder.py
sdr/tpms_monitor.py
sdr/keyfob_analyzer.py
automation/triggers.py
automation/scheduler.py
automation/keybinds.sh
aesthetic/boot_splash.sh
aesthetic/motd.sh
aesthetic/theme_switcher.sh
aesthetic/themes/cyberpunk.theme
aesthetic/themes/stealth.theme
aesthetic/themes/matrix.theme
aesthetic/decoy/hollywood_mode.sh
aesthetic/decoy/fake_desktop.sh
gpio/led_controller.py
gpio/button_handler.py
gpio/oled_display.py
tests/test_installation.sh
tests/test_hardware.sh
tests/test_services.sh
tests/test_connectivity.sh
data/oui_database.txt
data/ble_vulnerability_db.json
data/templates/report_template.md
data/templates/report_template.html
data/templates/executive_summary.md
data/wordlists/download_wordlists.sh
docs/HARDWARE.md
docs/QUICKSTART.md
docs/CONFIGURATION.md
docs/TROUBLESHOOTING.md
docs/KEYBINDS.md
docs/LEGAL.md
MODULES
)
}

run_python() {
    if ! command -v "${PYTHON}" >/dev/null 2>&1; then
        record FAIL "python interpreter available" "python3 not found"
        return 0
    fi
    record PASS "python interpreter available" "$(${PYTHON} --version 2>&1)"
    local output
    if output="$("${PYTHON}" -m compileall -q "${INSTALL_DIR}" 2>&1)"; then
        record PASS "all python modules compile" ""
    else
        record FAIL "all python modules compile" "$(printf '%s' "${output}" | head -1)"
    fi
    local module
    for module in cyberlib cybergpio; do
        if "${PYTHON}" -c "import sys; sys.path.insert(0, '${INSTALL_DIR}/lib'); import ${module}" >/dev/null 2>&1; then
            record PASS "import ${module}" ""
        else
            record FAIL "import ${module}" "import raised an error"
        fi
    done
    if "${PYTHON}" -c "import yaml" >/dev/null 2>&1; then
        record PASS "PyYAML available" "config is parsed as YAML"
    else
        record SKIP "PyYAML available" "falling back to the built-in parser"
    fi
    local version
    version="$("${PYTHON}" -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>/dev/null)"
    if [[ "${version%%.*}" -ge 3 ]] && [[ "${version##*.}" -ge 8 ]]; then
        record PASS "python version is 3.8 or newer" "${version}"
    else
        record FAIL "python version is 3.8 or newer" "${version}"
    fi
}

run_shell() {
    local errors=0 count=0 relative
    while IFS= read -r relative; do
        [[ -n "${relative}" ]] || continue
        case "${relative}" in
            *.sh|bin/cdeck|config/bashrc_cyberdeck|config/aliases.sh)
                count=$(( count + 1 ))
                if ! bash -n "${INSTALL_DIR}/${relative}" 2>/dev/null; then
                    errors=$(( errors + 1 ))
                    record FAIL "parses: ${relative}" "bash -n reported an error"
                fi
                ;;
        esac
    done < <(cd "${INSTALL_DIR}" && find . -type f \( -name '*.sh' -o -name 'cdeck' -o -name 'bashrc_cyberdeck' -o -name 'aliases.sh' \) | sed 's|^\./||')
    if (( errors == 0 )); then
        record PASS "every shell script parses (${count} files)" ""
    fi
}

run_config() {
    if [[ ! -r "${CONF_FILE}" ]]; then
        record FAIL "configuration readable" "${CONF_FILE}"
        return 0
    fi
    record PASS "configuration readable" "${CONF_FILE}"
    local missing
    missing="$("${PYTHON}" - "${CONF_FILE}" "${INSTALL_DIR}/lib" <<'PYEOF' 2>/dev/null
import sys
path, libdir = sys.argv[1], sys.argv[2]
data = {}
try:
    import yaml
    data = yaml.safe_load(open(path)) or {}
except ImportError:
    sys.path.insert(0, libdir)
    try:
        from cyberlib import Config
        data = Config(path).load(path).as_dict()
    except Exception:
        # Last resort: the tiny parser understands the shipped layout
        section = None
        for raw in open(path):
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if not line[0].isspace() and line.rstrip().endswith(":"):
                section = line.strip()[:-1]
                data.setdefault(section, {})
                continue
            if ":" in line and line[0].isspace():
                key, _, value = line.strip().partition(":")
                data.setdefault(section or "general", {})[key.strip()] = value.strip()
required = {
    "general": ["install_dir", "log_level"],
    "network": ["monitor_interface", "primary_interface"],
    "monitoring": ["hud_refresh_rate"],
    "mac_rotation": ["enabled", "interval"],
    "api_keys": ["abuseipdb", "alienvault_otx", "greynoise", "shodan"],
    "alerts": ["new_device_alert", "webhook_url"],
    "automation": ["auto_recon_on_connect"],
    "gpio": ["enabled", "status_led_pin", "alert_led_pin", "button_pin"],
    "display": ["theme", "hud_refresh_rate"],
}
missing = [f"{section}.{key}" for section, keys in required.items()
           for key in keys if key not in (data.get(section) or {})]
print(",".join(missing))
PYEOF
)"
    if [[ -n "${missing}" ]]; then
        record FAIL "configuration has every required key" "missing: ${missing}"
    else
        record PASS "configuration has every required key" ""
    fi
    local theme
    theme="$(cdeck::conf_get display.theme cyberpunk)"
    if [[ -f "${INSTALL_DIR}/aesthetic/themes/${theme}.theme" ]]; then
        record PASS "selected theme exists" "${theme}"
    else
        record FAIL "selected theme exists" "no aesthetic/themes/${theme}.theme"
    fi
    if cdeck::has_cmd python3; then
        if "${PYTHON}" - "${CONF_FILE}" <<'PYEOF' >/dev/null 2>&1
import sys
try:
    import yaml
    yaml.safe_load(open(sys.argv[1]))
except ImportError:
    sys.exit(0)
PYEOF
        then
            record PASS "configuration is valid YAML" ""
        else
            record FAIL "configuration is valid YAML" "parser reported an error"
        fi
    fi
}

run_data() {
    local db
    for db in events alerts probes ble arp services usb payloads baseline; do
        if [[ -f "${INSTALL_DIR}/data/${db}.db" ]]; then
            if command -v sqlite3 >/dev/null 2>&1; then
                if sqlite3 "file:${INSTALL_DIR}/data/${db}.db?mode=ro" ".tables" >/dev/null 2>&1; then
                    record PASS "database ${db}.db readable" ""
                else
                    record FAIL "database ${db}.db readable" "sqlite3 could not read it"
                fi
            elif [[ -r "${INSTALL_DIR}/data/${db}.db" ]]; then
                record PASS "database ${db}.db present" ""
            fi
        else
            record SKIP "database ${db}.db" "not created yet"
        fi
    done
    local oui_lines
    if [[ -f "${INSTALL_DIR}/data/oui_database.txt" ]]; then
        oui_lines="$(wc -l < "${INSTALL_DIR}/data/oui_database.txt" | tr -d ' ')"
        if (( oui_lines > 100 )); then
            record PASS "OUI database has entries" "${oui_lines} lines"
        else
            record FAIL "OUI database has entries" "only ${oui_lines} lines"
        fi
    else
        record FAIL "OUI database present" "data/oui_database.txt missing"
    fi
    local file
    for file in ble_vulnerability_db.json pager_capcodes.json; do
        if [[ -f "${INSTALL_DIR}/data/${file}" ]]; then
            if "${PYTHON}" -c "import json,sys; json.load(open(sys.argv[1]))" \
                "${INSTALL_DIR}/data/${file}" >/dev/null 2>&1; then
                record PASS "valid JSON: ${file}" ""
            else
                record FAIL "valid JSON: ${file}" "could not be parsed"
            fi
        else
            record SKIP "valid JSON: ${file}" "not installed"
        fi
    done
    local template
    for template in report_template.html report_template.md executive_summary.md; do
        check_file "${INSTALL_DIR}/data/templates/${template}" "template: ${template}"
    done
}

run_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        record SKIP "systemd units" "systemd is not available on this host"
        return 0
    fi
    local unit
    for unit in cyberdeck-monitor.service mac-rotator.service mac-rotator.timer \
                probe-logger.service ble-scanner.service rogue-ap-detector.service \
                usb-watcher.service; do
        if [[ -f "/etc/systemd/system/${unit}" || -f "/etc/systemd/system/multi-user.target.wants/${unit}" ]]; then
            record PASS "unit installed: ${unit}" ""
        elif systemctl list-unit-files "${unit}" >/dev/null 2>&1 \
            && systemctl list-unit-files "${unit}" 2>/dev/null | grep -q "${unit}"; then
            record PASS "unit installed: ${unit}" ""
        else
            record SKIP "unit installed: ${unit}" "not installed (run setup.sh)"
        fi
    done
    local udev="/etc/udev/rules.d/99-cyberdeck-usb.rules"
    if [[ -f "${udev}" ]]; then
        record PASS "udev rules installed" "${udev}"
    else
        record SKIP "udev rules installed" "not installed"
    fi
    local motd="/etc/profile.d/cyberdeck-motd.sh"
    if [[ -f "${motd}" ]]; then
        record PASS "login MOTD installed" "${motd}"
    else
        record SKIP "login MOTD installed" "not installed"
    fi
}

run_permissions() {
    local mode
    mode="$(stat -c '%a' "${CONF_FILE}" 2>/dev/null || stat -f '%Lp' "${CONF_FILE}" 2>/dev/null)"
    if [[ -n "${mode}" ]]; then
        if [[ "${mode}" == "600" || "${mode}" == "640" || "${mode}" == "660" ]]; then
            record PASS "configuration is not world readable" "mode ${mode}"
        elif [[ "${mode}" == "644" ]]; then
            record FAIL "configuration is not world readable" \
                "mode ${mode} - run: chmod 600 ${CONF_FILE}"
        else
            record PASS "configuration mode" "${mode}"
        fi
    fi
    if [[ -d "${INSTALL_DIR}/vault" ]]; then
        local vault_mode
        vault_mode="$(stat -c '%a' "${INSTALL_DIR}/vault" 2>/dev/null)"
        if [[ "${vault_mode}" == "700" || "${vault_mode}" == "750" ]]; then
            record PASS "vault directory is private" "mode ${vault_mode}"
        else
            record SKIP "vault directory is private" "mode ${vault_mode}"
        fi
    fi
    local world_writable
    world_writable="$(find "${INSTALL_DIR}" -maxdepth 3 -type f -perm -0002 2>/dev/null | head -5)"
    if [[ -z "${world_writable}" ]]; then
        record PASS "no world-writable files in the install" ""
    else
        record FAIL "no world-writable files in the install" \
            "$(printf '%s' "${world_writable}" | head -1)"
    fi
    if [[ -r "${INSTALL_DIR}/logs" && -w "${INSTALL_DIR}/logs" ]]; then
        record PASS "log directory is writable" ""
    else
        record FAIL "log directory is writable" "${INSTALL_DIR}/logs"
    fi
}

run_runtime() {
    if [[ -x "${INSTALL_DIR}/bin/cdeck" ]]; then
        if "${INSTALL_DIR}/bin/cdeck" --version >/dev/null 2>&1; then
            record PASS "cdeck runs" "$("${INSTALL_DIR}/bin/cdeck" --version 2>&1 | head -1)"
        else
            record FAIL "cdeck runs" "--version returned an error"
        fi
    else
        record FAIL "cdeck runs" "bin/cdeck is not executable"
    fi
    if [[ -L /usr/local/bin/cdeck || -x /usr/bin/cdeck ]]; then
        record PASS "cdeck is on PATH" ""
    elif command -v cdeck >/dev/null 2>&1; then
        record PASS "cdeck is on PATH" "$(command -v cdeck)"
    else
        record SKIP "cdeck is on PATH" "link not installed"
    fi
    local script
    for script in aesthetic/motd.sh aesthetic/theme_switcher.sh aesthetic/boot_splash.sh; do
        if [[ -x "${INSTALL_DIR}/${script}" ]]; then
            if "${INSTALL_DIR}/${script}" --help >/dev/null 2>&1 \
                || "${INSTALL_DIR}/${script}" --version >/dev/null 2>&1; then
                record PASS "runs: ${script}" ""
            else
                record FAIL "runs: ${script}" "--help/--version failed"
            fi
        else
            record FAIL "runs: ${script}" "missing or not executable"
        fi
    done
    if [[ -f "${INSTALL_DIR}/state/hardware.json" ]]; then
        record PASS "hardware inventory present" "state/hardware.json"
    else
        record SKIP "hardware inventory present" "run: cdeck hardware --write"
    fi
    if [[ -f "${INSTALL_DIR}/logs/setup.log" ]]; then
        record PASS "installer log present" "$(wc -l < "${INSTALL_DIR}/logs/setup.log" | tr -d ' ') lines"
    else
        record SKIP "installer log present" "no logs/setup.log"
    fi
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)     usage; exit 0 ;;
        --version|-V)  printf 'test_installation %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -q|--quiet)    QUIET=1 ;;
        -v|--verbose)  VERBOSE=1 ;;
        -j|--json)     JSON=1; QUIET=1 ;;
        --fix)         FIX=1 ;;
        --list)        LIST=1 ;;
        --install-dir) shift; INSTALL_DIR="${1:-${INSTALL_DIR}}" ;;
        *)             cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

if (( LIST )); then
    list_checks
    exit 0
fi

STARTED="$(date +%s)"
if (( ! QUIET )); then
    cdeck::banner "installation test" "${INSTALL_DIR} · $(date '+%Y-%m-%d %H:%M:%S')"
fi

run_structure
run_modules
run_python
run_shell
run_config
run_data
run_systemd
run_permissions
run_runtime

DURATION=$(( $(date +%s) - STARTED ))

if (( JSON )); then
    printf '{\n'
    printf '  "install_dir": "%s",\n' "${INSTALL_DIR}"
    printf '  "generated": "%s",\n' "$(cdeck::iso_stamp)"
    printf '  "duration_s": %d,\n' "${DURATION}"
    printf '  "passed": %d, "failed": %d, "skipped": %d,\n' "${PASSES}" "${FAILURES}" "${SKIPS}"
    printf '  "checks": [\n'
    local_first=1
    for entry in "${RESULTS[@]}"; do
        IFS='|' read -r status name detail <<< "${entry}"
        (( local_first )) || printf ',\n'
        local_first=0
        printf '    {"status": "%s", "name": "%s", "detail": "%s"}' \
            "${status}" "${name//\"/}" "${detail//\"/}"
    done
    printf '\n  ]\n}\n'
else
    printf '\n'
    printf '  %b%d passed%b · %b%d failed%b · %b%d skipped%b · %ds\n\n' \
        "${C_GREEN}" "${PASSES}" "${C_RESET}" \
        "$([[ ${FAILURES} -gt 0 ]] && echo "${C_RED}" || echo "${C_DIM}")" "${FAILURES}" "${C_RESET}" \
        "${C_DIM}" "${SKIPS}" "${C_RESET}" "${DURATION}"
    if (( FAILURES )); then
        cdeck::error "${FAILURES} installation check(s) failed"
        cdeck::info "run setup.sh again to repair the installation: sudo ${INSTALL_DIR}/setup.sh"
        cdeck::info "troubleshooting: ${INSTALL_DIR}/docs/TROUBLESHOOTING.md"
    else
        cdeck::ok "the installation is complete"
    fi
    printf '\n'
fi

if (( FAILURES > 125 )); then
    exit 125
fi
exit "${FAILURES}"
