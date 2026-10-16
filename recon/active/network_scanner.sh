#!/usr/bin/env bash
# =============================================================================
# network_scanner.sh - network scanning presets for cyberdeck-arsenal
# =============================================================================
#
# Description
# -----------
# Runs nmap with sensible, documented presets so an operator never has to
# remember flag combinations in the field. Every preset writes normal, XML and
# grepable output into a timestamped engagement directory and prints a readable
# summary of the results.
#
# Presets
#   stealth     -sS -T2 --top-ports 1000        quiet SYN scan, slow timing
#   aggressive  -sS -sV -O -T4 -A               loud, maximum information
#   vuln        -sV --script vuln,vulners       vulnerability detection scripts
#   udp         -sU --top-ports 200 -T4         UDP services
#   full        -p- -sS -sV -T4 -A              all 65535 TCP ports
#   discovery   -sn                              host discovery only (ping sweep)
#   custom      <your own nmap arguments>
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: nmap, cyberdeck_common.sh (bash library)
# Licence     : MIT - authorised use only, see docs/LEGAL.md
#
# Usage
# -----
#   sudo ./network_scanner.sh stealth 192.168.1.0/24
#   sudo ./network_scanner.sh full 10.0.0.5
#   sudo ./network_scanner.sh custom 192.168.1.0/24 -p 80,443 --script http-title
#   ./network_scanner.sh --help
# =============================================================================

# shellcheck source=../../lib/cyberdeck_common.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../../lib/cyberdeck_common.sh" ]]; then
    source "${SCRIPT_DIR}/../../lib/cyberdeck_common.sh"
elif [[ -f /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh ]]; then
    source /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh
else
    echo "fatal: cyberdeck_common.sh not found" >&2
    exit 1
fi

cdeck::init "network_scanner"

PRESET=""
TARGET=""
OUTPUT_DIR=""
EXTRA_ARGS=()
QUICK_DISCOVERY=0

# --------------------------------------------------------------------------- #
# Help
# --------------------------------------------------------------------------- #
usage() {
    cdeck::usage_header \
        "Network scanning presets (nmap wrapper)" \
        "$0 <preset> <target> [extra nmap args...]" \
        "sudo $0 stealth 192.168.1.0/24" \
        "sudo $0 aggressive 10.0.0.5" \
        "sudo $0 vuln example.com" \
        "sudo $0 discovery 192.168.1.0/24" \
        "sudo $0 custom 192.168.1.5 -p 1-1024 --script banner"
    cat <<EOF

${C_BOLD}PRESETS${C_RESET}
  stealth     SYN scan, top 1000 ports, -T2 (slow, less likely to trip IDS)
  aggressive  SYN + version + OS detection, -A -T4 (loud but thorough)
  vuln        Version detection plus the 'vuln' and 'vulners' NSE scripts
  udp         UDP top 200 ports (needs root, slow)
  full        All 65535 TCP ports with version and OS detection
  discovery   Ping sweep only - find live hosts without port scanning
  custom      Pass your own nmap arguments after the target

${C_BOLD}OPTIONS${C_RESET}
  -o, --output DIR   write results into DIR (default: an engagement directory)
  -q, --quiet        do not print the summary table
  -y, --yes          skip the confirmation prompt (implies authorisation)
      --timing T     override the nmap timing template (T0-T5)

${C_YELLOW}⚠  Only scan networks you own or are authorised to test.${C_RESET}
EOF
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
QUIET=0
while (( $# )); do
    case "$1" in
        --help|-h)      usage; exit 0 ;;
        -o|--output)    shift; OUTPUT_DIR="${1:-}" ;;
        -q|--quiet)     QUIET=1 ;;
        -y|--yes)       export CDECK_ASSUME_YES=1 ;;
        --timing)       shift; CDECK_TIMING="${1:-T4}" ;;
        stealth|aggressive|vuln|udp|full|discovery|custom)
            if [[ -z "${PRESET}" ]]; then PRESET="$1"; else EXTRA_ARGS+=("$1"); fi ;;
        *)
            if [[ -z "${TARGET}" && "${PRESET}" != "custom" ]]; then TARGET="$1"
            else EXTRA_ARGS+=("$1"); fi ;;
    esac
    shift
done

if [[ -z "${PRESET}" ]]; then
    cdeck::error "no preset given"
    usage
    exit 2
fi
if [[ "${PRESET}" == "custom" ]]; then
    # For custom, the first remaining positional was consumed as TARGET; rebuild
    if [[ -n "${TARGET}" ]]; then EXTRA_ARGS=("${TARGET}" "${EXTRA_ARGS[@]:-}"); fi
    TARGET="${EXTRA_ARGS[0]:-}"
    EXTRA_ARGS=("${EXTRA_ARGS[@]:1}")
    if [[ -z "${TARGET}" ]]; then
        cdeck::error "custom preset needs a target"
        usage
        exit 2
    fi
elif [[ -z "${TARGET}" ]]; then
    cdeck::error "no target given"
    usage
    exit 2
fi

# --------------------------------------------------------------------------- #
# Pre-flight
# --------------------------------------------------------------------------- #
cdeck::require_cmds nmap || exit 1

# Raw packets are needed for most presets
if [[ "${EUID}" -ne 0 ]]; then
    cdeck::warn "not running as root - falling back to TCP connect scans (-sT) where needed"
fi

# Validate the target looks like an address, hostname or CIDR
if [[ ! "${TARGET}" =~ ^[a-zA-Z0-9._:/-]+$ ]]; then
    cdeck::error "target contains unexpected characters: ${TARGET}"
    exit 2
fi

cdeck::legal_warning "network scanning of ${TARGET}"
cdeck::confirm "Confirm you are authorised to scan ${TARGET}?" y "--yes" || {
    cdeck::error "not confirmed - aborting"
    exit 1
}

# --------------------------------------------------------------------------- #
# Output directory
# --------------------------------------------------------------------------- #
if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="$(cdeck::engagement_dir "${TARGET}")"
fi
mkdir -p "${OUTPUT_DIR}/raw"
STAMP="$(date '+%Y%m%d_%H%M%S')"
BASE="${OUTPUT_DIR}/raw/nmap_${PRESET}_${STAMP}"
SUMMARY_MD="${OUTPUT_DIR}/scan_${PRESET}_${STAMP}.md"

# --------------------------------------------------------------------------- #
# Build the nmap command
# --------------------------------------------------------------------------- #
TIMING="${CDECK_TIMING:-$(cdeck::conf_get scanning.nmap_timing T4)}"
NMAP_ARGS=()

case "${PRESET}" in
    stealth)
        if [[ "${EUID}" -eq 0 ]]; then
            NMAP_ARGS=(-sS -T2 --top-ports 1000 --open -Pn)
        else
            NMAP_ARGS=(-sT -T2 --top-ports 1000 --open -Pn)
        fi
        ;;
    aggressive)
        if [[ "${EUID}" -eq 0 ]]; then
            NMAP_ARGS=(-sS -sV -O -A -T4 --version-intensity 7)
        else
            NMAP_ARGS=(-sT -sV -A -T4)
            cdeck::warn "OS detection (-O) requires root and has been omitted"
        fi
        ;;
    vuln)
        NMAP_ARGS=(-sV -Pn -T4 --script "vuln,vulners,http-vuln-*" --script-timeout 5m)
        cdeck::warn "vulnerability scripts are noisy and can crash fragile services"
        ;;
    udp)
        if [[ "${EUID}" -ne 0 ]]; then
            cdeck::die "UDP scanning requires root: sudo $0 udp ${TARGET}"
        fi
        NMAP_ARGS=(-sU --top-ports 200 -T4 --max-retries 1 --host-timeout 15m)
        ;;
    full)
        if [[ "${EUID}" -eq 0 ]]; then
            NMAP_ARGS=(-p- -sS -sV -A -T4 --min-rate 500)
        else
            NMAP_ARGS=(-p- -sT -sV -T4 --min-rate 200)
        fi
        cdeck::info "full port scan of ${TARGET} will take a while"
        ;;
    discovery)
        NMAP_ARGS=(-sn -PE -PS22,80,443 -PA80,443 -T4)
        QUICK_DISCOVERY=1
        ;;
    custom)
        NMAP_ARGS=("${EXTRA_ARGS[@]}")
        EXTRA_ARGS=()
        ;;
    *)
        cdeck::error "unknown preset: ${PRESET}"
        usage
        exit 2
        ;;
esac

# Additional operator-supplied arguments (never for custom: they are the args)
if (( ${#EXTRA_ARGS[@]} )); then
    NMAP_ARGS+=("${EXTRA_ARGS[@]}")
fi

# Use the configured timing when the preset allowed an override and none was given
if [[ -n "${CDECK_TIMING:-}" && "${PRESET}" != "custom" ]]; then
    NMAP_ARGS+=("-${CDECK_TIMING}")
fi

# Configurable extra args from cyberdeck.conf
CONF_EXTRA="$(cdeck::conf_get scanning.nmap_extra_args "")"
if [[ -n "${CONF_EXTRA}" ]]; then
    # shellcheck disable=SC2206 - intentional word splitting of configured flags
    NMAP_ARGS+=(${CONF_EXTRA})
fi

# --------------------------------------------------------------------------- #
# Run the scan
# --------------------------------------------------------------------------- #
cdeck::banner "network scan" "${PRESET} → ${TARGET}"
cdeck::info "command: nmap ${NMAP_ARGS[*]} ${TARGET}"
cdeck::info "output: ${BASE}.{nmap,xml,gnmap}"

START_EPOCH="$(date +%s)"
set +e
nmap "${NMAP_ARGS[@]}" -oN "${BASE}.nmap" -oX "${BASE}.xml" -oG "${BASE}.gnmap" "${TARGET}" \
    | tee "${BASE}.stdout"
NMAP_RC=$?
set -e
DURATION=$(( $(date +%s) - START_EPOCH ))

if (( NMAP_RC != 0 )); then
    cdeck::warn "nmap exited with code ${NMAP_RC} (partial results may still be usable)"
fi
cdeck::ok "scan finished in ${DURATION}s"
[[ -f "${BASE}.nmap" ]] || cdeck::die "no output produced - check the nmap error above"

# --------------------------------------------------------------------------- #
# Parse the grepable output into a summary
# --------------------------------------------------------------------------- #
declare -a SUMMARY_LINES=()
HOST_COUNT=0
OPEN_PORT_COUNT=0
declare -A PORT_HISTOGRAM=()

if [[ -f "${BASE}.gnmap" ]]; then
    while IFS= read -r line; do
        [[ "${line}" == "Host:"* ]] || continue
        HOST_COUNT=$(( HOST_COUNT + 1 ))
        host_ip="$(awk '{print $2}' <<< "${line}")"
        host_name="$(grep -oP 'Host: \S+ \(\K[^)]+' <<< "${line}" || true)"
        ports_field="$(sed -n 's/.*Ports: \(.*\)\tIgnored.*/\1/p' <<< "${line}")"
        [[ -z "${ports_field}" ]] && ports_field="$(sed -n 's/.*Ports: \(.*\)$/\1/p' <<< "${line}")"

        open_ports=""
        if [[ -n "${ports_field}" && "${ports_field}" != "" ]]; then
            IFS=',' read -ra port_entries <<< "${ports_field//, /,}"
            for entry in "${port_entries[@]}"; do
                state="$(awk '{print $2}' <<< "${entry}")"
                [[ "${state}" == "open" ]] || continue
                number="$(awk '{print $1}' <<< "${entry}" | cut -d/ -f1)"
                service="$(awk '{print $3}' <<< "${entry}")"
                open_ports+="${number}/${service} "
                OPEN_PORT_COUNT=$(( OPEN_PORT_COUNT + 1 ))
                PORT_HISTOGRAM["${service}"]=$(( ${PORT_HISTOGRAM["${service}"]:-0} + 1 ))
            done
        fi
        os_guess="$(sed -n 's/.*OS: \(.*\)$/\1/p' <<< "${line}" | cut -d, -f1)"
        SUMMARY_LINES+=("${host_ip}|${host_name:-}|${os_guess:-unknown}|${open_ports:-none}")
    done < "${BASE}.gnmap"
fi

# XML fallback when the grepable file is missing or empty
if (( HOST_COUNT == 0 )) && [[ -f "${BASE}.xml" ]] && cdeck::has_cmd python3; then
    while IFS=$'\t' read -r ip name ports; do
        [[ -z "${ip}" ]] && continue
        HOST_COUNT=$(( HOST_COUNT + 1 ))
        SUMMARY_LINES+=("${ip}|${name}|unknown|${ports}")
    done < <(python3 - "${BASE}.xml" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.argv[1])
except Exception:
    sys.exit(0)
for host in tree.getroot().findall("host"):
    status = host.find("status")
    if status is not None and status.get("state") != "up":
        continue
    address = host.find("address")
    ip = address.get("addr") if address is not None else "?"
    name_el = host.find("hostnames/hostname")
    name = name_el.get("name") if name_el is not None else ""
    ports = []
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            service = port.find("service")
            svc = service.get("name") if service is not None else "unknown"
            ports.append(f"{port.get('portid')}/{svc}")
    print(f"{ip}\t{name}\t{' '.join(ports)}")
PYEOF
    )
fi

# --------------------------------------------------------------------------- #
# Print the summary
# --------------------------------------------------------------------------- #
if (( QUIET == 0 )); then
    cdeck::banner "scan summary" "${PRESET} → ${TARGET} (${DURATION}s)"
    if (( HOST_COUNT == 0 )); then
        printf '  no live hosts found\n'
    else
        printf '  %-16s %-24s %s\n' "HOST" "NAME / OS" "OPEN PORTS"
        for entry in "${SUMMARY_LINES[@]}"; do
            IFS='|' read -r ip name os ports <<< "${entry}"
            printf '  %-16s %-24s %s\n' "${ip}" "${name:-${os:0:24}}" "${ports}"
        done
    fi
    printf '\n  hosts up: %d   open ports: %d\n' "${HOST_COUNT}" "${OPEN_PORT_COUNT}"
    if (( ${#PORT_HISTOGRAM[@]} )); then
        printf '  services: '
        for service in "${!PORT_HISTOGRAM[@]}"; do
            printf '%s(%d) ' "${service}" "${PORT_HISTOGRAM[${service}]}"
        done
        printf '\n'
    fi
    printf '\n'
fi

# --------------------------------------------------------------------------- #
# Markdown summary (feeds report_generator.py)
# --------------------------------------------------------------------------- #
{
    printf '# Network scan: %s\n\n' "${TARGET}"
    printf -- '- **Preset**: %s\n' "${PRESET}"
    printf -- '- **Command**: `nmap %s %s`\n' "${NMAP_ARGS[*]}" "${TARGET}"
    printf -- '- **Date**: %s\n' "$(date -Is)"
    printf -- '- **Duration**: %ss\n' "${DURATION}"
    printf -- '- **Hosts up**: %s\n' "${HOST_COUNT}"
    printf -- '- **Open ports**: %s\n\n' "${OPEN_PORT_COUNT}"
    printf '## Hosts\n\n'
    if (( HOST_COUNT == 0 )); then
        printf 'No live hosts were found.\n\n'
    else
        printf '| Host | Name | OS guess | Open ports |\n|---|---|---|---|\n'
        for entry in "${SUMMARY_LINES[@]}"; do
            IFS='|' read -r ip name os ports <<< "${entry}"
            printf '| %s | %s | %s | %s |\n' "${ip}" "${name:-}" "${os:-}" "${ports}"
        done
        printf '\n'
    fi
    printf '## Raw output\n\n'
    printf -- '- `%s.nmap` - human readable\n' "$(basename "${BASE}")"
    printf -- '- `%s.xml` - machine readable (importable by other tools)\n' "$(basename "${BASE}")"
    printf -- '- `%s.gnmap` - grepable\n' "$(basename "${BASE}")"
} > "${SUMMARY_MD}"

cdeck::ok "summary written to ${SUMMARY_MD}"

# Record in the shared event log for the dashboard feed
if [[ -f /opt/cyberdeck-arsenal/lib/cyberlib.py ]]; then
    PYTHONPATH=/opt/cyberdeck-arsenal/lib python3 - "$PRESET" "$TARGET" "$HOST_COUNT" "$OPEN_PORT_COUNT" <<'PYEOF' 2>/dev/null || true
import sys
try:
    from cyberlib import Database
    preset, target, hosts, ports = sys.argv[1:5]
    with Database("events") as db:
        db.event("network_scanner", "scan",
                 f"{preset} scan of {target}: {hosts} host(s), {ports} open port(s)",
                 "INFO", {"preset": preset, "target": target, "hosts": int(hosts),
                          "open_ports": int(ports)})
except Exception:
    pass
PYEOF
fi

exit 0
