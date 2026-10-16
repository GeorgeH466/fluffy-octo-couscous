#!/usr/bin/env bash
# =============================================================================
# test_connectivity.sh - check that the deck can reach the world, and how
# =============================================================================
#
# Description
# -----------
# Answers the questions that matter the moment you sit down at a deck: is there a
# link, is there a route, does DNS work, is the path clean, is my traffic leaving
# through the tunnel I think it is, and which of the services this platform
# depends on are actually reachable from here?
#
# Checks, in order:
#   link        interface present, carrier up, speed/duplex
#   layer 3     gateway reachable, public address reachable, latency and loss
#   dns         resolver configuration, resolution of several names, DNSSEC hint
#   http        plain HTTP and HTTPS fetches, certificate validity, captive portal
#   mtu         path MTU discovery with don't-fragment probes
#   tunnel      VPN/Tor state, leak test through the configured URL
#   services    the feeds and registries the suite talks to (Shodan, OUI, GitHub,
#               package mirrors) plus optional API key presence
#   targeting   local subnet, gateway MAC, and the ranges declared in the config
#
# Every check has a timeout, nothing is scanned, and the only traffic generated
# is ordinary DNS, ICMP, and a handful of GET requests to the hosts above.
#
# Exit code: the number of failed required checks (0 = the deck is online).
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash, coreutils, iproute2; optional: ping, dig, curl, openssl
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./test_connectivity.sh                # full connectivity report
#   ./test_connectivity.sh --json         # machine readable
#   ./test_connectivity.sh --quick        # skip the slow checks (MTU, feeds)
#   ./test_connectivity.sh --leak         # force the VPN leak test
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

cdeck::init "test_connectivity"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
TEST_HOST="$(cdeck::conf_get testing.connectivity_host 1.1.1.1)"
LEAK_URL="$(cdeck::conf_get network.leak_test_url http://ifconfig.me/ip)"
QUICK=0
JSON=0
QUIET=0
VERBOSE=0
FORCE_LEAK=0
FAILURES=0
PASSES=0
SKIPS=0
declare -a RESULTS=()

#: Hosts the suite fetches from, with the purpose shown in the report
declare -a SERVICE_HOSTS=(
    "https://api.shodan.io|Shodan API (host intelligence)"
    "https://otx.alienvault.com|AlienVault OTX (threat feeds)"
    "https://api.abuseipdb.com|AbuseIPDB (IP reputation)"
    "https://standards-oui.ieee.org|IEEE OUI registry (MAC vendors)"
    "https://github.com|GitHub (wordlists, tool updates)"
    "https://archlinux.org|Arch mirrors (package updates)"
)

usage() {
    cdeck::usage_header \
        "Check the deck's connectivity, name resolution and tunnel state" \
        "$0 [--quick] [--json] [--leak] [--quiet] [--verbose]" \
        "$0              # full connectivity report" \
        "$0 --quick      # skip the slow checks" \
        "$0 --leak       # force the VPN leak test"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -q, --quick        skip MTU discovery and the external feed probes
  -j, --json         emit JSON (implies --quiet)
  -l, --leak         always run the leak test, even with no tunnel up
  -v, --verbose      show the raw output of the probes
  --host HOST        override the connectivity test host (${TEST_HOST})
  --install-dir PATH override the install directory
  -h, --help         this help
  -V, --version      version

${C_BOLD}NOTES${C_RESET}
  Only ICMP, DNS and a few HTTPS GET requests are generated. No scanning,
  no enumeration, nothing that would look unusual on a monitored network.

${C_BOLD}EXIT CODE${C_RESET}
  Number of failed checks (0 = the deck is online and the tunnel state matches
  the configuration).
EOF
}

# --------------------------------------------------------------------------- #
# Framework
# --------------------------------------------------------------------------- #
record() {
    # record <status> <group> <name> <detail>
    local status="$1" group="$2" name="$3" detail="${4:-}"
    case "${status}" in
        PASS) PASSES=$(( PASSES + 1 )) ;;
        FAIL) FAILURES=$(( FAILURES + 1 )) ;;
        SKIP) SKIPS=$(( SKIPS + 1 )) ;;
    esac
    RESULTS+=("${status}|${group}|${name}|${detail}")
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
    printf '  %b%s%b %-30s %b%s%b\n' "${colour}" "${glyph}" "${C_RESET}" \
        "${name}" "${C_DIM}" "${detail}" "${C_RESET}"
}

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
check_link() {
    local interface address state speed
    interface="$(cdeck::default_iface 2>/dev/null || true)"
    if [[ -z "${interface}" ]]; then
        record FAIL link "default interface" "none - no route without an interface"
        return 1
    fi
    record PASS link "default interface" "${interface}"
    state="$(cat "/sys/class/net/${interface}/operstate" 2>/dev/null || echo unknown)"
    if [[ "${state}" == "up" ]]; then
        record PASS link "link state" "${state}"
    else
        record FAIL link "link state" "${state}"
    fi
    speed="$(cat "/sys/class/net/${interface}/speed" 2>/dev/null || echo '')"
    if [[ -n "${speed}" && "${speed}" != "-1" ]]; then
        record PASS link "link speed" "${speed} Mbps"
    fi
    address="$(ip -o -4 addr show dev "${interface}" 2>/dev/null | awk '{print $4; exit}')"
    if [[ -n "${address}" ]]; then
        record PASS link "IPv4 address" "${address}"
    else
        record FAIL link "IPv4 address" "no address on ${interface}"
    fi
    local mac
    mac="$(cat "/sys/class/net/${interface}/address" 2>/dev/null || echo unknown)"
    record PASS link "MAC address" "${mac}"
    local mtu
    mtu="$(cat "/sys/class/net/${interface}/mtu" 2>/dev/null || echo unknown)"
    record PASS link "MTU" "${mtu}"
    return 0
}

check_layer3() {
    local interface gateway
    interface="$(cdeck::default_iface 2>/dev/null || true)"
    gateway="$(ip route show default 2>/dev/null | awk '{print $3; exit}')"
    if [[ -n "${gateway}" ]]; then
        record PASS layer3 "gateway" "${gateway} via ${interface}"
        if have ping; then
            if ping -c 2 -W 2 "${gateway}" >/dev/null 2>&1; then
                record PASS layer3 "gateway reachable" "2/2 replies"
            else
                record FAIL layer3 "gateway reachable" "no reply from ${gateway}"
            fi
        else
            record SKIP layer3 "gateway reachable" "ping not installed"
        fi
    else
        record FAIL layer3 "gateway" "no default gateway configured"
    fi

    if have ping; then
        local output loss rtt
        output="$(ping -c 4 -W 2 "${TEST_HOST}" 2>&1)"
        if printf '%s' "${output}" | grep -qE "[1-4] (packets )?received|[1-4] received"; then
            loss="$(printf '%s' "${output}" | grep -oE "[0-9]+(\.[0-9]+)?% packet loss" | head -1)"
            rtt="$(printf '%s' "${output}" | grep -oE "rtt [^=]+= [0-9.]+/[0-9.]+" | head -1)"
            record PASS layer3 "public reachability" "${loss:-replies received} · ${rtt:-}"
            if (( VERBOSE )) && (( ! QUIET )); then
                printf '%s\n' "${output}" | tail -2 | sed 's/^/      /'
            fi
        else
            record FAIL layer3 "public reachability" "no reply from ${TEST_HOST} (ICMP may be filtered)"
        fi
    else
        record SKIP layer3 "public reachability" "ping not installed"
    fi
}

check_dns() {
    local resolv="/etc/resolv.conf"
    if [[ -L "${resolv}" ]]; then
        record PASS dns "resolver configuration" "resolv.conf → $(readlink -f "${resolv}")"
    elif [[ -f "${resolv}" ]]; then
        record PASS dns "resolver configuration" "${resolv}"
    else
        record FAIL dns "resolver configuration" "no ${resolv}"
    fi
    local servers
    servers="$(grep -E "^nameserver" "${resolv}" 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    if [[ -n "${servers}" ]]; then
        record PASS dns "nameservers" "${servers}"
    else
        record FAIL dns "nameservers" "none configured"
    fi

    local name resolved
    for name in github.com archlinux.org one.one.one.one; do
        if have getent; then
            resolved="$(timeout 5 getent hosts "${name}" 2>/dev/null | head -1 | awk '{print $1}')"
        elif have dig; then
            resolved="$(timeout 5 dig +short "${name}" A 2>/dev/null | head -1)"
        else
            resolved=""
        fi
        if [[ -n "${resolved}" ]]; then
            record PASS dns "resolve ${name}" "${resolved}"
        else
            record FAIL dns "resolve ${name}" "no answer (DNS blocked or filter in place)"
        fi
    done

    if have dig; then
        if timeout 6 dig +dnssec +short cloudflare.com 2>/dev/null | grep -q .; then
            record PASS dns "DNSSEC resolution" "dig answered"
        else
            record SKIP dns "DNSSEC resolution" "no answer from the resolver"
        fi
    else
        record SKIP dns "DNSSEC resolution" "dig (bind-tools) not installed"
    fi
}

check_http() {
    local url status
    for url in "http://${TEST_HOST}" "https://github.com"; do
        if have curl; then
            local output code time_total
            output="$(timeout 12 curl -sS -o /dev/null -w '%{http_code} %{time_total} %{ssl_verify_result}' \
                --max-time 10 "${url}" 2>&1)"
            code="${output%% *}"
            time_total="$(printf '%s' "${output}" | awk '{print $2}')"
            if [[ "${code}" =~ ^[0-9]+$ ]] && (( code > 0 )); then
                record PASS http "fetch ${url}" "HTTP ${code} in ${time_total}s"
            else
                # A captive portal or a filtered network shows up here
                record FAIL http "fetch ${url}" "$(printf '%s' "${output}" | head -1)"
            fi
        else
            record SKIP http "fetch ${url}" "curl not installed"
            break
        fi
    done

    if have curl; then
        local body
        body="$(timeout 10 curl -sS --max-time 8 "http://${TEST_HOST}" 2>/dev/null | head -c 400 || true)"
        if printf '%s' "${body}" | grep -qiE "captive|login|sign in|portal|accept terms"; then
            record FAIL http "captive portal" "the network is redirecting HTTP to a login page"
        else
            record PASS http "captive portal" "no interception detected"
        fi
    fi

    if have openssl; then
        local expiry
        expiry="$(timeout 12 openssl s_client -connect github.com:443 -servername github.com \
            </dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
        if [[ -n "${expiry}" ]]; then
            record PASS http "TLS certificate" "github.com valid until ${expiry}"
        else
            record SKIP http "TLS certificate" "could not read the certificate"
        fi
    else
        record SKIP http "TLS certificate" "openssl not installed"
    fi
}

check_mtu() {
    if ! have ping; then
        record SKIP mtu "path MTU" "ping not installed"
        return 0
    fi
    local size=1472
    if ping -c 1 -W 3 -M do -s "${size}" "${TEST_HOST}" >/dev/null 2>&1; then
        record PASS mtu "path MTU" "1500 (no fragmentation needed at ${size})"
        return 0
    fi
    local probe
    for probe in 1400 1300 1200; do
        if ping -c 1 -W 3 -M do -s "${probe}" "${TEST_HOST}" >/dev/null 2>&1; then
            record PASS mtu "path MTU" "$(( probe + 28 )) bytes (tunnel or PPPoE in the path)"
            return 0
        fi
    done
    record SKIP mtu "path MTU" "could not determine (ICMP filtered?)"
}

check_tunnel() {
    local state="off"
    if cdeck::wireguard_up; then
        state="wireguard"
    elif pgrep -x openvpn >/dev/null 2>&1; then
        state="openvpn"
    elif pgrep -x tor >/dev/null 2>&1; then
        state="tor"
    fi
    record PASS tunnel "tunnel state" "${state}"

    local configured_vpn
    configured_vpn="$(cdeck::conf_get network.tor_enabled false)"
    if [[ "${state}" == "off" ]] && [[ "${configured_vpn}" == "true" ]]; then
        record FAIL tunnel "expected tunnel" "network.tor_enabled is true but Tor is not running"
    fi

    if [[ "${state}" == "off" ]] && (( ! FORCE_LEAK )); then
        record SKIP tunnel "leak test" "no tunnel is up (use --leak to test anyway)"
        return 0
    fi
    if ! have curl; then
        record SKIP tunnel "leak test" "curl not installed"
        return 0
    fi
    local public_ip
    public_ip="$(timeout 10 curl -sS --max-time 8 "${LEAK_URL}" 2>/dev/null | tr -d '\n' | head -c 60)"
    if [[ -z "${public_ip}" ]]; then
        record SKIP tunnel "leak test" "the leak URL did not answer (${LEAK_URL})"
        return 0
    fi
    if [[ "${state}" == "off" ]]; then
        record PASS tunnel "public address" "${public_ip} (no tunnel, direct)"
        return 0
    fi
    # With a tunnel up, the public address must not be the local WAN address
    local interface local_prefix
    interface="$(cdeck::default_iface 2>/dev/null || true)"
    local_prefix="$(ip -o -4 addr show dev "${interface}" 2>/dev/null | awk '{print $4}' | cut -d. -f1-2)"
    if [[ -n "${local_prefix}" && "${public_ip}" == "${local_prefix}"* ]]; then
        record FAIL tunnel "leak test" "public address ${public_ip} is in the local range ${local_prefix}.x.x - traffic is NOT tunnelled"
    else
        record PASS tunnel "leak test" "${state} up, public address ${public_ip}"
    fi
}

check_services() {
    local entry url purpose
    for entry in "${SERVICE_HOSTS[@]}"; do
        url="${entry%%|*}"
        purpose="${entry#*|}"
        if [[ -z "${url}" ]]; then
            continue
        fi
        if ! have curl; then
            record SKIP services "${purpose}" "curl not installed"
            continue
        fi
        local code
        code="$(timeout 12 curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "${url}" 2>/dev/null || echo 000)"
        if [[ "${code}" =~ ^[0-9]+$ ]] && (( code >= 200 && code < 500 )); then
            record PASS services "${purpose}" "HTTP ${code}"
        else
            record FAIL services "${purpose}" "HTTP ${code} - unreachable from here"
        fi
    done
    local key_count=0 key
    for key in abuseipdb alienvault_otx greynoise shodan; do
        if [[ -n "$(cdeck::conf_get "api_keys.${key}" '')" ]]; then
            key_count=$(( key_count + 1 ))
        fi
    done
    if (( key_count > 0 )); then
        record PASS services "API keys configured" "${key_count} of 4"
    else
        record SKIP services "API keys configured" "none set - enrichment stages are skipped"
    fi
}

check_targeting() {
    local interface cidr
    interface="$(cdeck::default_iface 2>/dev/null || true)"
    cidr="$(ip -o -4 addr show dev "${interface}" 2>/dev/null | awk '{print $4; exit}')"
    if [[ -n "${cidr}" ]]; then
        record PASS targeting "local subnet" "${cidr} (${interface})"
        if have ip; then
            local neighbours
            neighbours="$(ip neigh show dev "${interface}" 2>/dev/null | wc -l | tr -d ' ')"
            record PASS targeting "neighbour table" "${neighbours} entry/entries"
        fi
    else
        record SKIP targeting "local subnet" "no address on the default interface"
    fi
    local ranges
    ranges="$(cdeck::conf_get scanning.auto_target_ranges '')"
    if [[ -n "${ranges}" ]]; then
        record PASS targeting "declared scan ranges" "${ranges//$'\n'/ }"
    fi
    if [[ -f "${INSTALL_DIR}/data/oui_database.txt" ]]; then
        record PASS targeting "OUI database" "$(wc -l < "${INSTALL_DIR}/data/oui_database.txt" | tr -d ' ') entries for offline lookups"
    else
        record SKIP targeting "OUI database" "not installed - vendor lookups need the network"
    fi
}

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
run_all() {
    RESULTS=(); PASSES=0; FAILURES=0; SKIPS=0
    if check_link; then
        check_layer3
    else
        record FAIL layer3 "reachability" "skipped: no default interface"
    fi
    check_dns
    check_http
    check_tunnel
    if (( ! QUICK )); then
        check_mtu
        check_services
    fi
    check_targeting
}

emit_json() {
    printf '{\n'
    printf '  "generated": "%s",\n' "$(cdeck::iso_stamp)"
    printf '  "test_host": "%s",\n' "${TEST_HOST}"
    printf '  "passed": %d, "failed": %d, "skipped": %d,\n' "${PASSES}" "${FAILURES}" "${SKIPS}"
    printf '  "checks": [\n'
    local first=1 entry
    for entry in "${RESULTS[@]}"; do
        IFS='|' read -r status group name detail <<< "${entry}"
        (( first )) || printf ',\n'
        first=0
        printf '    {"status": "%s", "group": "%s", "name": "%s", "detail": "%s"}' \
            "${status}" "${group}" "${name//\"/}" "${detail//\"/}"
    done
    printf '\n  ]\n}\n'
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)       usage; exit 0 ;;
        --version|-V)    printf 'test_connectivity %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -q|--quick)      QUICK=1 ;;
        -j|--json)       JSON=1; QUIET=1 ;;
        -l|--leak)       FORCE_LEAK=1 ;;
        -v|--verbose)    VERBOSE=1 ;;
        --host)          shift; TEST_HOST="${1:-${TEST_HOST}}" ;;
        --install-dir)   shift; INSTALL_DIR="${1:-${INSTALL_DIR}}" ;;
        *)               cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

if (( ! QUIET )); then
    cdeck::banner "connectivity test" "${TEST_HOST} · $(hostname) · $(date '+%H:%M:%S')"
fi

run_all

if (( JSON )); then
    emit_json
else
    printf '\n'
    printf '  %b%d passed%b · %b%d failed%b · %b%d skipped%b\n\n' \
        "${C_GREEN}" "${PASSES}" "${C_RESET}" \
        "$([[ ${FAILURES} -gt 0 ]] && echo "${C_RED}" || echo "${C_DIM}")" "${FAILURES}" "${C_RESET}" \
        "${C_DIM}" "${SKIPS}" "${C_RESET}"
    if (( FAILURES )); then
        cdeck::warn "${FAILURES} connectivity check(s) failed"
        cdeck::info "if the deck should be offline (air-gapped work), this is expected"
        cdeck::info "to bring it back: cdeck profiles --apply <profile> · cdeck vpn --up"
    else
        cdeck::ok "the deck is online"
    fi
    printf '\n'
fi

exit "${FAILURES}"
