#!/usr/bin/env bash
# =============================================================================
# vpn_switcher.sh - VPN profile manager with leak checking and kill switch
# =============================================================================
#
# Description
# -----------
# Manages OpenVPN and WireGuard profiles from the command line, rotates between
# them, and verifies that traffic actually leaves through the tunnel:
#
#   * brings profiles up/down and records the state in state/vpn.state
#   * reports the effective exit address, the resolvers in use and whether IPv6
#     is leaking around the tunnel
#   * installs a kill switch (default-deny for anything that is not the tunnel)
#     so a dropped VPN does not silently expose traffic on the raw interface
#   * can start Tor and print the proxychains configuration for it
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: openvpn or wireguard-tools, iptables, curl, iproute2;
#               optional: tor, proxychains-ng, resolvectl/systemd-resolved
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   sudo ./vpn_switcher.sh --list
#   sudo ./vpn_switcher.sh --up proton-uk-01
#   sudo ./vpn_switcher.sh --status --check-leaks
#   sudo ./vpn_switcher.sh --rotate --random
#   sudo ./vpn_switcher.sh --kill-switch on
#   sudo ./vpn_switcher.sh --down
#   ./vpn_switcher.sh --help
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

cdeck::init "vpn_switcher"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
STATE_DIR="${CDECK_INSTALL_DIR}/state"
STATE_FILE="${STATE_DIR}/vpn.state"
PROFILE_DIR="$(cdeck::conf_get network.vpn_profile_dir /etc/openvpn/profiles)"
DEFAULT_CONFIG="$(cdeck::conf_get network.default_vpn_config /etc/openvpn/client.conf)"
WIREGUARD_IFACE="$(cdeck::conf_get network.wireguard_interface wg0)"
LEAK_URL="$(cdeck::conf_get network.leak_test_url http://ifconfig.me/ip)"
KILL_SWITCH_DEFAULT="$(cdeck::conf_get network.kill_switch true)"

ACTION="status"
PROFILE=""
RANDOM_PROFILE=0
CHECK_LEAKS=0
ACTION_ARG=""
CHAIN="CDECK_KILLSWITCH"

usage() {
    cdeck::usage_header \
        "VPN profile manager (OpenVPN + WireGuard) with leak checks and a kill switch" \
        "$0 [--up <profile> | --down | --rotate [--random] | --status | --list | --kill-switch on|off | --tor on|off | --check-leaks]" \
        "sudo $0 --list                                  # show available profiles" \
        "sudo $0 --up proton-uk-01                       # connect" \
        "sudo $0 --status --check-leaks                  # exit IP, DNS and IPv6 checks" \
        "sudo $0 --rotate --random                       # switch to a random profile" \
        "sudo $0 --kill-switch on                        # survive a dropped tunnel"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -u, --up NAME          bring up an OpenVPN profile or WireGuard interface
  -d, --down             bring the active tunnel down and stop the kill switch
  -r, --rotate           switch to another profile
  --random               with --rotate: choose the profile at random
  -s, --status           show interface, exit address and tunnel state (default)
  -l, --list             list profiles found on disk
  --check-leaks          compare exit addresses, resolvers and IPv6 exposure
  --kill-switch on|off   default-deny everything outside the tunnel
  --tor on|off           start/stop Tor and print the proxychains config
  -p, --profile-dir DIR  override the profile directory (${PROFILE_DIR})
  --yes                  skip confirmation prompts
  --help, -h             this help

${C_BOLD}WHERE PROFILES LIVE${C_RESET}
  OpenVPN      ${PROFILE_DIR}/*.ovpn, /etc/openvpn/client/*.conf, ${DEFAULT_CONFIG}
  WireGuard    /etc/wireguard/*.conf  (interface name = file name without .conf)
  State        ${STATE_FILE}

${C_YELLOW}⚠  The kill switch blocks all non-tunnel traffic, including your SSH${C_RESET}
  session if you are connected over the interface it protects. Use it on a local
  console or add an explicit exception for your management address first.
EOF
}

# --------------------------------------------------------------------------- #
# Arguments
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)       usage; exit 0 ;;
        --version|-V)    printf 'vpn_switcher %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -u|--up)         shift; ACTION="up"; PROFILE="${1:-}" ;;
        -d|--down)       ACTION="down" ;;
        -r|--rotate)     ACTION="rotate" ;;
        --random)        RANDOM_PROFILE=1 ;;
        -s|--status)     ACTION="status" ;;
        -l|--list)       ACTION="list" ;;
        --check-leaks)   CHECK_LEAKS=1 ;;
        --kill-switch)   shift; ACTION="killswitch"; ACTION_ARG="${1:-}" ;;
        --tor)           shift; ACTION="tor"; ACTION_ARG="${1:-}" ;;
        -p|--profile-dir) shift; PROFILE_DIR="${1:-}" ;;
        --yes|-y)        export CDECK_ASSUME_YES=1 ;;
        -*)              cdeck::error "unknown option: $1"; usage; exit 2 ;;
        *)               cdeck::warn "ignoring non-option argument: $1" ;;
    esac
    shift
done

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
profile_kind() {
    # profile_kind <name> -> openvpn | wireguard | unknown
    local name="$1"
    if [[ -f "${PROFILE_DIR}/${name}.ovpn" || -f "${PROFILE_DIR}/${name}" \
          || -f "/etc/openvpn/client/${name}.conf" || "${name}" == "${DEFAULT_CONFIG}" \
          || -f "/etc/openvpn/${name}.conf" ]]; then
        printf 'openvpn'
    elif [[ -f "/etc/wireguard/${name}.conf" || -f "${PROFILE_DIR}/${name}.conf" ]]; then
        printf 'wireguard'
    else
        printf 'unknown'
    fi
}

profile_path() {
    local name="$1" candidate
    for candidate in "${PROFILE_DIR}/${name}.ovpn" "${PROFILE_DIR}/${name}" \
                     "${PROFILE_DIR}/${name}.conf" "/etc/openvpn/client/${name}.conf" \
                     "/etc/openvpn/${name}.conf" "/etc/wireguard/${name}.conf" "${name}"; do
        [[ -f "${candidate}" ]] && { printf '%s' "${candidate}"; return 0; }
    done
    return 1
}

require_vpn_tools() {
    local missing=()
    cdeck::has_cmd openvpn || missing+=(openvpn)
    cdeck::has_cmd wg || missing+=(wireguard-tools)
    if (( ${#missing[@]} == 2 )); then
        cdeck::error "no VPN client installed (missing: ${missing[*]})"
        cdeck::info "install with: sudo pacman -S openvpn wireguard-tools"
        return 1
    fi
    return 0
}

save_state() {
    mkdir -p "${STATE_DIR}"
    {
        printf 'updated=%s\n' "$(date -Is)"
        printf 'action=%s\n' "$1"
        printf 'profile=%s\n' "${2:-}"
        printf 'kind=%s\n' "${3:-}"
        printf 'interface=%s\n' "${4:-}"
        printf 'tunnel_ip=%s\n' "${5:-}"
        printf 'exit_ip=%s\n' "${6:-}"
        printf 'kill_switch=%s\n' "$(kill_switch_status)"
    } > "${STATE_FILE}"
    chmod 0600 "${STATE_FILE}" 2>/dev/null || true
}

external_ip() {
    local endpoint
    for endpoint in "http://ifconfig.me/ip" "http://icanhazip.com" \
                    "http://api.ipify.org" "http://checkip.amazonaws.com"; do
        local value
        value="$(curl -fsS -m 8 "${endpoint}" 2>/dev/null | tr -d '[:space:]')"
        if [[ -n "${value}" ]]; then
            printf '%s' "${value}"
            return 0
        fi
    done
    printf 'unavailable'
    return 1
}

active_tunnel() {
    # Prints: kind|interface|config
    local iface
    for iface in $(cdeck::interfaces); do
        case "${iface}" in
            tun*|tap*)
                if pgrep -af "openvpn.*${iface}" >/dev/null 2>&1 || pgrep -af "openvpn" >/dev/null 2>&1; then
                    printf 'openvpn|%s|%s\n' "${iface}" "$(pgrep -af openvpn | head -1 | awk '{print $NF}')"
                    return 0
                fi
                ;;
        esac
    done
    if [[ -d "/sys/class/net/${WIREGUARD_IFACE}" ]]; then
        printf 'wireguard|%s|/etc/wireguard/%s.conf\n' "${WIREGUARD_IFACE}" "${WIREGUARD_IFACE}"
        return 0
    fi
    # Any other wireguard interface that happens to be up
    for iface in $(cdeck::interfaces); do
        if [[ -d "/sys/class/net/${iface}/wireguard" ]]; then
            printf 'wireguard|%s|/etc/wireguard/%s.conf\n' "${iface}" "${iface}"
            return 0
        fi
    done
    printf 'none||\n'
    return 1
}

kill_switch_status() {
    cdeck::has_cmd iptables || { printf 'unavailable'; return 0; }
    if iptables -L "${CHAIN}" -n >/dev/null 2>&1; then
        printf 'active'
    else
        printf 'inactive'
    fi
}

# --------------------------------------------------------------------------- #
# Kill switch
# --------------------------------------------------------------------------- #
kill_switch_on() {
    if ! cdeck::has_cmd iptables; then
        cdeck::error "iptables is required for the kill switch"
        return 1
    fi
    local tunnel_iface="$1"
    cdeck::warning "${C_YELLOW}kill switch${C_RESET}: blocking all traffic that is not the tunnel"

    iptables -N "${CHAIN}" 2>/dev/null || iptables -F "${CHAIN}"
    # Always allow loopback and the tunnel itself
    iptables -A "${CHAIN}" -o lo -j ACCEPT
    iptables -A "${CHAIN}" -o "${tunnel_iface}" -j ACCEPT
    [[ -n "${WIREGUARD_IFACE}" ]] && iptables -A "${CHAIN}" -o "${WIREGUARD_IFACE}" -j ACCEPT
    # Allow established/related traffic and the VPN handshake itself
    iptables -A "${CHAIN}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A "${CHAIN}" -p udp -m multiport --dports 1194,1195,1197,1198,51820 -j ACCEPT
    iptables -A "${CHAIN}" -p tcp -m multiport --dports 443,1194 -j ACCEPT
    # DHCP so the interface can still get an address
    iptables -A "${CHAIN}" -p udp --dport 67:68 -j ACCEPT
    # Allow the management/SSH source address recorded by the operator
    if [[ -n "$(cdeck::conf_get network.management_address "")" ]]; then
        iptables -A "${CHAIN}" -s "$(cdeck::conf_get network.management_address "")" -j ACCEPT
    fi
    iptables -A "${CHAIN}" -j DROP

    iptables -C OUTPUT -j "${CHAIN}" 2>/dev/null || iptables -I OUTPUT 1 -j "${CHAIN}"
    cdeck::ok "kill switch installed (chain ${CHAIN})"
    cdeck::info "verify with: ip a; curl -m 5 ${LEAK_URL}"
    return 0
}

kill_switch_off() {
    if ! cdeck::has_cmd iptables; then
        cdeck::warn "iptables not installed - nothing to remove"
        return 0
    fi
    while iptables -C OUTPUT -j "${CHAIN}" 2>/dev/null; do
        iptables -D OUTPUT -j "${CHAIN}" || break
    done
    while iptables -C FORWARD -j "${CHAIN}" 2>/dev/null; do
        iptables -D FORWARD -j "${CHAIN}" || break
    done
    iptables -F "${CHAIN}" 2>/dev/null || true
    iptables -X "${CHAIN}" 2>/dev/null || true
    cdeck::ok "kill switch removed"
    return 0
}

# --------------------------------------------------------------------------- #
# Connecting / disconnecting
# --------------------------------------------------------------------------- #
connect_openvpn() {
    local config="$1" name="$2"
    if ! cdeck::has_cmd openvpn; then
        cdeck::error "openvpn is not installed (pacman -S openvpn)"
        return 1
    fi
    mkdir -p "${INSTALL_DIR}/logs" "${INSTALL_DIR}/state"
    local log="${CDECK_LOG_DIR}/openvpn.log"
    cdeck::info "starting OpenVPN with ${config}"
    nohup openvpn --config "${config}" --daemon cdeck-openvpn \
        --log "${log}" --writepid "${STATE_DIR}/openvpn.pid" >/dev/null 2>&1 || {
        cdeck::error "openvpn failed to start - see ${log}"
        tail -5 "${log}" 2>/dev/null | sed 's/^/    /'
        return 1
    }

    # Wait for the tunnel interface to appear
    local waited=0 tunnel=""
    while (( waited < 30 )); do
        for candidate in $(cdeck::interfaces); do
            case "${candidate}" in
                tun*|tap*) tunnel="${candidate}" ;;
            esac
        done
        [[ -n "${tunnel}" ]] && break
        sleep 1
        waited=$(( waited + 1 ))
    done
    if [[ -z "${tunnel}" ]]; then
        cdeck::error "no tunnel interface appeared after 30s"
        cdeck::info "common causes: wrong credentials, expired certificate, blocked UDP port"
        tail -8 "${log}" 2>/dev/null | sed 's/^/    /'
        return 1
    fi
    cdeck::ok "tunnel up: ${tunnel}"
    local tunnel_ip exit_ip
    tunnel_ip="$(ip -4 -o addr show "${tunnel}" | awk '{print $4}' | cut -d/ -f1 | head -1)"
    exit_ip="$(external_ip)"

    if [[ "$(kill_switch_status)" != "active" && "${KILL_SWITCH_DEFAULT}" == "true" ]]; then
        cdeck::info "network.kill_switch is true in cyberdeck.conf - installing the kill switch"
        kill_switch_on "${tunnel}"
    fi
    save_state "up" "${name}" "openvpn" "${tunnel}" "${tunnel_ip}" "${exit_ip}"
    cdeck::ok "exit address: ${exit_ip} (tunnel address ${tunnel_ip})"
    log_event "VPN up (${name}, ${tunnel}, exit ${exit_ip})"
    return 0
}

connect_wireguard() {
    local interface="$1"
    if ! cdeck::has_cmd wg; then
        cdeck::error "wireguard-tools are not installed (pacman -S wireguard-tools)"
        return 1
    fi
    if [[ ! -f "/etc/wireguard/${interface}.conf" ]]; then
        cdeck::error "no configuration found at /etc/wireguard/${interface}.conf"
        return 1
    fi
    cdeck::info "bringing up WireGuard interface ${interface}"
    if wg-quick up "${interface}"; then
        cdeck::ok "wireguard ${interface} is up"
        local tunnel_ip exit_ip
        tunnel_ip="$(ip -4 -o addr show "${interface}" | awk '{print $4}' | cut -d/ -f1 | head -1)"
        exit_ip="$(external_ip)"
        if [[ "$(kill_switch_status)" != "active" && "${KILL_SWITCH_DEFAULT}" == "true" ]]; then
            kill_switch_on "${interface}"
        fi
        save_state "up" "${interface}" "wireguard" "${interface}" "${tunnel_ip}" "${exit_ip}"
        cdeck::ok "exit address: ${exit_ip}"
        log_event "WireGuard up (${interface}, exit ${exit_ip})"
        return 0
    fi
    cdeck::error "wg-quick failed"
    cdeck::info "check the configuration and try: sudo wg-quick up ${interface}"
    return 1
}

disconnect() {
    local kind="$1" interface="$2"
    case "${kind}" in
        openvpn)
            if [[ -f "${STATE_DIR}/openvpn.pid" ]]; then
                local pid; pid="$(cat "${STATE_DIR}/openvpn.pid")"
                kill -TERM "${pid}" 2>/dev/null && cdeck::ok "sent TERM to openvpn (pid ${pid})"
                rm -f "${STATE_DIR}/openvpn.pid"
            fi
            cdeck::kill_processes "openvpn --config" || true
            ;;
        wireguard)
            if cdeck::has_cmd wg-quick; then
                wg-quick down "${interface}" 2>/dev/null && cdeck::ok "wireguard ${interface} down" \
                    || cdeck::warn "could not bring ${interface} down (was it up?)"
            fi
            ;;
        none)
            cdeck::info "no tunnel is running"
            ;;
    esac
    kill_switch_off
    save_state "down" "" "" "" "" "$(external_ip)"
    log_event "VPN down (${kind:-none})"
    cdeck::ok "traffic will use the normal interface again"
    return 0
}

# --------------------------------------------------------------------------- #
# Listing, status, leaks
# --------------------------------------------------------------------------- #
list_profiles() {
    cdeck::banner "VPN profiles" "${PROFILE_DIR}"
    local found=0 name
    if [[ -d "${PROFILE_DIR}" ]]; then
        while IFS= read -r name; do
            [[ -z "${name}" ]] && continue
            found=$(( found + 1 ))
            printf '    %s%-28s%s openvpn\n' "${C_BOLD}" "$(basename "${name}" .ovpn)" "${C_RESET}"
        done < <(find "${PROFILE_DIR}" -maxdepth 1 -name '*.ovpn' -o -name '*.conf' 2>/dev/null | sort)
    fi
    if [[ -d /etc/openvpn/client ]]; then
        while IFS= read -r name; do
            [[ -z "${name}" ]] && continue
            found=$(( found + 1 ))
            printf '    %s%-28s%s openvpn (/etc/openvpn/client)\n' "${C_BOLD}" \
                "$(basename "${name}" .conf)" "${C_RESET}"
        done < <(find /etc/openvpn/client -maxdepth 1 -name '*.conf' 2>/dev/null | sort)
    fi
    if [[ -f "${DEFAULT_CONFIG}" ]]; then
        found=$(( found + 1 ))
        printf '    %s%-28s%s openvpn (configured default)\n' "${C_BOLD}" \
            "$(basename "${DEFAULT_CONFIG}")" "${C_RESET}"
    fi
    if [[ -d /etc/wireguard ]]; then
        while IFS= read -r name; do
            [[ -z "${name}" ]] && continue
            found=$(( found + 1 ))
            printf '    %s%-28s%s wireguard\n' "${C_BOLD}" "$(basename "${name}" .conf)" "${C_RESET}"
        done < <(find /etc/wireguard -maxdepth 1 -name '*.conf' 2>/dev/null | sort)
    fi
    if (( found == 0 )); then
        cdeck::warn "no VPN profiles found"
        cdeck::info "put .ovpn files in ${PROFILE_DIR} or WireGuard configs in /etc/wireguard"
        cdeck::info "many providers ship an .ovpn download per location"
    else
        cdeck::info "${found} profile(s) available"
    fi
    return 0
}

show_status() {
    cdeck::banner "VPN status" "$(date '+%H:%M:%S')"
    local active kind interface config
    active="$(active_tunnel)"
    IFS='|' read -r kind interface config <<< "${active}"

    printf '\n  %stunnel%s\n' "${C_BOLD}" "${C_RESET}"
    if [[ "${kind}" == "none" ]]; then
        printf '    %snone active%s - traffic is using the normal interface\n' "${C_YELLOW}" "${C_RESET}"
    else
        printf '    %s%s%s on %s\n' "${C_GREEN}" "${kind}" "${C_RESET}" "${interface}"
        printf '    config      : %s\n' "${config}"
        printf '    address     : %s\n' "$(ip -4 -o addr show "${interface}" 2>/dev/null | awk '{print $4}')"
        printf '    peer        : %s\n' "$(if [[ "${kind}" == "wireguard" ]] && cdeck::has_cmd wg; then
            wg show "${interface}" endpoints 2>/dev/null | awk '{print $2}' | paste -sd, -; fi)"
    fi

    printf '\n  %sports and leak surface%s\n' "${C_BOLD}" "${C_RESET}"
    printf '    kill switch : %s\n' "$(kill_switch_status)"
    printf '    default gw  : %s\n' "$(ip route show default | awk '{print $3}' | paste -sd, -)"
    printf '    resolvers   : %s\n' "$(grep -h '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | paste -sd, - )"
    local v6_gateway
    v6_gateway="$(ip -6 route show default 2>/dev/null | head -1 | awk '{print $3}')"
    printf '    ipv6 route  : %s\n' "${v6_gateway:-none (IPv6 disabled or unrouted)}"

    printf '\n  %sexit address%s\n' "${C_BOLD}" "${C_RESET}"
    local exit_ip
    exit_ip="$(external_ip)"
    printf '    %s\n' "${exit_ip}"
    if [[ "${kind}" != "none" && "${exit_ip}" != "unavailable" ]]; then
        # If the exit address equals the direct address, the tunnel is not used
        local direct
        direct="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep -v '^10\.\|^192\.168\.\|^172\.' | head -1)"
        if [[ "${exit_ip}" == "${direct}" ]]; then
            cdeck::alert "the exit address equals a local address - traffic may NOT be tunnelled"
            cdeck::info "check the routing table: ip route get 1.1.1.1"
        else
            cdeck::ok "exit address differs from the local address - the tunnel is carrying traffic"
        fi
    fi

    if [[ -f "${STATE_FILE}" ]]; then
        printf '\n  %srecorded state%s\n' "${C_BOLD}" "${C_RESET}"
        sed 's/^/    /' "${STATE_FILE}"
    fi
    printf '\n'
    return 0
}

check_leaks() {
    cdeck::banner "leak check" "${LEAK_URL}"
    local failures=0

    cdeck::info "1/4 external address (multiple endpoints)"
    local ip1 ip2
    ip1="$(curl -fsS -m 8 http://ifconfig.me/ip 2>/dev/null | tr -d '[:space:]')"
    ip2="$(curl -fsS -m 8 http://icanhazip.com 2>/dev/null | tr -d '[:space:]')"
    printf '    ifconfig.me : %s\n' "${ip1:-unavailable}"
    printf '    icanhazip   : %s\n' "${ip2:-unavailable}"
    if [[ -n "${ip1}" && -n "${ip2}" && "${ip1}" != "${ip2}" ]]; then
        cdeck::alert "different exit addresses reported - traffic may be split across paths"
        failures=$(( failures + 1 ))
    fi
    [[ -z "${ip1}" ]] && { cdeck::error "no outbound connectivity"; failures=$(( failures + 1 )); }

    cdeck::info "2/4 DNS resolvers"
    if cdeck::has_cmd resolvectl; then
        resolvectl status 2>/dev/null | grep -E "DNS Servers|Current DNS Server" | sed 's/^/    /' | head -6
    fi
    grep -h '^nameserver' /etc/resolv.conf 2>/dev/null | sed 's/^/    /' | head -6
    local resolver
    while read -r resolver; do
        [[ -z "${resolver}" ]] && continue
        if [[ "${resolver}" == "127.0.0.53" || "${resolver}" == "127.0.0.1" ]]; then
            continue  # local stub resolver: fine, it forwards per its own config
        fi
        if [[ "${resolver}" =~ ^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
            cdeck::alert "resolver ${resolver} is a private address - queries may bypass the tunnel"
            failures=$(( failures + 1 ))
        fi
    done < <(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null)

    cdeck::info "3/4 IPv6 exposure"
    local v6
    v6="$(curl -fsS -m 8 -6 http://icanhazip.com 2>/dev/null | tr -d '[:space:]')"
    if [[ -n "${v6}" ]]; then
        cdeck::alert "IPv6 works (${v6}) - if the VPN is IPv4-only, that is a leak"
        failures=$(( failures + 1 ))
    else
        cdeck::ok "no IPv6 route to the internet (nothing to leak over)"
    fi

    cdeck::info "4/4 routing for the exit destination"
    local route
    route="$(ip route get 1.1.1.1 2>/dev/null | head -2 | sed 's/^/    /')"
    printf '%s\n' "${route}"
    local active kind interface
    IFS='|' read -r kind interface _ <<< "$(active_tunnel)"
    if [[ "${kind}" != "none" ]] && ! grep -q "dev ${interface}" <<< "${route}"; then
        cdeck::alert "traffic to 1.1.1.1 does not use ${interface} - the tunnel is not the default path"
        failures=$(( failures + 1 ))
    fi

    printf '\n'
    if (( failures )); then
        cdeck::warn "${failures} potential leak(s) found - review the output above"
        log_event "leak check found ${failures} issue(s)" WARNING
        return 1
    fi
    cdeck::ok "no leaks detected in this check"
    log_event "leak check passed" INFO
    return 0
}

# --------------------------------------------------------------------------- #
# Tor
# --------------------------------------------------------------------------- #
tor_control() {
    local argument="$1"
    case "${argument}" in
        on)
            if ! cdeck::has_cmd tor; then
                cdeck::error "tor is not installed (pacman -S tor)"
                return 1
            fi
            if systemctl start tor 2>/dev/null; then
                cdeck::ok "tor started via systemd"
            elif tor --daemon 2>/dev/null; then
                cdeck::ok "tor started in the background"
            else
                cdeck::error "could not start tor"
                return 1
            fi
            sleep 2
            cdeck::info "proxy: socks5 127.0.0.1:9050"
            if cdeck::has_cmd proxychains4 || cdeck::has_cmd proxychains; then
                cdeck::info "use proxychains for individual commands, e.g. proxychains4 nmap -sT target"
                cdeck::info "keep this in /etc/proxychains.conf:  socks5 127.0.0.1 9050"
            fi
            cdeck::info "transparent mode needs iptables rules on 9040/53 - route through a socks proxy instead"
            ;;
        off)
            systemctl stop tor 2>/dev/null && cdeck::ok "tor stopped" || true
            cdeck::kill_processes "tor --daemon" || true
            cdeck::info "tor is no longer running"
            ;;
        status)
            if pgrep -x tor >/dev/null 2>&1; then
                cdeck::ok "tor is running"
                printf '    exit address: %s\n' \
                    "$(curl -fsS -m 10 --socks5 127.0.0.1:9050 http://ifconfig.me/ip 2>/dev/null || echo unavailable)"
            else
                cdeck::info "tor is not running"
            fi
            ;;
        *)
            cdeck::error "usage: --tor on|off|status"
            return 2
            ;;
    esac
    return 0
}

log_event() {
    local message="$1" severity="${2:-INFO}"
    python3 - "${message}" "${severity}" <<'PYEOF' 2>/dev/null || true
import sys
try:
    sys.path.insert(0, "/opt/cyberdeck-arsenal/lib")
    from cyberlib import Database
    with Database("events") as db:
        db.event("vpn_switcher", "vpn", sys.argv[1], sys.argv[2])
except Exception:
    pass
PYEOF
}

# --------------------------------------------------------------------------- #
# Rotate
# --------------------------------------------------------------------------- #
rotate() {
    local -a profiles=()
    local candidate
    if [[ -d "${PROFILE_DIR}" ]]; then
        while IFS= read -r candidate; do
            [[ -z "${candidate}" ]] && continue
            profiles+=("$(basename "${candidate}")")
        done < <(find "${PROFILE_DIR}" -maxdepth 1 -type f \( -name '*.ovpn' -o -name '*.conf' \) 2>/dev/null | sort)
    fi
    if [[ -d /etc/wireguard ]]; then
        while IFS= read -r candidate; do
            [[ -z "${candidate}" ]] && continue
            profiles+=("$(basename "${candidate}" .conf)")
        done < <(find /etc/wireguard -maxdepth 1 -name '*.conf' 2>/dev/null | sort)
    fi

    if (( ${#profiles[@]} == 0 )); then
        cdeck::error "no profiles to rotate between"
        cdeck::info "add profiles to ${PROFILE_DIR} or /etc/wireguard"
        return 1
    fi
    if (( ${#profiles[@]} == 1 )); then
        cdeck::warn "only one profile available - rotating to it"
    fi

    local active kind interface
    IFS='|' read -r kind interface _ <<< "$(active_tunnel)"
    local chosen=""
    if (( RANDOM_PROFILE )); then
        while true; do
            chosen="${profiles[RANDOM % ${#profiles[@]}]}"
            [[ -z "${kind}" || "${kind}" == "none" ]] && break
            [[ "${chosen}" != "${interface}" ]] && break
        done
        cdeck::info "randomly selected: ${chosen}"
    else
        # Deterministic round-robin: pick the profile after the active one
        local index=0 position=-1
        for candidate in "${profiles[@]}"; do
            [[ "${candidate%.*}" == "${interface}" || "${candidate}" == "${interface}" ]] && position="${index}"
            index=$(( index + 1 ))
        done
        chosen="${profiles[$(( (position + 1) % ${#profiles[@]} ))]}"
        cdeck::info "next profile in rotation: ${chosen}"
    fi

    cdeck::confirm "Switch the tunnel to ${chosen}?" y || {
        cdeck::info "rotation cancelled"
        return 0
    }
    [[ "${kind}" != "none" ]] && disconnect "${kind}" "${interface}"
    bring_up "${chosen%.ovpn}"
}

bring_up() {
    local name="$1"
    local kind; kind="$(profile_kind "${name}")"
    case "${kind}" in
        openvpn)
            local path; path="$(profile_path "${name}")" || {
                cdeck::error "profile not found: ${name}"; return 1; }
            connect_openvpn "${path}" "${name}"
            ;;
        wireguard)
            connect_wireguard "${name}"
            ;;
        *)
            cdeck::error "unknown profile: ${name}"
            cdeck::info "run --list to see what is available"
            return 2
            ;;
    esac
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
require_vpn_tools || true

case "${ACTION}" in
    list)
        list_profiles; exit $?
        ;;
    status)
        show_status
        if (( CHECK_LEAKS )); then
            cdeck::require_root "leak checking" || exit 1
            check_leaks || exit 1
        fi
        exit 0
        ;;
    up)
        if [[ -z "${PROFILE}" ]]; then
            cdeck::error "--up needs a profile name (see --list)"
            exit 2
        fi
        cdeck::require_root "bringing a tunnel up" || exit 1
        # Disconnect whatever is already running so we do not stack tunnels
        IFS='|' read -r kind interface _ <<< "$(active_tunnel)"
        [[ "${kind}" != "none" ]] && disconnect "${kind}" "${interface}"
        bring_up "${PROFILE}"
        exit $?
        ;;
    down)
        cdeck::require_root "bringing the tunnel down" || exit 1
        IFS='|' read -r kind interface _ <<< "$(active_tunnel)"
        disconnect "${kind}" "${interface}"
        exit $?
        ;;
    rotate)
        cdeck::require_root "rotating the tunnel" || exit 1
        rotate
        exit $?
        ;;
    killswitch)
        cdeck::require_root "changing the kill switch" || exit 1
        case "${ACTION_ARG}" in
            on)
                IFS='|' read -r kind interface _ <<< "$(active_tunnel)"
                if [[ "${kind}" == "none" ]]; then
                    cdeck::warn "no tunnel is up: enabling the kill switch now will block all traffic"
                    cdeck::warn "use it as a 'panic' packet stop, and remember to turn it off"
                    cdeck::confirm "Continue anyway?" n || exit 1
                    interface="none"
                fi
                kill_switch_on "${interface}"
                ;;
            off) kill_switch_off ;;
            "")  printf 'kill switch: %s\n' "$(kill_switch_status)" ;;
            *)   cdeck::error "usage: --kill-switch on|off"; exit 2 ;;
        esac
        save_state "killswitch" "" "" "" "" "$(external_ip)"
        exit $?
        ;;
    tor)
        case "${ACTION_ARG}" in
            on) cdeck::require_root "starting tor" || exit 1 ;;
            off) cdeck::require_root "stopping tor" || exit 1 ;;
        esac
        tor_control "${ACTION_ARG:-status}"
        exit $?
        ;;
    *)
        cdeck::error "unknown action: ${ACTION}"
        usage
        exit 2
        ;;
esac
