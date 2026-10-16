#!/usr/bin/env bash
# =============================================================================
# network_profile_manager.sh - per-location network profiles
# =============================================================================
#
# Description
# -----------
# Saves and applies complete network configurations ("profiles") so the deck
# can move between a lab bench, a client site, a hotel and a home network
# without re-typing addresses. A profile records the interface set, addressing
# mode (DHCP or static), address/prefix/gateway, DNS resolvers, search domain,
# MTU, proxy settings, MAC policy and whether radios should be left off.
#
# Applying a profile uses NetworkManager (nmcli) when it is available, and falls
# back to plain ip/iw/resolv.conf so the tool still works on a minimal BlackArch
# install with no NM running.
#
# Commands
#   --list                 show saved profiles
#   --current              show the live configuration (addresses, routes, DNS)
#   --save NAME            capture the current configuration as NAME
#   --apply NAME           apply a profile
#   --show NAME            print a profile
#   --delete NAME          remove a profile (prompts)
#   --export [DIR]         copy profiles to a directory (or tar them)
#   --import PATH          import a profile or a tar of profiles
#   --set-static ...       create/update a profile with static addressing
#   --set-dhcp NAME        create/update a profile using DHCP
#   --dns "1.1.1.1 ..."    set the resolvers for a profile
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: iproute2, iw, resolvconf or systemd-resolved; optional: nmcli
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   sudo ./network_profile_manager.sh --save client-site-eth0
#   sudo ./network_profile_manager.sh --apply client-site-eth0
#   sudo ./network_profile_manager.sh --set-static lab --iface eth0 \
#        --address 10.10.10.50/24 --gateway 10.10.10.1 --dns "10.10.10.2 1.1.1.1"
#   ./network_profile_manager.sh --list
#   ./network_profile_manager.sh --help
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

cdeck::init "network_profile_manager"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
PROFILE_DIR="${CDECK_INSTALL_DIR}/profiles"
DEFAULT_DNS="$(cdeck::conf_get network.dns_servers "" | tr -d '[]",')"
ACTION=""
NAME=""
IFACE="$(cdeck::conf_get network.ethernet_interface eth0)"
ADDRESS=""
GATEWAY=""
DNS=""
SEARCH_DOMAIN=""
MTU=""
PROXY=""
MAC_POLICY="keep"
TARGET=""

usage() {
    cdeck::usage_header \
        "Per-location network profile manager (DHCP, static, DNS, proxy)" \
        "$0 <--save NAME | --apply NAME | --list | --current | --show NAME | --delete NAME | --export [DIR] | --import PATH | --set-static NAME ... | --set-dhcp NAME>" \
        "sudo $0 --save site-lab                     # snapshot the current setup" \
        "sudo $0 --apply site-lab                    # switch to it later" \
        "sudo $0 --set-static bench --iface eth0 --address 10.10.10.50/24 --gateway 10.10.10.1" \
        "sudo $0 --show bench                        # inspect a profile" \
        "$0 --current                                # what is live right now"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -s, --save NAME           capture the current configuration as NAME
  -a, --apply NAME          apply a saved profile
  -l, --list                list saved profiles
  -c, --current             show the live configuration
  --show NAME               print a saved profile (raw)
  -d, --delete NAME         delete a profile
  --export [DIR]            copy every profile to DIR (default: cwd)
  --import PATH             import a profile file or a tar archive
  --set-static NAME         write a static profile (needs --address)
  --set-dhcp NAME           write a DHCP profile
  -i, --iface IF            interface for --set-* (default: ${IFACE})
  --address CIDR            e.g. 10.10.10.50/24
  --gateway IP
  --dns "IP [IP...]"        resolvers, space separated
  --search DOMAIN           DNS search domain
  --mtu N                   interface MTU
  --proxy URL               HTTP(S) proxy for the profile
  --mac keep|random|restore|AA:BB:...  MAC policy applied with the profile
  --yes                     skip confirmations
  --help, -h                this help

${C_BOLD}WHERE PROFILES LIVE${C_RESET}
  ${PROFILE_DIR}/<name>.conf

${C_YELLOW}⚠  Applying a profile reconfigures the interface immediately.${C_RESET}
  If you are connected over that interface, your session will drop. Apply
  profiles from a local console, or keep a second interface configured.
EOF
}

# --------------------------------------------------------------------------- #
# Arguments
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)      usage; exit 0 ;;
        --version|-V)   printf 'network_profile_manager %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -s|--save)      shift; ACTION="save"; NAME="${1:-}" ;;
        -a|--apply)     shift; ACTION="apply"; NAME="${1:-}" ;;
        -l|--list)      ACTION="list" ;;
        -c|--current)   ACTION="current" ;;
        --show)         shift; ACTION="show"; NAME="${1:-}" ;;
        -d|--delete)    shift; ACTION="delete"; NAME="${1:-}" ;;
        --export)       ACTION="export"
                        if [[ -n "${2:-}" && "${2:0:1}" != "-" ]]; then TARGET="$2"; shift; fi ;;
        --import)       shift; ACTION="import"; TARGET="${1:-}" ;;
        --set-static)   shift; ACTION="set-static"; NAME="${1:-}" ;;
        --set-dhcp)     shift; ACTION="set-dhcp"; NAME="${1:-}" ;;
        -i|--iface)     shift; IFACE="${1:-}" ;;
        --address)      shift; ADDRESS="${1:-}" ;;
        --gateway)      shift; GATEWAY="${1:-}" ;;
        --dns)          shift; DNS="${1:-}" ;;
        --search)       shift; SEARCH_DOMAIN="${1:-}" ;;
        --mtu)          shift; MTU="${1:-}" ;;
        --proxy)        shift; PROXY="${1:-}" ;;
        --mac)          shift; MAC_POLICY="${1:-keep}" ;;
        --yes|-y)       export CDECK_ASSUME_YES=1 ;;
        *)              cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

[[ -z "${ACTION}" ]] && { ACTION="current"; }

profile_file() { printf '%s/%s.conf' "${PROFILE_DIR}" "$1"; }

safe_name() {
    # Profile names become filenames: keep them boring
    printf '%s' "$1" | tr -c '[:alnum:]._-' '-' | sed 's/--*/-/g;s/^-//;s/-$//'
}

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
show_current() {
    cdeck::banner "current network" "$(hostname)"
    printf '\n  %sinterfaces%s\n' "${C_BOLD}" "${C_RESET}"
    ip -brief address 2>/dev/null | sed 's/^/    /' || ifconfig -a 2>/dev/null | sed 's/^/    /'
    printf '\n  %sroutes%s\n' "${C_BOLD}" "${C_RESET}"
    ip route show 2>/dev/null | sed 's/^/    /'
    printf '\n  %sresolvers%s\n' "${C_BOLD}" "${C_RESET}"
    if cdeck::has_cmd resolvectl; then
        resolvectl status 2>/dev/null | grep -E "DNS Server|Current DNS|DNS Domain" | sed 's/^/    /' | head -8
    fi
    if [[ -f /etc/resolv.conf ]]; then
        grep -E '^(nameserver|search)' /etc/resolv.conf | sed 's/^/    /'
    fi
    printf '\n  %swifi%s\n' "${C_BOLD}" "${C_RESET}"
    if cdeck::has_cmd iw; then
        local iface
        for iface in $(cdeck::wlan_interfaces); do
            printf '    %-10s %s · %s · %s\n' "${iface}" \
                "$(iw dev "${iface}" info 2>/dev/null | awk '/ssid/ {print $2}')" \
                "$(iw dev "${iface}" info 2>/dev/null | awk '/channel/ {print $2 " ch"}')" \
                "$(cat "/sys/class/net/${iface}/address" 2>/dev/null)"
        done
    fi
    printf '\n  %sproxy environment%s\n' "${C_BOLD}" "${C_RESET}"
    local variable
    for variable in http_proxy https_proxy ftp_proxy no_proxy; do
        [[ -n "${!variable:-}" ]] && printf '    %-12s %s\n' "${variable}" "${!variable}"
    done
    printf '\n'
    local saved=0
    if [[ -d "${PROFILE_DIR}" ]]; then
        saved="$(find "${PROFILE_DIR}" -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l | tr -d ' ')"
    fi
    cdeck::info "${saved} saved profile(s) in ${PROFILE_DIR}"
    cdeck::info "save this setup with: $0 --save <name>"
    return 0
}

list_profiles() {
    cdeck::banner "network profiles" "${PROFILE_DIR}"
    if [[ ! -d "${PROFILE_DIR}" ]] || [[ -z "$(find "${PROFILE_DIR}" -maxdepth 1 -name '*.conf' 2>/dev/null)" ]]; then
        cdeck::info "no profiles saved yet"
        cdeck::info "create one with: $0 --save <name>   or   $0 --set-static <name> --address 10.0.0.5/24"
        return 0
    fi
    printf '\n  %-22s %-10s %-20s %-16s %s\n' "PROFILE" "IFACE" "ADDRESS" "GATEWAY" "SAVED"
    local file name iface address gateway saved
    while IFS= read -r file; do
        [[ -z "${file}" ]] && continue
        name="$(basename "${file}" .conf)"
        iface="$(awk -F= '/^iface=/ {print $2}' "${file}")"
        address="$(awk -F= '/^address=/ {print $2}' "${file}")"
        gateway="$(awk -F= '/^gateway=/ {print $2}' "${file}")"
        saved="$(awk -F= '/^saved=/ {print $2}' "${file}")"
        printf '  %-22s %-10s %-20s %-16s %s\n' "${name}" "${iface:-auto}" \
            "${address:-dhcp}" "${gateway:--}" "${saved:--}"
    done < <(find "${PROFILE_DIR}" -maxdepth 1 -name '*.conf' | sort)
    printf '\n'
    return 0
}

show_profile() {
    local file
    file="$(profile_file "${NAME}")"
    [[ -f "${file}" ]] || { cdeck::error "no such profile: ${NAME}"; return 1; }
    cdeck::banner "profile: ${NAME}" "${file}"
    printf '\n'
    sed 's/^/    /' "${file}"
    printf '\n'
    return 0
}

# --------------------------------------------------------------------------- #
# Saving
# --------------------------------------------------------------------------- #
save_profile() {
    local name="${1:-}"
    [[ -z "${name}" ]] && { cdeck::error "--save needs a name"; return 2; }
    name="$(safe_name "${name}")"
    mkdir -p "${PROFILE_DIR}"
    local file; file="$(profile_file "${name}")"
    if [[ -f "${file}" ]]; then
        cdeck::confirm "Profile ${name} exists - overwrite it?" n || return 0
    fi

    # Work out which interface actually carries the default route
    local primary
    primary="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    [[ -z "${primary}" ]] && primary="$(cdeck::conf_get network.primary_interface eth0)"

    local mode="dhcp" address="" gateway="" dns="" search="" mtu="" mac
    address="$(ip -4 -o addr show "${primary}" 2>/dev/null | awk '{print $4}' | head -1)"
    gateway="$(ip route show default dev "${primary}" 2>/dev/null | awk '/default/ {print $3; exit}')"
    mtu="$(cat "/sys/class/net/${primary}/mtu" 2>/dev/null)"
    mac="$(cdeck::iface_mac "${primary}")"
    [[ -n "${address}" && -n "${gateway}" ]] && mode="static"
    if [[ "${mode}" == "static" ]]; then
        # A DHCP lease also shows an address; detect it via the NM/dhclient markers
        if cdeck::has_cmd nmcli && nmcli -t -f IP4.METHOD dev show "${primary}" 2>/dev/null | grep -q "auto"; then
            mode="dhcp"
        elif [[ -f "/var/lib/dhcp/dhclient.${primary}.leases" ]] || \
             [[ -f "/var/lib/NetworkManager/dhclient-${primary}.lease" ]]; then
            mode="dhcp"
        fi
    fi
    dns="$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | paste -sd' ' -)"
    search="$(awk '/^search/ {$1=""; print}' /etc/resolv.conf 2>/dev/null | head -1 | sed 's/^ *//')"

    cat > "${file}" <<EOF
# cyberdeck-arsenal network profile
# saved by network_profile_manager.sh
name=${name}
saved=$(date -Is)
host=$(hostname)
iface=${primary}
mode=${mode}
address=${address}
gateway=${gateway}
dns=${dns}
search=${search}
mtu=${mtu:-1500}
mac=${mac}
mac_policy=keep
proxy=${http_proxy:-}
routes=$(ip route show dev "${primary}" 2>/dev/null | tr '\n' ';' )
EOF
    chmod 0600 "${file}"
    cdeck::ok "profile saved: ${file}"
    cdeck::info "mode=${mode} iface=${primary} address=${address:-dhcp} gateway=${gateway:-none}"
    cdeck::info "apply it later with: $0 --apply ${name}"
    log_event "profile saved: ${name}" INFO
    return 0
}

write_profile() {
    # write_profile <name> <mode>
    local name mode
    name="$(safe_name "${1:-}")"
    mode="${2:-dhcp}"
    [[ -z "${name}" ]] && { cdeck::error "a profile name is required"; return 2; }
    if [[ "${mode}" == "static" && -z "${ADDRESS}" ]]; then
        cdeck::error "--set-static needs --address (for example 10.10.10.50/24)"
        return 2
    fi
    if [[ -n "${ADDRESS}" && "${ADDRESS}" != */* ]]; then
        cdeck::warn "${ADDRESS} has no prefix length - assuming /24"
        ADDRESS="${ADDRESS}/24"
    fi
    [[ -z "${GATEWAY}" && "${mode}" == "static" ]] && {
        # Derive .1 of the same subnet as a sensible default
        local network="${ADDRESS%.*}"
        GATEWAY="${network}.1"
        cdeck::info "no gateway given - using ${GATEWAY}"
    }
    if [[ -z "${DNS}" ]]; then
        DNS="${DEFAULT_DNS:-1.1.1.1 9.9.9.9}"
    fi

    mkdir -p "${PROFILE_DIR}"
    local file; file="$(profile_file "${name}")"
    cat > "${file}" <<EOF
# cyberdeck-arsenal network profile
# created by network_profile_manager.sh --set-${mode}
name=${name}
saved=$(date -Is)
host=$(hostname)
iface=${IFACE}
mode=${mode}
address=${ADDRESS}
gateway=${GATEWAY}
dns=${DNS}
search=${SEARCH_DOMAIN}
mtu=${MTU:-1500}
mac=
mac_policy=${MAC_POLICY}
proxy=${PROXY}
routes=
EOF
    chmod 0600 "${file}"
    cdeck::ok "profile written: ${file}"
    cdeck::info "apply it with: $0 --apply ${name}"
    return 0
}

# --------------------------------------------------------------------------- #
# Applying
# --------------------------------------------------------------------------- #
apply_profile() {
    local name; name="$(safe_name "${1:-}")"
    local file; file="$(profile_file "${name}")"
    [[ -f "${file}" ]] || { cdeck::error "no such profile: ${name}"; return 1; }

    local iface mode address gateway dns search mtu mac_policy proxy
    iface="$(awk -F= '/^iface=/ {print $2}' "${file}")"
    mode="$(awk -F= '/^mode=/ {print $2}' "${file}")"
    address="$(awk -F= '/^address=/ {print $2}' "${file}")"
    gateway="$(awk -F= '/^gateway=/ {print $2}' "${file}")"
    dns="$(awk -F= '/^dns=/ {print $2}' "${file}")"
    search="$(awk -F= '/^search=/ {print $2}' "${file}")"
    mtu="$(awk -F= '/^mtu=/ {print $2}' "${file}")"
    mac_policy="$(awk -F= '/^mac_policy=/ {print $2}' "${file}")"
    proxy="$(awk -F= '/^proxy=/ {print $2}' "${file}")"

    [[ -z "${iface}" || ! -d "/sys/class/net/${iface}" ]] && {
        cdeck::error "profile targets ${iface:-an unknown interface}, which is not present"
        cdeck::info "available: $(cdeck::interfaces | tr '\n' ' ')"
        return 1
    }

    cdeck::banner "applying profile" "${name} → ${iface}"
    cdeck::warn "the interface will be reconfigured - an SSH session over it would drop"
    cdeck::confirm "Apply profile ${name} to ${iface}?" y || return 0

    # MAC policy first: changing it later would invalidate any DHCP lease
    case "${mac_policy}" in
        random)
            local rotator="${INSTALL_DIR}/utilities/mac_rotator.py"
            [[ -f "${rotator}" ]] && python3 "${rotator}" --rotate -i "${iface}" --quiet || \
                cdeck::warn "mac_rotator.py not found - leaving the MAC alone"
            ;;
        restore)
            local rotator="${INSTALL_DIR}/utilities/mac_rotator.py"
            [[ -f "${rotator}" ]] && python3 "${rotator}" --restore -i "${iface}" --quiet || true
            ;;
        keep|"") : ;;
        *) cdeck::warn "unsupported mac_policy '${mac_policy}' - leaving the MAC alone" ;;
    esac

    local applied=0
    if cdeck::has_cmd nmcli; then
        local connection
        connection="$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null \
            | awk -F: -v dev="${iface}" '$2 == dev {print $1; exit}')"
        if [[ -z "${connection}" ]]; then
            connection="$(nmcli -t -f NAME connection show 2>/dev/null | head -1)"
        fi
        if [[ -n "${connection}" ]]; then
            if [[ "${mode}" == "static" ]]; then
                nmcli connection modify "${connection}" \
                    ipv4.method manual ipv4.addresses "${address}" \
                    ipv4.gateway "${gateway}" \
                    ipv4.dns "${dns// /,}" ${search:+ipv4.dns-search "${search}"} \
                    ${mtu:+802-3-ethernet.mtu "${mtu}"} >/dev/null 2>&1 \
                    && applied=1
            else
                nmcli connection modify "${connection}" \
                    ipv4.method auto ipv4.addresses "" ipv4.gateway "" \
                    ipv4.dns "${dns// /,}" ${mtu:+802-3-ethernet.mtu "${mtu}"} >/dev/null 2>&1 \
                    && applied=1
            fi
            if (( applied )); then
                nmcli connection down "${connection}" >/dev/null 2>&1 || true
                if nmcli connection up "${connection}" >/dev/null 2>&1; then
                    cdeck::ok "NetworkManager applied ${name} to ${iface}"
                else
                    cdeck::warn "NetworkManager could not bring ${connection} up - falling back to ip"
                    applied=0
                fi
            fi
        fi
    fi

    if (( applied == 0 )); then
        cdeck::info "configuring ${iface} directly with ip"
        ip link set "${iface}" up
        [[ -n "${mtu}" ]] && ip link set "${iface}" mtu "${mtu}" 2>/dev/null || true
        if [[ "${mode}" == "static" ]]; then
            ip -4 addr flush dev "${iface}" 2>/dev/null || true
            if ip addr add "${address}" dev "${iface}"; then
                cdeck::ok "address ${address} assigned"
            else
                cdeck::error "could not assign ${address} to ${iface}"
                return 1
            fi
        else
            ip -4 addr flush dev "${iface}" 2>/dev/null || true
            local leased=0 client
            for client in "dhcpcd -n ${iface}" "dhclient -1 ${iface}" "udhcpc -i ${iface} -n -q"; do
                if cdeck::has_cmd "${client%% *}"; then
                    cdeck::info "requesting a lease: ${client}"
                    if ${client} >/dev/null 2>&1; then
                        leased=1
                        break
                    fi
                fi
            done
            (( leased )) || cdeck::warn "no DHCP client succeeded - check the link and the network"
        fi
        if [[ "${mode}" == "static" && -n "${gateway}" ]]; then
            ip route replace default via "${gateway}" dev "${iface}" 2>/dev/null \
                && cdeck::ok "default route via ${gateway}" \
                || cdeck::warn "could not set the default route via ${gateway}"
        fi
    fi

    # --- DNS --------------------------------------------------------------- #
    if [[ -n "${dns}" ]]; then
        if cdeck::has_cmd resolvectl; then
            # shellcheck disable=SC2086 - the list is intentionally split
            resolvectl dns "${iface}" ${dns} 2>/dev/null && cdeck::ok "resolvers set: ${dns}"
            [[ -n "${search}" ]] && resolvectl domain "${iface}" "${search}" 2>/dev/null || true
        fi
        if [[ -w /etc/resolv.conf || "${EUID}" -eq 0 ]]; then
            local backup="/etc/resolv.conf.cyberdeck.$(date +%Y%m%d%H%M%S)"
            [[ -f /etc/resolv.conf && ! -f "${backup}" ]] && cp -a /etc/resolv.conf "${backup}" 2>/dev/null || true
            if [[ ! -L /etc/resolv.conf ]]; then
                {
                    printf '# written by network_profile_manager.sh (%s)\n' "$(date -Is)"
                    for resolver in ${dns}; do printf 'nameserver %s\n' "${resolver}"; done
                    [[ -n "${search}" ]] && printf 'search %s\n' "${search}"
                } > /etc/resolv.conf
                cdeck::ok "/etc/resolv.conf updated (backup: ${backup})"
            else
                cdeck::info "/etc/resolv.conf is managed by systemd-resolved - leaving it alone"
            fi
        fi
    fi

    # --- proxy ------------------------------------------------------------- #
    if [[ -n "${proxy}" ]]; then
        local profile_sh="${PROFILE_DIR}/${name}.env"
        cat > "${profile_sh}" <<EOF
# proxy environment for the '${name}' network profile
export http_proxy="${proxy}"
export https_proxy="${proxy}"
export HTTP_PROXY="${proxy}"
export HTTPS_PROXY="${proxy}"
export no_proxy="localhost,127.0.0.1,::1,.local"
EOF
        chmod 0600 "${profile_sh}"
        cdeck::ok "proxy environment written: ${profile_sh}"
        cdeck::info "load it with: source ${profile_sh}"
    fi

    printf '\n'
    cdeck::ok "profile '${name}' applied"
    printf '    %-10s %s\n' "interface" "${iface}"
    printf '    %-10s %s\n' "mode" "${mode}"
    printf '    %-10s %s\n' "address" "$(ip -4 -o addr show "${iface}" | awk '{print $4}' | paste -sd, -)"
    printf '    %-10s %s\n' "gateway" "$(ip route show default | awk '{print $3}' | paste -sd, -)"
    printf '    %-10s %s\n' "resolvers" "${dns:-unchanged}"
    printf '\n'
    log_event "profile applied: ${name} to ${iface}" INFO
    return 0
}

# --------------------------------------------------------------------------- #
# Delete / export / import
# --------------------------------------------------------------------------- #
delete_profile() {
    local name; name="$(safe_name "${1:-}")"
    local file; file="$(profile_file "${name}")"
    [[ -f "${file}" ]] || { cdeck::error "no such profile: ${name}"; return 1; }
    cdeck::confirm "Delete profile ${name}?" n || return 0
    rm -f "${file}" "${PROFILE_DIR}/${name}.env"
    cdeck::ok "deleted ${name}"
    return 0
}

export_profiles() {
    local destination="${TARGET:-$(pwd)}"
    [[ -d "${destination}" ]] || { cdeck::error "no such directory: ${destination}"; return 1; }
    if [[ -z "$(find "${PROFILE_DIR}" -maxdepth 1 -name '*.conf' 2>/dev/null)" ]]; then
        cdeck::warn "no profiles to export"
        return 1
    fi
    local target_dir="${destination}/cyberdeck-profiles"
    mkdir -p "${target_dir}"
    cp -a "${PROFILE_DIR}"/*.conf "${target_dir}/" 2>/dev/null
    chmod 0600 "${target_dir}"/*.conf 2>/dev/null || true
    local count; count="$(find "${target_dir}" -name '*.conf' | wc -l | tr -d ' ')"
    cdeck::ok "exported ${count} profile(s) to ${target_dir}"
    cdeck::warn "profiles may contain private addressing and proxy credentials - move them securely"
    return 0
}

import_profiles() {
    local source="${1:-}"
    [[ -e "${source}" ]] || { cdeck::error "no such file or directory: ${source:-<none>}"; return 1; }
    mkdir -p "${PROFILE_DIR}"
    if [[ -d "${source}" ]]; then
        cp -a "${source}"/*.conf "${PROFILE_DIR}/" 2>/dev/null || {
            cdeck::error "no .conf files found in ${source}"; return 1; }
    elif [[ "${source}" == *.tar* ]]; then
        tar -xzf "${source}" -C /tmp 2>/dev/null || { cdeck::error "could not read ${source}"; return 1; }
        local extracted
        extracted="$(find /tmp -maxdepth 2 -name '*.conf' -newer "${source}" 2>/dev/null | head -1)"
        if [[ -z "${extracted}" ]]; then
            cdeck::error "the archive contains no .conf profiles"; return 1
        fi
        cp -a "$(dirname "${extracted}")"/*.conf "${PROFILE_DIR}/" 2>/dev/null
    elif [[ "${source}" == *.conf ]]; then
        cp -a "${source}" "${PROFILE_DIR}/"
    else
        cdeck::error "unsupported import source: ${source} (expected a directory, .tar.gz or .conf)"
        return 1
    fi
    local count; count="$(find "${PROFILE_DIR}" -maxdepth 1 -name '*.conf' | wc -l | tr -d ' ')"
    cdeck::ok "import complete - ${count} profile(s) available"
    list_profiles
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
        db.event("network_profile_manager", "network", sys.argv[1], sys.argv[2])
except Exception:
    pass
PYEOF
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
mkdir -p "${PROFILE_DIR}"
chmod 0700 "${PROFILE_DIR}" 2>/dev/null || true

case "${ACTION}" in
    list)        list_profiles; exit $? ;;
    current)     show_current; exit $? ;;
    show)        show_profile; exit $? ;;
    save)        cdeck::require_root "saving the network configuration" || exit 1
                 save_profile "${NAME}"; exit $? ;;
    set-static)  cdeck::require_root "writing a static profile" || exit 1
                 write_profile "${NAME}" static; exit $? ;;
    set-dhcp)    cdeck::require_root "writing a DHCP profile" || exit 1
                 write_profile "${NAME}" dhcp; exit $? ;;
    apply)       cdeck::require_root "applying a network profile" || exit 1
                 apply_profile "${NAME}"; exit $? ;;
    delete)      delete_profile "${NAME}"; exit $? ;;
    export)      export_profiles; exit $? ;;
    import)      import_profiles "${TARGET}"; exit $? ;;
    *)
        cdeck::error "unknown action: ${ACTION}"
        usage
        exit 2
        ;;
esac
