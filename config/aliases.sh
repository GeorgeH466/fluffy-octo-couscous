#!/usr/bin/env bash
# =============================================================================
# config/aliases.sh - cyberdeck-arsenal shell aliases and helper functions
# =============================================================================
#
# Description
# -----------
# Every cyberdeck entry point expressed as a short alias, plus a handful of
# shell functions for the workflows that need arguments. Sourced by
# config/bashrc_cyberdeck, which setup.sh installs as /etc/profile.d/… so the
# aliases are available to every interactive shell on the deck.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash, the cyberdeck-arsenal install at /opt/cyberdeck-arsenal
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Notes
# -----
# * Aliases pointing at `cdeck` cover the common case; the functions below add
#   argument handling (`scan`, `profile`, `recon`, `deck-status`).
# * Nothing here touches the network by itself - these are conveniences only.
# =============================================================================

# Guard against double sourcing
[[ -n "${CYBERDECK_ALIASES_SOURCED:-}" ]] && return 0
CYBERDECK_ALIASES_SOURCED=1

CDECK_INSTALL_DIR="${CDECK_INSTALL_DIR:-${CYBERDECK_INSTALL_DIR:-/opt/cyberdeck-arsenal}}"
CDECK_VENV="${CDECK_INSTALL_DIR}/venv"
CDECK_PY="${CDECK_VENV}/bin/python3"
[[ -x "${CDECK_PY}" ]] || CDECK_PY="$(command -v python3 || echo python3)"

# --------------------------------------------------------------------------- #
# Short names for the launcher
# --------------------------------------------------------------------------- #
alias cyberdeck='cdeck'
alias deck='cdeck dashboard'

# --------------------------------------------------------------------------- #
# Dashboards
# --------------------------------------------------------------------------- #
alias hud='cdeck dashboard'
alias deck-hud='cdeck dashboard'
alias packets='cdeck packets'
alias packet-weather='cdeck packets'
alias threats='cdeck threats'
alias threat-ticker='cdeck threats'
alias netmap='cdeck netmap'
alias network-map='cdeck netmap'
alias rf='cdeck rf'
alias rf-spectrum='cdeck rf'
alias spectrum='cdeck rf'

# --------------------------------------------------------------------------- #
# Recon
# --------------------------------------------------------------------------- #
alias surveys='cdeck services'
alias services='cdeck services'
alias probe-log='${CDECK_PY} ${CDECK_INSTALL_DIR}/recon/passive/wifi_probe_logger.py'
alias ble='${CDECK_PY} ${CDECK_INSTALL_DIR}/recon/passive/ble_scanner.py'
alias arpmap='${CDECK_PY} ${CDECK_INSTALL_DIR}/recon/passive/arp_mapper.py'
alias rogue='${CDECK_PY} ${CDECK_INSTALL_DIR}/recon/passive/rogue_ap_detector.py --watch'
alias osint='${CDECK_PY} ${CDECK_INSTALL_DIR}/recon/active/osint_gatherer.py'

scan()                 { cdeck scan "$@"; }
profile()              { cdeck profile "$@"; }
recon()                { cdeck scan "$1" && cdeck profile "$1"; }
wifi-scan()            { cdeck wifi "$@"; }
webscan()              { "${CDECK_INSTALL_DIR}/recon/active/web_recon.sh" "$@"; }
netscan()              { "${CDECK_INSTALL_DIR}/recon/active/network_scanner.sh" "$@"; }

# --------------------------------------------------------------------------- #
# Attack (all of these are loud: read the legal warning first)
# --------------------------------------------------------------------------- #
alias arsonal='sudo ${CDECK_INSTALL_DIR}/attack/wifi_arsenal.sh'
alias wifiar='sudo ${CDECK_INSTALL_DIR}/attack/wifi_arsenal.sh'
alias responder='sudo ${CDECK_INSTALL_DIR}/attack/responder_launcher.sh'
alias mitm='sudo ${CDECK_INSTALL_DIR}/attack/mitm_toolkit.sh'
alias payloads='${CDECK_PY} ${CDECK_INSTALL_DIR}/attack/payload_server.py'
alias payload-recipes='${CDECK_PY} ${CDECK_INSTALL_DIR}/attack/payload_server.py --recipes'

# --------------------------------------------------------------------------- #
# Utilities
# --------------------------------------------------------------------------- #
alias rotmac='sudo ${CDECK_PY} ${CDECK_INSTALL_DIR}/utilities/mac_rotator.py'
alias vpn='sudo ${CDECK_INSTALL_DIR}/utilities/vpn_switcher.sh'
alias vault='sudo ${CDECK_INSTALL_DIR}/utilities/encrypted_vault.sh'
alias usb='sudo ${CDECK_PY} ${CDECK_INSTALL_DIR}/utilities/usb_handler.py'
alias panic='sudo ${CDECK_INSTALL_DIR}/utilities/self_destruct.sh'
alias profiles='sudo ${CDECK_INSTALL_DIR}/utilities/network_profile_manager.sh'
alias hardware='cdeck hardware'
alias hwd='cdeck hardware'

# --------------------------------------------------------------------------- #
# SDR
# --------------------------------------------------------------------------- #
alias sdr='${CDECK_PY} ${CDECK_INSTALL_DIR}/sdr/sdr_scanner.py'
alias adsb='${CDECK_PY} ${CDECK_INSTALL_DIR}/sdr/adsb_tracker.py'
alias pager='${CDECK_PY} ${CDECK_INSTALL_DIR}/sdr/pager_decoder.py'
alias tpms='${CDECK_PY} ${CDECK_INSTALL_DIR}/sdr/tpms_monitor.py'
alias keyfob='${CDECK_PY} ${CDECK_INSTALL_DIR}/sdr/keyfob_analyzer.py'

# --------------------------------------------------------------------------- #
# Automation, GPIO, aesthetics
# --------------------------------------------------------------------------- #
alias triggers='${CDECK_PY} ${CDECK_INSTALL_DIR}/automation/triggers.py'
alias scheduler='${CDECK_PY} ${CDECK_INSTALL_DIR}/automation/scheduler.py'
alias jobs='${CDECK_PY} ${CDECK_INSTALL_DIR}/automation/scheduler.py --list'
alias leds='${CDECK_PY} ${CDECK_INSTALL_DIR}/gpio/led_controller.py'
alias buttons='${CDECK_PY} ${CDECK_INSTALL_DIR}/gpio/button_handler.py'
alias oled='${CDECK_PY} ${CDECK_INSTALL_DIR}/gpio/oled_display.py'
alias bootsplash='sudo ${CDECK_INSTALL_DIR}/aesthetic/boot_splash.sh'
alias motd='${CDECK_INSTALL_DIR}/aesthetic/motd.sh'
alias theme='sudo ${CDECK_INSTALL_DIR}/aesthetic/theme_switcher.sh'
alias hollywood='${CDECK_INSTALL_DIR}/aesthetic/decoy/hollywood_mode.sh'
alias fakedesktop='${CDECK_INSTALL_DIR}/aesthetic/decoy/fake_desktop.sh'

# --------------------------------------------------------------------------- #
# Reporting, evidence and health
# --------------------------------------------------------------------------- #
alias report='${CDECK_PY} ${CDECK_INSTALL_DIR}/recon/reporting/report_generator.py'
alias hash='${CDECK_PY} ${CDECK_INSTALL_DIR}/recon/reporting/evidence_hasher.py'
alias hashfile='${CDECK_PY} ${CDECK_INSTALL_DIR}/recon/reporting/evidence_hasher.py --shallow'
alias reportdir='cd "${CDECK_INSTALL_DIR}/reports" || true'
alias caps='cd "${CDECK_INSTALL_DIR}/captures" || true'
alias decklog='tail -f "${CDECK_INSTALL_DIR}/logs/cyberdeck.log"'
alias stats='cdeck status'
alias cdeckcheck='cdeck doctor'
alias selftest='cdeck doctor --full'

# --------------------------------------------------------------------------- #
# Small functions that need argument handling
# --------------------------------------------------------------------------- #
# report <engagement-dir> [formats]
report_build() {
    local directory="${1:-.}" formats="${2:-md,html,exec}"
    "${CDECK_PY}" "${CDECK_INSTALL_DIR}/recon/reporting/report_generator.py" \
        "${directory}" --formats "${formats}"
}

# capture <interface> [seconds]
capture() {
    local iface="${1:-$(cdeck status --json 2>/dev/null | "$(command -v jq || echo cat)" -r '.interfaces[0].name' 2>/dev/null)}"
    local seconds="${2:-60}"
    local out="${CDECK_INSTALL_DIR}/captures/manual_$(date +%Y%m%d_%H%M%S).pcap"
    [[ -z "${iface}" ]] && { echo "usage: capture <interface> [seconds]"; return 2; }
    sudo tcpdump -i "${iface}" -U -w "${out}" -G "${seconds}" -W 1 -z true && \
        echo "captured to ${out}"
}

# listen <port> - quick TCP listener that logs to the captures directory
listen() {
    local port="${1:-4444}"
    local log="${CDECK_INSTALL_DIR}/captures/listener_${port}_$(date +%Y%m%d_%H%M%S).log"
    echo "listening on 0.0.0.0:${port} (log: ${log}) - Ctrl-C to stop"
    nc -lvnp "${port}" 2>&1 | tee "${log}"
}

# deck-status - one-line summary for prompt/status scripts
deck-status() { cdeck status --oneline 2>/dev/null || cdeck status; }

# deck-help - cheat sheet of everything above
deck-help() {
    cat <<'EOF'

  cyberdeck-arsenal quick reference
  ─────────────────────────────────
  dashboards      hud · packets · threats · netmap · rf
  recon           scan <target> · profile <target> · wifi-scan · surveys
                  ble · arpmap · rogue · osint <target>
  attack          arsonal · responder · mitm · payloads        (sudo, authorised only)
  utilities       rotmac · vpn · vault · usb · panic · profiles · hardware
  sdr             sdr · adsb · pager · tpms · keyfob
  automation      triggers · scheduler · jobs
  gpio            leds · buttons · oled
  reports         report_build <dir> · hash <path> · reportdir · caps
  health          cdeck status · cdeckcheck · selftest

  full documentation: /opt/cyberdeck-arsenal/docs/QUICKSTART.md
  legal notice      : /opt/cyberdeck-arsenal/docs/LEGAL.md

EOF
}
alias cheat='deck-help'

# Friendly banner when a shell starts (only for interactive logins, only once)
if [[ $- == *i* && -z "${CYBERDECK_BANNER_SHOWN:-}" ]]; then
    export CYBERDECK_BANNER_SHOWN=1
    if [[ -x "${CDECK_INSTALL_DIR}/aesthetic/motd.sh" && "${CYBERDECK_QUIET_BANNER:-0}" != "1" ]]; then
        "${CDECK_INSTALL_DIR}/aesthetic/motd.sh" --short 2>/dev/null || true
    fi
fi
