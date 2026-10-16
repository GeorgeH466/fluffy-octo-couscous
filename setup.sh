#!/usr/bin/env bash
# =============================================================================
# cyberdeck-arsenal :: setup.sh - master installer / uninstaller
# =============================================================================
#
# Description
# -----------
# Turns a base BlackArch (or Arch) Linux installation into a complete
# cyberdeck operations platform: offensive toolchain, passive/active recon
# modules, TUI dashboards, SDR tooling, automation engine, systemd services,
# wordlists, databases and a `cdeck` entry point.
#
# The script is:
#   * idempotent  - safe to run repeatedly, every step checks before acting
#   * resumable   - progress is tracked in /opt/cyberdeck-arsenal/state/setup.state
#   * logged      - everything goes to /opt/cyberdeck-arsenal/logs/setup.log
#   * granular    - --minimal for the core, --full for everything (SDR + GPIO)
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: Arch/BlackArch, bash>=5, pacman, python3, git, curl
# Licence     : MIT (see LICENSE). Authorised use only - see docs/LEGAL.md
#
# Usage
# -----
#   sudo ./setup.sh                 # standard install (asks for confirmation)
#   sudo ./setup.sh --minimal       # core toolchain + dashboards only
#   sudo ./setup.sh --full          # everything: SDR, GPIO, extra tooling
#   sudo ./setup.sh --yes           # non-interactive (accepts the legal notice)
#   sudo ./setup.sh --resume        # continue after an interruption
#   sudo ./setup.sh --uninstall     # remove everything this script installed
#
# =============================================================================

set -euo pipefail

# --------------------------------------------------------------------------- #
# Constants and paths
# --------------------------------------------------------------------------- #
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "${SCRIPT_PATH}")"

INSTALL_DIR="${CYBERDECK_INSTALL_DIR:-/opt/cyberdeck-arsenal}"
LOG_DIR="${INSTALL_DIR}/logs"
STATE_DIR="${INSTALL_DIR}/state"
STATE_FILE="${STATE_DIR}/setup.state"
SETUP_LOG="${LOG_DIR}/setup.log"
VENV_DIR="${INSTALL_DIR}/venv"
BACKUP_DIR="${INSTALL_DIR}/backups"
RECIPIENT_USER="${SUDO_USER:-${USER}}"
RECIPIENT_HOME="$(getent passwd "${RECIPIENT_USER}" 2>/dev/null | cut -d: -f6 || echo "${HOME}")"

MODE="standard"          # minimal | standard | full
ASSUME_YES=0
DRY_RUN=0
RESUME=0
SKIP_WORDLISTS=0
SKIP_HARDENING=0
UNINSTALL=0
FORCE_STEPS=()

# Package groups -------------------------------------------------------------
CORE_PACKAGES=(
    # Wireless / network attack surface
    aircrack-ng bettercap ettercap responder reaver bully wifite hcxtools hcxdumptool
    kismet macchanger wireshark-cli tcpdump tshark
    # Scanning / enumeration
    nmap masscan nikto gobuster dirb ffuf nuclei sqlmap wpscan
    whatweb wafw00f subfinder amass theharvester dnsrecon dnsutils whois bind-tools
    enum4linux smbclient impacket
    # Credentials / exploitation
    hashcat john hydra medusa metasploit exploitdb
    # Crypto / TLS
    sslscan testssl.sh openssl gnupg
    # Networking plumbing
    openvpn wireguard-tools tor proxychains-ng socat netcat gnu-netcat iptables-nft ufw fail2ban
    # RF / hardware
    rtl-sdr rtl_433 usbutils udevil exfatprogs ntfs-3g
    # Python / dev runtime
    python python-pip python-virtualenv python-setuptools git base-devel gcc make
    # Terminal ergonomics
    tmux screen zsh fish jq yq fzf bat ripgrep fd htop btop tree wget curl rsync unzip zip
    # Aesthetics
    figlet toilet lolcat cowsay cmatrix sl aalib
    # Python bindings needed by system tooling
    python-yaml python-requests python-psutil python-cryptography python-pillow
)

FULL_PACKAGES=(
    # SDR extras
    gqrx sdrangel urh inspectrum multimon-ng acarsdec
    # GPIO / embedded (Raspberry Pi)
    python-rpi.gpio i2c-tools python-smbus
    # NFC / RFID
    libnfc nfc-tools mfoc mfcuk
    # Extra offensive tooling
    feroxbuster dirsearch eyewitness cutycapt chromium gobuster-toolkit
    arp-scan ettercap-gtk macchanger
    # Forensics / analysis
    binwalk foremost sleuthkit autopsy radare2 ghidra
    # Misc quality of life
    zip p7zip pigz pv ncdu
)

MINIMAL_PACKAGES=(
    aircrack-ng nmap nikto gobuster tcpdump wireshark-cli macchanger
    python python-pip python-virtualenv git jq fzf bat ripgrep htop curl wget
    tmux figlet lolcat whois dnsutils usbutils
)

# BlackArch repository packages that may not exist on plain Arch
BLACKARCH_PACKAGES=(
    blackarch-keyring blackarch-mirrorlist bettercap responder wifite
    hcxtools hcxdumptool reaver bully theharvester
)

PYTHON_PACKAGES=(
    rich textual scapy bleak requests flask python-nmap netifaces psutil
    pyserial Pillow cryptography watchdog pyyaml graphviz
    paho-mqtt python-dateutil tabulate
)

SYSTEMD_SERVICES=(
    cyberdeck-monitor.service mac-rotator.service mac-rotator.timer
    probe-logger.service ble-scanner.service rogue-ap-detector.service
    usb-watcher.service
)
# Enabled but never auto-started by the installer (intrusive by nature)
INTRUSIVE_SERVICES=()

DATABASES=(events probes ble arp services baseline usb alerts payloads)

# --------------------------------------------------------------------------- #
# Colours, logging, output helpers
# --------------------------------------------------------------------------- #
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'
    MAGENTA=$'\033[35m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; DIM=""; RESET=""
fi

WARNINGS=()
ERRORS=()

log_write() {
    local level="$1"; shift
    printf '%s %-8s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${level}" "$*" >> "${SETUP_LOG}" 2>/dev/null || true
}

msg_info()  { printf '%b→%b %s\n' "${CYAN}"    "${RESET}" "$*"; log_write INFO "$*"; }
msg_ok()    { printf '%b✔%b %s\n' "${GREEN}"   "${RESET}" "$*"; log_write OK "$*"; }
msg_warn()  { printf '%b!%b %s\n' "${YELLOW}"  "${RESET}" "$*"; log_write WARNING "$*"; WARNINGS+=("$*"); }
msg_error() { printf '%b✘%b %s\n' "${RED}"     "${RESET}" "$*"; log_write ERROR "$*"; ERRORS+=("$*"); }
msg_debug() { [[ "${CYBERDECK_DEBUG:-0}" == "1" ]] && { printf '%b· %s%b\n' "${DIM}" "$*" "${RESET}"; log_write DEBUG "$*"; }; return 0; }
msg_step()  { printf '\n%b%s%b\n' "${BOLD}${BLUE}" "$*" "${RESET}"; log_write STEP "$*"; }

banner() {
    cat <<EOF
${CYAN}${BOLD}
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗██╗  ██╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║ ██╔╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║█████╗  ██║     █████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██╔══╝  ██║     ██╔═██╗
  ╚██████╗   ██║   ██████╔╝███████╗██████╔╝██████╔╝███████╗╚██████╗██║  ██╗
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝
${RESET}${MAGENTA}        A R S E N A L   ::   master installer v${SCRIPT_VERSION}${RESET}
${DIM}        BlackArch cyberdeck operations suite - authorised use only${RESET}
EOF
}

usage() {
    cat <<EOF
${BOLD}cyberdeck-arsenal installer${RESET}

${BOLD}USAGE${RESET}
  sudo ./setup.sh [OPTIONS]

${BOLD}OPTIONS${RESET}
  --minimal            Install the core toolchain only (no SDR/GPIO extras)
  --full               Install everything, including SDR, GPIO, forensics extras
  --yes, -y            Non-interactive: accept prompts and the legal notice
  --dry-run            Show what would be done without changing the system
  --resume             Continue from the last completed step
  --skip-wordlists     Do not download rockyou.txt / SecLists subsets
  --skip-hardening     Do not apply host firewall/SSH hardening
  --from-step N        Start at step N (1-12)
  --uninstall          Remove cyberdeck-arsenal and everything it installed
  --help, -h           Show this help
  --version, -V        Show the installer version

${BOLD}STEPS${RESET}
   1 preflight    Verify root, distro, connectivity, disk space, architecture
   2 update       pacman -Syu
   3 packages     Install BlackArch/Arch toolchain
   4 venv         Create Python virtualenv at ${VENV_DIR}
   5 directories  Create the runtime directory tree
   6 config       Install cyberdeck.conf, aliases, tmux, MOTD, cdeck
   7 services     Install and enable systemd units
   8 databases    Initialise SQLite databases + OUI/BLE databases
   9 wordlists    Download rockyou and SecLists subsets
  10 hardware     Detect and configure hardware
  11 hardening    Firewall, fail2ban, SSH hardening, permissions
  12 postinstall  Run tests, print summary, generate uninstall.sh

${BOLD}EXAMPLES${RESET}
  sudo ./setup.sh --full --yes
  sudo ./setup.sh --minimal && cdeck status
  sudo ./setup.sh --uninstall

${DIM}Log file: ${SETUP_LOG}${RESET}
EOF
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
parse_args() {
    while (( $# )); do
        case "$1" in
            --minimal)        MODE="minimal" ;;
            --full)           MODE="full" ;;
            --standard)       MODE="standard" ;;
            --yes|-y)         ASSUME_YES=1 ;;
            --dry-run)        DRY_RUN=1 ;;
            --resume)         RESUME=1 ;;
            --skip-wordlists) SKIP_WORDLISTS=1 ;;
            --skip-hardening) SKIP_HARDENING=1 ;;
            --from-step)      shift; FORCE_STEPS+=("step_${1}") ;;
            --reinstall-step) shift; FORCE_STEPS+=("step_${1}") ;;
            --uninstall)      UNINSTALL=1 ;;
            --help|-h)        usage; exit 0 ;;
            --version|-V)     echo "cyberdeck-arsenal setup ${SCRIPT_VERSION}"; exit 0 ;;
            *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
        esac
        shift
    done
}

# --------------------------------------------------------------------------- #
# State tracking (resume support)
# --------------------------------------------------------------------------- #
state_init() {
    mkdir -p "${STATE_DIR}" "${LOG_DIR}" 2>/dev/null || true
    [[ -f "${STATE_FILE}" ]] || : > "${STATE_FILE}"
}

state_done() {
    # state_done <step> -> true when the step already completed successfully
    (( RESUME == 0 )) && return 1
    grep -qxF "$1" "${STATE_FILE}" 2>/dev/null
}

state_mark() {
    grep -qxF "$1" "${STATE_FILE}" 2>/dev/null || echo "$1" >> "${STATE_FILE}"
    log_write STATE "completed $1"
}

state_completed_count() {
    if [[ -f "${STATE_FILE}" ]]; then wc -l < "${STATE_FILE}"; else echo 0; fi
}

run_step() {
    # run_step <function> <label>
    local fn="$1"; shift
    local label="$*"
    if state_done "${fn}"; then
        printf '%b•%b %s (already completed)\n' "${DIM}" "${RESET}" "${label}"
        return 0
    fi
    msg_step "▶ ${label}"
    if (( DRY_RUN == 1 )); then
        msg_warn "dry-run: skipping execution of ${fn}"
        return 0
    fi
    if "${fn}"; then
        state_mark "${fn}"
        msg_ok "${label} - done"
    else
        msg_error "${label} - failed"
        msg_warn "fix the issue and re-run with: sudo ${SCRIPT_NAME} --resume"
        return 1
    fi
}

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
have() { command -v "$1" >/dev/null 2>&1; }

ask_confirm() {
    # ask_confirm <prompt> [default]
    local prompt="$1" default="${2:-y}"
    (( ASSUME_YES == 1 )) && return 0
    [[ -t 0 ]] || return 0
    local reply
    if [[ "${default}" == "y" ]]; then
        read -r -p "${YELLOW}${prompt} [Y/n] ${RESET}" reply || true
        reply="${reply:-y}"
    else
        read -r -p "${YELLOW}${prompt} [y/N] ${RESET}" reply || true
        reply="${reply:-n}"
    fi
    [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]
}

disk_free_gb() {
    df -BG --output=avail "${1:-/}" 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0
}

package_available() {
    # package_available <pkg> - true when pacman can resolve the package
    pacman -Si "$1" >/dev/null 2>&1 || pacman -Ssq "^${1}$" 2>/dev/null | grep -qx "$1"
}

install_packages() {
    # install_packages <pkg...> - install available packages, report the rest
    local requested=("$@")
    local available=() missing=() to_install=()
    local pkg
    for pkg in "${requested[@]}"; do
        if package_available "${pkg}"; then
            available+=("${pkg}")
        else
            missing+=("${pkg}")
        fi
    done
    for pkg in "${available[@]}"; do
        pacman -Qq "${pkg}" >/dev/null 2>&1 || to_install+=("${pkg}")
    done
    if (( ${#missing[@]} )); then
        msg_warn "not available in configured repos: ${missing[*]}"
    fi
    if (( ${#to_install[@]} == 0 )); then
        msg_ok "all requested packages already installed"
        return 0
    fi
    msg_info "installing ${#to_install[@]} package(s)..."
    if ! pacman -S --needed --noconfirm --noprogressbar "${to_install[@]}" >> "${SETUP_LOG}" 2>&1; then
        # Retry one-by-one so a single broken package does not abort the run
        msg_warn "batch install failed - retrying individually"
        local failed=()
        for pkg in "${to_install[@]}"; do
            if pacman -S --needed --noconfirm --noprogressbar "${pkg}" >> "${SETUP_LOG}" 2>&1; then
                msg_debug "installed ${pkg}"
            else
                failed+=("${pkg}")
            fi
        done
        if (( ${#failed[@]} )); then
            msg_warn "packages not installed: ${failed[*]}"
            msg_info "these are optional; the suite degrades gracefully without them"
        fi
    else
        msg_ok "packages installed"
    fi
    return 0
}

write_state_json() {
    local path="${INSTALL_DIR}/state/install.json"
    mkdir -p "$(dirname "${path}")"
    cat > "${path}" <<EOF
{
  "suite": "cyberdeck-arsenal",
  "version": "${SCRIPT_VERSION}",
  "mode": "${MODE}",
  "installed_at": "$(date -Is)",
  "install_dir": "${INSTALL_DIR}",
  "venv": "${VENV_DIR}",
  "operator": "${RECIPIENT_USER}",
  "arch": "$(uname -m)",
  "distro": "$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)",
  "steps_completed": $(state_completed_count),
  "warnings": $(printf '%s\n' "${WARNINGS[@]:-}" | grep -c . || echo 0),
  "legal_notice_acknowledged": $( [[ -n "$(grep -c authorised_use_acknowledged: true "${INSTALL_DIR}/cyberdeck.conf" 2>/dev/null)" ]] && echo true || echo false)
}
EOF
    msg_debug "wrote ${path}"
}

# --------------------------------------------------------------------------- #
# STEP 1 - preflight
# --------------------------------------------------------------------------- #
step_preflight() {
    local failures=0

    # Root
    if [[ "${EUID}" -ne 0 ]]; then
        msg_error "must be run as root: sudo ${SCRIPT_NAME} $*"
        return 1
    fi
    msg_ok "running as root"

    # Distro
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        local distro_id="${ID:-unknown} ${ID_LIKE:-}"
        case "${distro_id}" in
            *blackarch*|*arch*)
                msg_ok "detected supported distribution: ${PRETTY_NAME:-${distro_id}}" ;;
            *debian*|*ubuntu*|*fedora*|*rhel*)
                msg_error "unsupported distribution: ${PRETTY_NAME:-${distro_id}}"
                msg_info "cyberdeck-arsenal targets BlackArch/Arch; use docker or a BlackArch ISO instead"
                failures=$(( failures + 1 )) ;;
            *)
                msg_warn "untested distribution '${PRETTY_NAME:-unknown}' - continuing, pacman is required"
                have pacman || { msg_error "pacman not found - this is not an Arch system"; failures=$(( failures + 1 )); } ;;
        esac
    else
        msg_error "/etc/os-release missing - cannot verify the distribution"
        failures=$(( failures + 1 ))
    fi

    have pacman || { msg_error "pacman not found"; return 1; }
    for tool in python3 git curl; do
        have "${tool}" || msg_warn "${tool} missing - it will be installed in step 3"
    done

    # Architecture
    local arch; arch="$(uname -m)"
    case "${arch}" in
        x86_64|aarch64|armv7l|armv6l) msg_ok "architecture: ${arch}" ;;
        *) msg_warn "untested architecture: ${arch}" ;;
    esac
    if [[ "${arch}" != "x86_64" ]]; then
        msg_info "non-x86 host detected: some tooling (metasploit, bettercap) may be limited"
    fi

    # Connectivity
    if curl -sSf -m 8 -o /dev/null https://blackarch.org 2>/dev/null \
        || curl -sSf -m 8 -o /dev/null https://archlinux.org 2>/dev/null; then
        msg_ok "internet connectivity verified"
    else
        msg_error "no internet connectivity - cannot install packages or wordlists"
        failures=$(( failures + 1 ))
    fi

    # Disk space
    local free_gb; free_gb="$(disk_free_gb /)"
    if (( free_gb < 10 )); then
        msg_warn "only ${free_gb}GB free on / - wordlists and tools need ~10GB (continuing)"
    else
        msg_ok "${free_gb}GB free on /"
    fi
    if (( free_gb < 3 )); then
        msg_error "insufficient disk space to continue safely"
        failures=$(( failures + 1 ))
    fi

    # BlackArch repository present?
    if grep -rqs 'blackarch' /etc/pacman.conf /etc/pacman.d/ 2>/dev/null; then
        msg_ok "BlackArch repository configuration found"
    else
        msg_warn "BlackArch repo not configured - core Arch packages only"
        msg_info "add it later with: curl -O https://blackarch.org/strap.sh && sudo bash strap.sh"
    fi

    # Summary and confirmation
    printf '\n'
    printf '%bInstallation plan (%s mode)%b\n' "${BOLD}" "${MODE}" "${RESET}"
    printf '  install dir : %s\n' "${INSTALL_DIR}"
    printf '  python venv : %s\n' "${VENV_DIR}"
    printf '  operator    : %s\n' "${RECIPIENT_USER}"
    case "${MODE}" in
        minimal)  printf '  packages    : %d core packages\n' "${#MINIMAL_PACKAGES[@]}" ;;
        standard) printf '  packages    : %d core packages (+%d optional BlackArch)\n' "${#CORE_PACKAGES[@]}" "${#BLACKARCH_PACKAGES[@]}" ;;
        full)     printf '  packages    : %d core + %d extra packages\n' "${#CORE_PACKAGES[@]}" "${#FULL_PACKAGES[@]}" ;;
    esac
    printf '  services    : %d systemd units (enabled, not started)\n' "${#SYSTEMD_SERVICES[@]}"
    printf '  wordlists   : %s\n' "$( (( SKIP_WORDLISTS == 1 )) && echo 'skipped' || echo 'rockyou + SecLists subsets' )"
    printf '  hardening   : %s\n' "$( (( SKIP_HARDENING == 1 )) && echo 'skipped' || echo 'UFW + fail2ban + SSH hardening' )"
    printf '\n'
    printf '%b⚠  LEGAL:%b this suite bundles offensive tooling. Use it only against systems and\n' "${YELLOW}${BOLD}" "${RESET}"
    printf '   networks you own or have explicit written authorisation to test.\n\n'

    if ! ask_confirm "Proceed with installation?" y; then
        msg_info "installation cancelled by operator"
        exit 0
    fi

    (( failures > 0 )) && { msg_error "pre-flight checks failed (${failures} problem(s))"; return 1; }
    msg_ok "pre-flight checks passed"
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 2 - system update
# --------------------------------------------------------------------------- #
step_update() {
    msg_info "refreshing package databases"
    if ! pacman -Sy --noconfirm >> "${SETUP_LOG}" 2>&1; then
        msg_warn "pacman -Sy failed (mirror/keyring problem?)"
        msg_info "attempting keyring refresh"
        pacman -Sy --noconfirm archlinux-keyring blackarch-keyring >> "${SETUP_LOG}" 2>&1 || true
        pacman -Sy --noconfirm >> "${SETUP_LOG}" 2>&1 || { msg_error "package database refresh failed"; return 1; }
    fi
    msg_info "upgrading installed packages (this can take a while)"
    if pacman -Su --noconfirm --noprogressbar >> "${SETUP_LOG}" 2>&1; then
        msg_ok "system up to date"
    else
        msg_warn "full system upgrade reported errors - see ${SETUP_LOG}"
        msg_info "continuing: a partial upgrade is usually still usable"
    fi
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 3 - packages
# --------------------------------------------------------------------------- #
step_packages() {
    local -a requested=()
    case "${MODE}" in
        minimal)  requested=("${MINIMAL_PACKAGES[@]}") ;;
        standard) requested=("${CORE_PACKAGES[@]}" "${BLACKARCH_PACKAGES[@]}") ;;
        full)     requested=("${CORE_PACKAGES[@]}" "${BLACKARCH_PACKAGES[@]}" "${FULL_PACKAGES[@]}") ;;
    esac

    install_packages "${requested[@]}"

    # Verify the tools whose package name differs from the command name
    local tool
    for tool in searchsploit msfconsole; do
        if have "${tool}"; then msg_ok "verified ${tool}"; else msg_warn "${tool} unavailable (install metasploit/exploitdb manually if needed)"; fi
    done
    have tshark || msg_warn "tshark missing - packet_weather.py will fall back to raw pcap parsing"
    have macchanger || msg_warn "macchanger missing - mac_rotator.py will use ip/iw directly (still works)"
    if [[ "${MODE}" == "full" ]]; then
        have gnuradio-companion || msg_warn "GNU Radio not installed (optional, large); SDR scripts work with rtl-sdr only"
    fi
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 4 - python virtualenv
# --------------------------------------------------------------------------- #
step_venv() {
    mkdir -p "${INSTALL_DIR}"
    if [[ ! -d "${VENV_DIR}" ]]; then
        msg_info "creating virtualenv at ${VENV_DIR}"
        python3 -m venv --system-site-packages "${VENV_DIR}" >> "${SETUP_LOG}" 2>&1 || {
            msg_error "venv creation failed (install python-virtualenv)"; return 1; }
    else
        msg_debug "venv already present"
    fi
    local pip="${VENV_DIR}/bin/pip"
    [[ -x "${pip}" ]] || { msg_error "pip missing inside venv"; return 1; }

    msg_info "upgrading pip/setuptools/wheel"
    "${pip}" install --quiet --upgrade pip setuptools wheel >> "${SETUP_LOG}" 2>&1 || msg_warn "pip self-upgrade failed"

    msg_info "installing Python dependencies (${#PYTHON_PACKAGES[@]} packages)"
    local pkg failed=()
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        if "${VENV_DIR}/bin/python" -m pip show "${pkg}" >/dev/null 2>&1; then
            msg_debug "${pkg} already installed"
            continue
        fi
        if ! "${pip}" install --quiet "${pkg}" >> "${SETUP_LOG}" 2>&1; then
            # Retry without the binary-only preference (some deps need to build)
            if ! "${pip}" install --quiet --no-binary :all: "${pkg}" >> "${SETUP_LOG}" 2>&1; then
                failed+=("${pkg}")
            fi
        fi
    done
    if (( ${#failed[@]} )); then
        msg_warn "python packages that failed to install: ${failed[*]}"
        msg_info "components needing them will report a clear error and continue"
    else
        msg_ok "all Python dependencies installed"
    fi

    # Verify critical modules
    local module
    for module in rich textual scapy requests flask psutil yaml; do
        if "${VENV_DIR}/bin/python" -c "import ${module}" 2>/dev/null; then
            msg_debug "python module ok: ${module}"
        else
            msg_warn "python module unavailable: ${module}"
        fi
    done
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 5 - directories
# --------------------------------------------------------------------------- #
step_directories() {
    local dir
    for dir in "${INSTALL_DIR}" "${INSTALL_DIR}/bin" "${INSTALL_DIR}/lib" \
               "${INSTALL_DIR}/config" "${INSTALL_DIR}/data" "${INSTALL_DIR}/data/wordlists" \
               "${INSTALL_DIR}/data/templates" "${INSTALL_DIR}/data/rf" \
               "${INSTALL_DIR}/logs" "${INSTALL_DIR}/captures" "${INSTALL_DIR}/reports" \
               "${INSTALL_DIR}/profiles" "${INSTALL_DIR}/vault" "${INSTALL_DIR}/state" \
               "${INSTALL_DIR}/dashboard" "${INSTALL_DIR}/recon" "${INSTALL_DIR}/attack" \
               "${INSTALL_DIR}/utilities" "${INSTALL_DIR}/sdr" "${INSTALL_DIR}/automation" \
               "${INSTALL_DIR}/gpio" "${INSTALL_DIR}/aesthetic" "${INSTALL_DIR}/tests" \
               "${INSTALL_DIR}/docs" "${BACKUP_DIR}"; do
        mkdir -p "${dir}"
    done
    msg_ok "runtime directory tree created under ${INSTALL_DIR}"

    # Copy the whole source tree (scripts are run from the install dir)
    if [[ "${SCRIPT_DIR}" != "${INSTALL_DIR}" ]]; then
        msg_info "copying suite source from ${SCRIPT_DIR} to ${INSTALL_DIR}"
        local item
        for item in bin lib config dashboard recon attack utilities sdr automation gpio \
                    aesthetic data tests docs README.md LICENSE setup.sh; do
            [[ -e "${SCRIPT_DIR}/${item}" ]] || continue
            if [[ -d "${SCRIPT_DIR}/${item}" ]]; then
                mkdir -p "${INSTALL_DIR}/${item}"
                cp -rT "${SCRIPT_DIR}/${item}" "${INSTALL_DIR}/${item}"
            else
                cp -f "${SCRIPT_DIR}/${item}" "${INSTALL_DIR}/${item}"
            fi
        done
    fi

    # Permissions: root-owned, group-readable by the operator's group
    chown -R root:"${RECIPIENT_USER}" "${INSTALL_DIR}" 2>/dev/null || true
    find "${INSTALL_DIR}" -type d -exec chmod 0750 {} + 2>/dev/null || true
    find "${INSTALL_DIR}" -type f -name '*.sh' -exec chmod 0750 {} + 2>/dev/null || true
    find "${INSTALL_DIR}" -type f -name '*.py' -exec chmod 0750 {} + 2>/dev/null || true
    chmod 0750 "${INSTALL_DIR}"/setup.sh 2>/dev/null || true
    chmod 0770 "${INSTALL_DIR}/vault" "${INSTALL_DIR}/captures" "${INSTALL_DIR}/logs" 2>/dev/null || true
    chmod 0600 "${INSTALL_DIR}/state"/* 2>/dev/null || true

    # Operator-writable engagement directories
    chown -R "${RECIPIENT_USER}":"${RECIPIENT_USER}" "${INSTALL_DIR}/vault" "${INSTALL_DIR}/reports" 2>/dev/null || true
    msg_ok "permissions applied"
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 6 - configuration
# --------------------------------------------------------------------------- #
step_config() {
    mkdir -p /etc/cyberdeck-arsenal

    # Master configuration
    if [[ -f "${INSTALL_DIR}/cyberdeck.conf" ]]; then
        cp -f "${INSTALL_DIR}/cyberdeck.conf" "${BACKUP_DIR}/cyberdeck.conf.$(date +%s).bak" 2>/dev/null || true
        msg_info "existing cyberdeck.conf preserved (backed up to ${BACKUP_DIR})"
    else
        cp -f "${SCRIPT_DIR}/config/cyberdeck.conf" "${INSTALL_DIR}/cyberdeck.conf"
        chmod 0600 "${INSTALL_DIR}/cyberdeck.conf"
        msg_ok "installed ${INSTALL_DIR}/cyberdeck.conf"
    fi
    ln -sf "${INSTALL_DIR}/cyberdeck.conf" /etc/cyberdeck-arsenal/cyberdeck.conf 2>/dev/null || true

    # Detect usable interfaces and write them into the config
    local primary monitor
    primary="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    monitor="$(for i in $(ls /sys/class/net 2>/dev/null); do [[ -d "/sys/class/net/$i/wireless" ]] && { echo "$i"; break; }; done)"
    if [[ -n "${primary}" ]]; then
        sed -i "s|^\(\s*primary_interface:\s*\).*|\1${primary}|" "${INSTALL_DIR}/cyberdeck.conf" 2>/dev/null || true
        msg_info "primary interface recorded as ${primary}"
    fi
    if [[ -n "${monitor}" && "${monitor}" != "${primary}" ]]; then
        sed -i "s|^\(\s*monitor_interface:\s*\).*|\1${monitor}|" "${INSTALL_DIR}/cyberdeck.conf" 2>/dev/null || true
        msg_info "monitor-capable interface recorded as ${monitor}"
    fi

    # Aliases + bashrc fragment
    install -m 0644 "${SCRIPT_DIR}/config/aliases.sh" "${INSTALL_DIR}/config/aliases.sh"
    install -m 0644 "${SCRIPT_DIR}/config/bashrc_cyberdeck" "${INSTALL_DIR}/config/bashrc_cyberdeck"

    local bashrc="${RECIPIENT_HOME}/.bashrc"
    if [[ -f "${bashrc}" ]] && ! grep -q 'cyberdeck-arsenal' "${bashrc}" 2>/dev/null; then
        {
            printf '\n# >>> cyberdeck-arsenal >>>\n'
            printf 'if [ -f %s/config/aliases.sh ]; then . %s/config/aliases.sh; fi\n' "${INSTALL_DIR}" "${INSTALL_DIR}"
            printf 'if [ -f %s/config/bashrc_cyberdeck ]; then . %s/config/bashrc_cyberdeck; fi\n' "${INSTALL_DIR}" "${INSTALL_DIR}"
            printf '# <<< cyberdeck-arsenal <<<\n'
        } >> "${bashrc}"
        chown "${RECIPIENT_USER}":"${RECIPIENT_USER}" "${bashrc}" 2>/dev/null || true
        msg_ok "shell integration appended to ${bashrc}"
    else
        msg_debug "shell integration already present or no .bashrc found"
    fi

    # tmux + conky
    install -m 0644 "${SCRIPT_DIR}/config/tmux.conf" "${RECIPIENT_HOME}/.tmux.conf.cyberdeck"
    install -m 0644 "${SCRIPT_DIR}/config/conky/cyberdeck_conky.conf" "${INSTALL_DIR}/config/conky/cyberdeck_conky.conf"
    msg_ok "tmux config installed as ~/.tmux.conf.cyberdeck (source it from ~/.tmux.conf)"

    # MOTD + boot splash
    install -m 0755 "${SCRIPT_DIR}/aesthetic/motd.sh" /etc/profile.d/cyberdeck-motd.sh
    chmod 0755 /etc/profile.d/cyberdeck-motd.sh
    msg_ok "MOTD installed at /etc/profile.d/cyberdeck-motd.sh"

    # `cdeck` entry point
    install -m 0755 "${SCRIPT_DIR}/bin/cdeck" "${INSTALL_DIR}/bin/cdeck"
    ln -sf "${INSTALL_DIR}/bin/cdeck" /usr/local/bin/cdeck
    ln -sf "${INSTALL_DIR}/bin/cdeck" /usr/local/bin/cyberdeck
    msg_ok "cdeck / cyberdeck commands installed in /usr/local/bin"

    # udev rules for USB monitoring
    mkdir -p /etc/udev/rules.d
    cat > /etc/udev/rules.d/99-cyberdeck-usb.rules <<'EOF'
# cyberdeck-arsenal :: notify the USB watcher and logger on device events
ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/bin/systemd-run --no-block --collect /opt/cyberdeck-arsenal/bin/cdeck-usb add %k"
ACTION=="remove", SUBSYSTEM=="usb", RUN+="/usr/bin/systemd-run --no-block --collect /opt/cyberdeck-arsenal/bin/cdeck-usb remove %k"
# Keep block devices read-only until the operator decides otherwise
SUBSYSTEM=="block", ENV{UDISKS_AUTO}="0"
EOF
    # udev requires single-line RUN commands; keep them short and side-effect free
    cat > /etc/udev/rules.d/99-cyberdeck-usb.rules <<'EOF'
# cyberdeck-arsenal :: log USB device insert/remove events
# The heavy lifting happens in usb-watcher.service (udev RUN must stay trivial).
ACTION=="add",    SUBSYSTEM=="usb", TAG+="systemd", ENV{SYSTEMD_WANTS}+="usb-watcher.service"
ACTION=="remove", SUBSYSTEM=="usb", TAG+="systemd", ENV{SYSTEMD_WANTS}+="usb-watcher.service"
# Mount removable media read-only by default
SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_MOUNT_OPTIONS}="ro,nosuid,nodev,noexec"
EOF
    udevadm control --reload-rules 2>/dev/null || true
    msg_ok "udev rules installed (/etc/udev/rules.d/99-cyberdeck-usb.rules)"

    # logrotate so the deck does not fill its own disk
    cat > /etc/logrotate.d/cyberdeck-arsenal <<EOF
${INSTALL_DIR}/logs/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
    create 0640 root ${RECIPIENT_USER}
}
EOF
    msg_ok "log rotation configured"
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 7 - systemd services
# --------------------------------------------------------------------------- #
step_services() {
    [[ -d /run/systemd/system ]] || { msg_warn "systemd not running - skipping service installation"; return 0; }

    local unit
    for unit in "${SYSTEMD_SERVICES[@]}"; do
        if [[ -f "${SCRIPT_DIR}/config/systemd/${unit}" ]]; then
            install -m 0644 "${SCRIPT_DIR}/config/systemd/${unit}" "/etc/systemd/system/${unit}"
            msg_debug "installed ${unit}"
        else
            msg_warn "missing unit file: config/systemd/${unit}"
        fi
    done
    systemctl daemon-reload

    # Enable passive/monitoring services only; intrusive ones are never auto-started
    for unit in "${SYSTEMD_SERVICES[@]}"; do
        [[ -f "/etc/systemd/system/${unit}" ]] || continue
        if systemctl enable "${unit}" >> "${SETUP_LOG}" 2>&1; then
            msg_ok "enabled ${unit} (not started)"
        else
            msg_warn "could not enable ${unit}"
        fi
    done

    # The MAC rotator timer is what actually schedules rotation
    if [[ -f /etc/systemd/system/mac-rotator.timer ]]; then
        local interval boot_delay
        interval="$(awk -F= '/^OnUnitActiveSec/ {print $2; exit}' /etc/systemd/system/mac-rotator.timer 2>/dev/null)"
        boot_delay="$(awk -F= '/^OnBootSec/ {print $2; exit}' /etc/systemd/system/mac-rotator.timer 2>/dev/null)"
        msg_info "mac-rotator.timer enabled - first rotation ${boot_delay:-2min} after boot, then every ${interval:-1h}"
    fi
    msg_info "start the monitor with: sudo systemctl start cyberdeck-monitor.service"
    msg_info "confirm the state with: systemctl list-timers 'cyberdeck*' 'mac-rotator*'"
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 8 - databases
# --------------------------------------------------------------------------- #
step_databases() {
    local db="${INSTALL_DIR}/data"
    mkdir -p "${db}"

    # --- OUI database -------------------------------------------------------
    local oui="${db}/oui_database.txt"
    if [[ -s "${oui}" ]] && (( $(wc -l < "${oui}") > 1000 )); then
        msg_ok "OUI database already present ($(wc -l < "${oui}") entries)"
    else
        msg_info "downloading the MAC vendor (OUI) database"
        local downloaded=0
        # Try the IEEE registry first, then the Wireshark manuf file (faster CDN)
        if curl -sSfL -m 90 -o "${oui}.tmp" \
            "https://standards-oui.ieee.org/oui/oui.txt" 2>>"${SETUP_LOG}"; then
            awk -F' ' '/\(hex\)/ {gsub(/\(hex\)/,""); printf "%s %s %s\n", $1, $2, substr($0, index($0,$4))}' \
                "${oui}.tmp" > "${oui}" 2>/dev/null || cp "${oui}.tmp" "${oui}"
            downloaded=1
        elif curl -sSfL -m 90 -o "${oui}.tmp" \
            "https://www.wireshark.org/download/automated/data/manuf" 2>>"${SETUP_LOG}"; then
            grep -vE '^\s*#' "${oui}.tmp" | awk '{print $1, substr($0, index($0,$2))}' > "${oui}"
            downloaded=1
        fi
        rm -f "${oui}.tmp"
        if (( downloaded == 1 )) && [[ -s "${oui}" ]]; then
            msg_ok "OUI database installed ($(wc -l < "${oui}") entries)"
        else
            msg_warn "could not download the OUI database - vendor lookups will degrade"
            cat > "${oui}" <<'EOF'
# Cyberdeck OUI database (offline fallback seed)
# Format: AA:BB:CC Vendor name
# Install the full IEEE registry with: cdeck update
00:00:0C Cisco Systems, Inc
00:03:93 Apple, Inc.
00:05:5D D-Link Corporation
00:0C:29 VMware, Inc.
00:15:5D Microsoft Corporation
00:16:3E Xensource, Inc.
00:1A:11 Google, Inc.
00:50:56 VMware, Inc.
00:1C:B3 Apple, Inc.
3C:5A:B4 Google, Inc.
B8:27:EB Raspberry Pi Foundation
DC:A6:32 Raspberry Pi Trading Ltd
E4:5F:01 Raspberry Pi Trading Ltd
28:CD:C1 Raspberry Pi Trading Ltd
F4:F5:D8 Google, Inc.
AC:DE:48 Private
EOF
            msg_info "seeded a minimal offline OUI list - run 'cdeck update' with internet access for full coverage"
        fi
    fi

    # --- BLE vulnerability database ----------------------------------------
    local ble_db="${db}/ble_vulnerability_db.json"
    if [[ -s "${ble_db}" ]]; then
        msg_ok "BLE vulnerability database present"
    else
        if [[ -f "${SCRIPT_DIR}/data/ble_vulnerability_db.json" ]]; then
            cp -f "${SCRIPT_DIR}/data/ble_vulnerability_db.json" "${ble_db}"
            msg_ok "installed BLE vulnerability database from the repository"
        else
            msg_warn "BLE vulnerability database source missing - creating an empty skeleton"
            printf '{"version":"1.0","updated":"%s","devices":[]}\n' "$(date +%F)" > "${ble_db}"
        fi
    fi

    # --- SQLite databases ---------------------------------------------------
    if have sqlite3; then
        local name
        for name in "${DATABASES[@]}"; do
            local path="${db}/${name}.db"
            if [[ -f "${path}" ]]; then
                msg_debug "database ${name}.db already exists"
                continue
            fi
            sqlite3 "${path}" 'PRAGMA journal_mode=WAL;' >/dev/null 2>&1 || true
            msg_debug "created ${path}"
        done
        # Apply the canonical schema from the Python library
        if [[ -x "${VENV_DIR}/bin/python" && -f "${INSTALL_DIR}/lib/cyberlib.py" ]]; then
            if "${VENV_DIR}/bin/python" - "${INSTALL_DIR}" <<'PYEOF' >> "${SETUP_LOG}" 2>&1; then
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "lib"))
import cyberlib
names = ["events", "probes", "ble", "arp", "services", "baseline", "usb", "alerts"]
for name in names:
    db = cyberlib.Database(name)
    db.close()
print("schemas applied:", ", ".join(names))
PYEOF
                msg_ok "SQLite schemas initialised for: ${DATABASES[*]}"
            else
                msg_warn "could not apply SQLite schemas (see ${SETUP_LOG}) - they will be created on first use"
            fi
        fi
        chgrp -R "${RECIPIENT_USER}" "${db}" 2>/dev/null || true
        chmod -R 0770 "${db}" 2>/dev/null || true
    else
        msg_warn "sqlite3 not installed - databases will be created on first use"
    fi

    # --- RF capture directory ----------------------------------------------
    mkdir -p "${INSTALL_DIR}/data/rf" "${INSTALL_DIR}/captures/ble" \
             "${INSTALL_DIR}/captures/wifi" "${INSTALL_DIR}/captures/sdr" \
             "${INSTALL_DIR}/captures/usb"
    msg_ok "capture directories prepared"
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 9 - wordlists
# --------------------------------------------------------------------------- #
step_wordlists() {
    if (( SKIP_WORDLISTS == 1 )); then
        msg_info "wordlist download skipped (--skip-wordlists)"
        return 0
    fi
    local wl="${INSTALL_DIR}/data/wordlists"
    mkdir -p "${wl}" /usr/share/wordlists

    # rockyou
    if [[ -s /usr/share/wordlists/rockyou.txt ]]; then
        msg_ok "rockyou.txt already present"
    elif [[ -s /usr/share/wordlists/rockyou.txt.gz ]]; then
        gunzip -kf /usr/share/wordlists/rockyou.txt.gz && msg_ok "decompressed rockyou.txt"
    else
        msg_info "downloading rockyou.txt (139 MB)"
        if curl -sSfL -m 600 -o /usr/share/wordlists/rockyou.txt.gz \
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" 2>>"${SETUP_LOG}" \
            || curl -sSfL -m 600 -o /usr/share/wordlists/rockyou.txt.gz \
            "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz" 2>>"${SETUP_LOG}"; then
            gunzip -f /usr/share/wordlists/rockyou.txt.gz && msg_ok "rockyou.txt installed"
        else
            msg_warn "rockyou.txt download failed - run 'cdeck update' later with connectivity"
        fi
    fi

    # SecLists subsets (downloaded individually to avoid a 2GB clone)
    local -a seclists_files=(
        "Discovery/Web-Content/common.txt"
        "Discovery/Web-Content/raft-medium-directories.txt"
        "Discovery/Web-Content/directory-list-2.3-medium.txt"
        "Discovery/DNS/subdomains-top1million-5000.txt"
        "Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
        "Passwords/Common-Credentials/best110.txt"
        "Usernames/top-usernames-shortlist.txt"
        "Fuzzing/SQLi/quick-SQLi.txt"
    )
    local rel dest
    for rel in "${seclists_files[@]}"; do
        dest="${wl}/$(basename "${rel}")"
        if [[ -s "${dest}" ]]; then
            msg_debug "$(basename "${dest}") already present"
            continue
        fi
        if curl -sSfL -m 300 -o "${dest}" \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/${rel}" 2>>"${SETUP_LOG}"; then
            msg_debug "downloaded $(basename "${dest}")"
        else
            rm -f "${dest}"
            msg_warn "could not download ${rel}"
        fi
    done

    # Curated small lists generated locally (always available, no network needed)
    cat > "${wl}/cyberdeck-default-users.txt" <<'EOF'
admin
administrator
root
user
guest
test
oracle
postgres
mysql
ftp
pi
ubnt
support
operator
backup
EOF
    cat > "${wl}/cyberdeck-default-passwords.txt" <<'EOF'
admin
password
123456
12345678
qwerty
letmein
welcome
changeme
admin123
root
toor
passw0rd
P@ssw0rd
cisco
default
ubnt
raspberry
cyberdeck
EOF
    cat > "${wl}/cyberdeck-wifi-common.txt" <<'EOF'
12345678
123456789
password
password1
password123
qwerty123
letmein123
internet
wireless
wifi12345
00000000
11111111
87654321
admin1234
iloveyou
EOF
    cat > "${wl}/cyberdeck-ssids.txt" <<'EOF'
FreeWiFi
Free WiFi
Public WiFi
Airport WiFi
Hotel Guest
Guest
Starbucks WiFi
eduroam
Cafe WiFi
Mobile Hotspot
EOF

    # Symlinks for the tools that expect a fixed location
    ln -sf "${wl}" /usr/share/wordlists/cyberdeck 2>/dev/null || true
    [[ -f "${wl}/rockyou.txt" ]] || ln -sf /usr/share/wordlists/rockyou.txt "${wl}/rockyou.txt" 2>/dev/null || true
    chmod -R a+r "${wl}" 2>/dev/null || true
    msg_ok "wordlists ready in ${wl} ($(du -sh "${wl}" 2>/dev/null | cut -f1) total)"
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 10 - hardware detection
# --------------------------------------------------------------------------- #
step_hardware() {
    local out="${INSTALL_DIR}/state/hardware.json"
    local script="${INSTALL_DIR}/utilities/hardware_detect.sh"
    if [[ -x "${script}" ]]; then
        if "${script}" --json > "${out}" 2>>"${SETUP_LOG}"; then
            msg_ok "hardware inventory written to ${out}"
        else
            msg_warn "hardware_detect.sh reported an error - see ${SETUP_LOG}"
        fi
    else
        msg_warn "hardware_detect.sh not found - writing a minimal inventory"
        printf '{"board":"%s","arch":"%s"}' "$(uname -m)" "$(uname -r)" > "${out}"
    fi

    # --- WiFi adapters ------------------------------------------------------
    local -a wlans=()
    local iface
    for iface in /sys/class/net/*; do
        iface="$(basename "${iface}")"
        [[ -d "/sys/class/net/${iface}/wireless" ]] && wlans+=("${iface}")
    done
    if (( ${#wlans[@]} == 0 )); then
        msg_warn "no wireless adapter detected - WiFi modules will skip gracefully"
        msg_info "recommended: Alfa AWUS036ACH / TP-Link TL-WN722N (v1) for monitor mode"
    else
        local monitor_capable=0
        for iface in "${wlans[@]}"; do
            local driver phy
            driver="$(basename "$(readlink -f "/sys/class/net/${iface}/device/driver" 2>/dev/null)" 2>/dev/null || echo unknown)"
            phy="$(cat "/sys/class/net/${iface}/phy80211/name" 2>/dev/null || echo "")"
            if [[ -n "${phy}" ]] && have iw && iw phy "${phy}" info 2>/dev/null | grep -A12 'Supported interface modes' | grep -q '\* monitor'; then
                monitor_capable=$(( monitor_capable + 1 ))
                msg_ok "${iface} supports monitor mode (driver: ${driver})"
                if iw phy "${phy}" info 2>/dev/null | grep -q 'mesh point'; then
                    msg_debug "${iface} also advertises mesh point support"
                fi
            else
                msg_info "${iface} detected (driver: ${driver}) - monitor mode capability unconfirmed"
            fi
        done
        (( monitor_capable > 0 )) || msg_warn "no monitor-mode-capable adapter confirmed - injection features may be limited"
    fi

    # --- SDR ---------------------------------------------------------------
    if have rtl_test && rtl_test -t >/dev/null 2>&1; then
        msg_ok "RTL-SDR device detected"
    elif lsusb 2>/dev/null | grep -qiE 'rtl|hackrf|airspy|limesdr|sdrplay|nooelec'; then
        msg_ok "SDR USB device detected (driver may need blacklisting for DVB-T dongles)"
    else
        msg_info "no SDR receiver detected - SDR modules will skip gracefully"
    fi

    # --- Proxmark / NFC ----------------------------------------------------
    if [[ -e /dev/ttyACM0 ]] || [[ -e /dev/ttyACM1 ]]; then
        if have pm3 || have proxmark3; then msg_ok "Proxmark3 detected"; else msg_info "serial device present but proxmark3 client not installed"; fi
    else
        msg_info "no Proxmark/NFC reader detected - NFC modules skip gracefully"
    fi

    # --- GPS ---------------------------------------------------------------
    if [[ -e /dev/ttyACM0 || -e /dev/ttyUSB0 ]]; then
        msg_info "serial device present - GPS may be available on /dev/ttyACM* or /dev/ttyUSB*"
        if have gpsd; then msg_ok "gpsd installed"; else msg_debug "install gpsd for live GPS coordinates in the HUD"; fi
    else
        msg_info "no GPS module detected - coordinate panel stays hidden"
    fi

    # --- GPIO --------------------------------------------------------------
    if [[ -e /proc/device-tree/model ]] && grep -qiE 'raspberry|banana|orange|rock|jetson' /proc/device-tree/model 2>/dev/null; then
        msg_ok "GPIO-capable board detected: $(tr -d '\0' < /proc/device-tree/model)"
        if [[ "${MODE}" != "minimal" ]]; then
            msg_info "enable the GPIO modules with: cdeck config gpio.enabled true"
        fi
    else
        msg_info "no GPIO single-board computer detected - GPIO modules skip gracefully"
    fi

    # --- Battery -----------------------------------------------------------
    if compgen -G "/sys/class/power_supply/BAT*" >/dev/null; then
        msg_ok "battery detected: $(cat /sys/class/power_supply/BAT*/capacity 2>/dev/null | head -1)%"
    else
        msg_info "no battery detected - low-battery automation disabled"
    fi
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 11 - security hardening
# --------------------------------------------------------------------------- #
step_hardening() {
    if (( SKIP_HARDENING == 1 )); then
        msg_info "hardening skipped (--skip-hardening)"
        return 0
    fi

    # --- iptables: default deny inbound, allow established ------------------
    if have iptables; then
        msg_info "configuring iptables default policy (deny inbound)"
        iptables -P INPUT DROP 2>/dev/null || msg_warn "could not set INPUT policy"
        iptables -P FORWARD DROP 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
        iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT
        iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
            || iptables -I INPUT 2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -C INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null \
            || iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
        if have iptables-save; then
            mkdir -p "${INSTALL_DIR}/state"
            iptables-save > "${INSTALL_DIR}/state/iptables.rules" 2>/dev/null || true
            msg_ok "iptables rules saved to ${INSTALL_DIR}/state/iptables.rules"
        fi
    else
        msg_warn "iptables not installed - skipping firewall rules"
    fi

    # --- UFW ---------------------------------------------------------------
    if have ufw; then
        msg_info "configuring UFW with restrictive defaults"
        ufw --force default deny incoming >/dev/null 2>&1 || true
        ufw --force default allow outgoing >/dev/null 2>&1 || true
        ufw allow from 192.168.0.0/16 to any port 22 proto tcp comment 'LAN ssh' >/dev/null 2>&1 || true
        ufw allow from 10.0.0.0/8 to any port 22 proto tcp comment 'LAN ssh' >/dev/null 2>&1 || true
        ufw --force enable >/dev/null 2>&1 && msg_ok "UFW enabled (deny incoming, LAN SSH allowed)" \
            || msg_warn "could not enable UFW"
    else
        msg_info "UFW not installed - the iptables policy above still applies"
    fi

    # --- fail2ban ----------------------------------------------------------
    if have fail2ban-client || [[ -x /usr/bin/fail2ban-server ]]; then
        mkdir -p /etc/fail2ban/jail.d
        cat > /etc/fail2ban/jail.d/cyberdeck.local <<'EOF'
# cyberdeck-arsenal :: conservative SSH protection
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 4
EOF
        systemctl enable --now fail2ban >> "${SETUP_LOG}" 2>&1 \
            && msg_ok "fail2ban enabled with cyberdeck jail" \
            || msg_warn "failed to enable fail2ban"
    else
        msg_info "fail2ban not installed - skipping"
    fi

    # --- SSH hardening (only if sshd is present) ---------------------------
    if [[ -f /etc/ssh/sshd_config ]]; then
        mkdir -p /etc/ssh/sshd_config.d
        cat > /etc/ssh/sshd_config.d/99-cyberdeck-hardening.conf <<'EOF'
# cyberdeck-arsenal SSH hardening
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 30
AllowAgentForwarding no
EOF
        if systemctl is-active sshd >/dev/null 2>&1; then
            sshd -t 2>/dev/null && systemctl reload sshd >> "${SETUP_LOG}" 2>&1 \
                && msg_ok "SSH hardened (key-based auth only)" \
                || msg_warn "sshd config test failed - review /etc/ssh/sshd_config.d/99-cyberdeck-hardening.conf"
        else
            msg_info "sshd not running - hardening config staged for next start"
        fi
        msg_warn "SSH now requires key authentication - ensure your key is installed before rebooting"
    else
        msg_info "no SSH server installed - hardening skipped"
    fi

    # --- Disable services that leak information or are unused --------------
    local svc
    for svc in avahi-daemon.service bluetooth.service cups.service rpcbind.service; do
        if systemctl list-unit-files "${svc}" >/dev/null 2>&1 && systemctl is-enabled "${svc}" >/dev/null 2>&1; then
            systemctl disable --now "${svc}" >> "${SETUP_LOG}" 2>&1 \
                && msg_info "disabled ${svc} (re-enable with: sudo systemctl enable --now ${svc})" \
                || msg_debug "could not disable ${svc}"
        fi
    done

    # --- File permissions on the suite -------------------------------------
    chmod 0700 "${INSTALL_DIR}/vault" 2>/dev/null || true
    chmod 0600 "${INSTALL_DIR}/cyberdeck.conf" 2>/dev/null || true
    chmod 0700 "${INSTALL_DIR}/state" 2>/dev/null || true
    msg_ok "filesystem permissions tightened"
    return 0
}

# --------------------------------------------------------------------------- #
# STEP 12 - post-install
# --------------------------------------------------------------------------- #
step_postinstall() {
    # Uninstaller
    generate_uninstall

    # Test suite (non-fatal)
    if [[ -x "${INSTALL_DIR}/tests/test_installation.sh" ]]; then
        msg_info "running test_installation.sh"
        if "${INSTALL_DIR}/tests/test_installation.sh" --quiet; then
            msg_ok "installation tests passed"
        else
            msg_warn "installation tests reported problems - run: ${INSTALL_DIR}/tests/test_installation.sh"
        fi
    fi

    write_state_json

    # Summary -------------------------------------------------------------
    printf '\n'
    local bar; bar="$(printf '─%.0s' $(seq 1 72))"
    printf '%b%s%b\n' "${CYAN}${BOLD}" "${bar}" "${RESET}"
    printf '%b  cyberdeck-arsenal installation summary%b\n' "${BOLD}" "${RESET}"
    printf '%b%s%b\n' "${CYAN}" "${bar}" "${RESET}"
    printf '  install dir   : %s\n' "${INSTALL_DIR}"
    printf '  config        : %s\n' "${INSTALL_DIR}/cyberdeck.conf"
    printf '  venv          : %s\n' "${VENV_DIR}"
    printf '  logs          : %s\n' "${LOG_DIR}"
    printf '  reports       : %s\n' "${INSTALL_DIR}/reports"
    printf '  steps done    : %s/12\n' "$(state_completed_count)"
    printf '  warnings      : %d\n' "${#WARNINGS[@]}"
    printf '  errors        : %d\n' "${#ERRORS[@]}"
    printf '\n'

    # Hardware summary
    if [[ -f "${INSTALL_DIR}/state/hardware.json" ]] && have jq; then
        printf '%b  detected hardware%b\n' "${BOLD}" "${RESET}"
        jq -r '(.wifi // [])[] | "  • WiFi      : \(.interface) [\(.driver // "unknown")] monitor=\(.monitor_capable // false)"' \
            "${INSTALL_DIR}/state/hardware.json" 2>/dev/null || true
        jq -r 'if (.sdr // []) | length > 0 then "  • SDR       : \(.sdr | join(", "))" else "  • SDR       : none detected" end' \
            "${INSTALL_DIR}/state/hardware.json" 2>/dev/null || true
        jq -r '"  • Board     : \(.board // "unknown")"' "${INSTALL_DIR}/state/hardware.json" 2>/dev/null || true
        printf '\n'
    fi

    # Quick start
    cat <<EOF
${BOLD}  Quick start${RESET}
    cdeck status              # hardware and system status
    cdeck dashboard           # launch the main HUD (also: cyberdeck)
    cdeck wifi                # WiFi arsenal menu
    cdeck scan 192.168.1.0/24 # quick network scan
    cdeck profile example.com # full target profile
    cdeck help                # everything else
    source ~/.bashrc          # pick up the new aliases in this shell

${BOLD}  Optional next steps${RESET}
    sudo systemctl start cyberdeck-monitor.service   # always-on monitoring
    sudo systemctl start mac-rotator.timer           # scheduled MAC rotation
    cdeck config                                     # add API keys for threat feeds

${YELLOW}${BOLD}  ⚠  Legal${RESET}: only use the active/attack modules against systems and
     radio spectrum you own or are explicitly authorised to test.
     See ${INSTALL_DIR}/docs/LEGAL.md

${BOLD}  Log file${RESET}: ${SETUP_LOG}
${BOLD}  Uninstall${RESET}: sudo ${INSTALL_DIR}/uninstall.sh
EOF
    printf '%b%s%b\n\n' "${CYAN}" "${bar}" "${RESET}"

    if (( ${#WARNINGS[@]} )); then
        msg_info "review the ${#WARNINGS[@]} warning(s) above; most are optional components"
    fi
    msg_ok "installation complete - welcome to the deck, ${RECIPIENT_USER}"
    return 0
}

# --------------------------------------------------------------------------- #
# Uninstaller generation
# --------------------------------------------------------------------------- #
generate_uninstall() {
    local path="${INSTALL_DIR}/uninstall.sh"
    cat > "${path}" <<UNINSTALL_EOF
#!/usr/bin/env bash
# =============================================================================
# cyberdeck-arsenal :: uninstall.sh - generated by setup.sh on \$(date -Is)
# =============================================================================
# Description : Removes cyberdeck-arsenal: services, symlinks, configs, logs,
#               databases, wordlists, the cdeck command and (optionally) all
#               packages that setup.sh installed.
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Usage       : sudo ${path} [--purge] [--keep-packages] [--keep-captures] [--yes]
# =============================================================================
set -uo pipefail

INSTALL_DIR="${INSTALL_DIR}"
PURGE=0
KEEP_PACKAGES=0
KEEP_CAPTURES=0
ASSUME_YES=0
RED=\$'\033[31m'; GREEN=\$'\033[32m'; YELLOW=\$'\033[33m'; CYAN=\$'\033[36m'; BOLD=\$'\033[1m'; RESET=\$'\033[0m'

for arg in "\$@"; do
    case "\${arg}" in
        --purge)          PURGE=1 ;;
        --keep-packages)  KEEP_PACKAGES=1 ;;
        --keep-captures)  KEEP_CAPTURES=1 ;;
        --yes|-y)         ASSUME_YES=1 ;;
        --help|-h)
            sed -n '2,12p' "\$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown option: \${arg}" >&2; exit 2 ;;
    esac
done

[[ "\${EUID}" -eq 0 ]] || { echo "\${RED}must run as root\${RESET}"; exit 1; }

confirm() {
    (( ASSUME_YES == 1 )) && return 0
    local reply
    read -r -p "\${YELLOW}\$1 [y/N] \${RESET}" reply || return 1
    [[ "\${reply,,}" == "y" ]]
}

echo "\${BOLD}\${CYAN}cyberdeck-arsenal uninstaller\${RESET}"
confirm "Remove cyberdeck-arsenal from \${INSTALL_DIR}? This cannot be undone." || {
    echo "aborted."; exit 0; }

# 1. Services
if [[ -d /run/systemd/system ]]; then
    for unit in cyberdeck-monitor.service mac-rotator.service mac-rotator.timer \\
                probe-logger.service ble-scanner.service rogue-ap-detector.service \\
                usb-watcher.service; do
        systemctl stop "\${unit}" 2>/dev/null || true
        systemctl disable "\${unit}" 2>/dev/null || true
        rm -f "/etc/systemd/system/\${unit}"
        echo "\${GREEN}✔\${RESET} removed \${unit}"
    done
    systemctl daemon-reload 2>/dev/null || true
fi

# 2. Symlinks and shell integration
rm -f /usr/local/bin/cdeck /usr/local/bin/cyberdeck
rm -f /etc/profile.d/cyberdeck-motd.sh
rm -f /etc/udev/rules.d/99-cyberdeck-usb.rules
rm -f /etc/logrotate.d/cyberdeck-arsenal
rm -f /etc/fail2ban/jail.d/cyberdeck.local
rm -f /etc/ssh/sshd_config.d/99-cyberdeck-hardening.conf
udevadm control --reload-rules 2>/dev/null || true
echo "\${GREEN}✔\${RESET} removed symlinks, MOTD, udev rules and hardening configs"

# 3. Shell rc cleanup
for rc in "\${HOME}/.bashrc" /home/*/.bashrc; do
    [[ -f "\${rc}" ]] || continue
    if grep -q 'cyberdeck-arsenal' "\${rc}" 2>/dev/null; then
        sed -i '/# >>> cyberdeck-arsenal >>>/,/# <<< cyberdeck-arsenal <<</d' "\${rc}"
        echo "\${GREEN}✔\${RESET} cleaned \${rc}"
    fi
done

# 4. Wordlist symlinks (never delete a user's rockyou.txt)
rm -f /usr/share/wordlists/cyberdeck
echo "\${GREEN}✔\${RESET} removed wordlist symlinks (rockyou.txt kept)"

# 5. Packages
if (( KEEP_PACKAGES == 0 && PURGE == 1 )); then
    echo "\${YELLOW}! --purge removes tool packages. Press Ctrl-C within 5s to abort.\${RESET}"
    sleep 5
    # Only remove packages that no other component depends on
    pacman -Rns --noconfirm bettercap responder wifite hcxtools hcxdumptool \\
        reaver bully 2>/dev/null || true
    echo "\${GREEN}✔\${RESET} removed cyberdeck-specific packages (shared toolchain kept)"
else
    echo "\${CYAN}→\${RESET} leaving tool packages installed (use --purge to remove)"
fi

# 6. Data
if (( KEEP_CAPTURES == 0 )); then
    if confirm "Securely delete captures and engagement reports?"; then
        if command -v shred >/dev/null 2>&1; then
            find "\${INSTALL_DIR}/captures" "\${INSTALL_DIR}/reports" "\${INSTALL_DIR}/vault" \\
                -type f -exec shred -uzn 1 {} \\; 2>/dev/null || true
        fi
        rm -rf "\${INSTALL_DIR}/captures" "\${INSTALL_DIR}/reports" "\${INSTALL_DIR}/vault"
        echo "\${GREEN}✔\${RESET} captures, reports and vault securely removed"
    else
        echo "\${CYAN}→\${RESET} keeping captures in \${INSTALL_DIR}/captures"
    fi
fi

# 7. Install directory
rm -rf "\${INSTALL_DIR}"
rm -rf /etc/cyberdeck-arsenal
echo "\${GREEN}✔\${RESET} removed \${INSTALL_DIR}"

echo ""
echo "\${BOLD}cyberdeck-arsenal removed.\${RESET} Reinstall with: sudo ./setup.sh"
echo "\${CYAN}→\${RESET} The firewall policy installed by setup.sh was left in place."
echo "   Reset it with: sudo ufw disable && sudo iptables -P INPUT ACCEPT && sudo iptables -F"
UNINSTALL_EOF
    chmod 0750 "${path}"
    msg_ok "uninstaller written to ${path}"
}

# --------------------------------------------------------------------------- #
# Uninstall mode (delegates to the generated uninstaller)
# --------------------------------------------------------------------------- #
run_uninstall() {
    banner
    msg_step "▶ Uninstalling cyberdeck-arsenal"
    if [[ -x "${INSTALL_DIR}/uninstall.sh" ]]; then
        exec "${INSTALL_DIR}/uninstall.sh" "$@"
    fi
    msg_warn "no generated uninstaller found - performing an inline removal"
    if (( ASSUME_YES == 0 )) && ! ask_confirm "Remove ${INSTALL_DIR} and all services?" n; then
        msg_info "cancelled"; exit 0
    fi
    local unit
    for unit in "${SYSTEMD_SERVICES[@]}"; do
        systemctl stop "${unit}" 2>/dev/null || true
        systemctl disable "${unit}" 2>/dev/null || true
        rm -f "/etc/systemd/system/${unit}"
    done
    systemctl daemon-reload 2>/dev/null || true
    rm -f /usr/local/bin/cdeck /usr/local/bin/cyberdeck
    rm -f /etc/profile.d/cyberdeck-motd.sh /etc/udev/rules.d/99-cyberdeck-usb.rules
    rm -rf "${INSTALL_DIR}" /etc/cyberdeck-arsenal
    msg_ok "cyberdeck-arsenal removed"
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
main() {
    parse_args "$@"
    state_init   # needs to happen before we can log
    log_write INFO "setup.sh ${SCRIPT_VERSION} started (mode=${MODE} user=${RECIPIENT_USER} args=$*)"

    banner

    if (( UNINSTALL == 1 )); then
        run_uninstall "$@"
        exit 0
    fi

    [[ "${EUID}" -eq 0 ]] || { msg_error "run as root: sudo ${SCRIPT_NAME} $*"; exit 1; }

    if state_done step_preflight && (( RESUME == 0 )); then
        msg_info "a previous installation was detected (state: $(state_completed_count)/12 steps)"
        msg_info "use --resume to continue it, or delete ${STATE_FILE} to start fresh"
        if ! ask_confirm "Re-run all steps from the beginning?" n; then
            msg_info "exiting - run 'sudo ${SCRIPT_NAME} --resume' to continue"
            exit 0
        fi
        : > "${STATE_FILE}"
    fi

    local start_time; start_time="$(date +%s)"

    # Steps run in dependency order; each is idempotent and resumable.
    run_step step_preflight     "Step  1/12 pre-flight checks"      || exit 1
    run_step step_update        "Step  2/12 system update"          || msg_warn "continuing after update problems"
    run_step step_packages      "Step  3/12 installing toolchain"   || exit 1
    run_step step_venv          "Step  4/12 python virtualenv"      || exit 1
    run_step step_directories   "Step  5/12 directory structure"    || exit 1
    run_step step_config        "Step  6/12 configuration"          || exit 1
    run_step step_services      "Step  7/12 systemd services"       || msg_warn "continuing without all services"
    run_step step_databases     "Step  8/12 databases"              || msg_warn "continuing without full database set"
    run_step step_wordlists     "Step  9/12 wordlists"              || msg_warn "continuing without wordlists"
    run_step step_hardware      "Step 10/12 hardware detection"     || msg_warn "hardware detection incomplete"
    run_step step_hardening     "Step 11/12 security hardening"     || msg_warn "hardening incomplete"
    run_step step_postinstall   "Step 12/12 post-install"           || msg_warn "post-install checks reported problems"

    local elapsed=$(( $(date +%s) - start_time ))
    msg_step "Installation finished in $(( elapsed / 60 ))m $(( elapsed % 60 ))s"
    log_write INFO "setup.sh finished in ${elapsed}s with ${#WARNINGS[@]} warnings and ${#ERRORS[@]} errors"
    (( ${#ERRORS[@]} )) && exit 1
    exit 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    mkdir -p "${LOG_DIR}" "${STATE_DIR}" 2>/dev/null || true
    main "$@"
fi
