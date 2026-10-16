#!/usr/bin/env bash
# =============================================================================
# download_wordlists.sh - fetch and manage wordlists for cyberdeck-arsenal
# =============================================================================
#
# Description
# -----------
# Downloads the wordlists the suite's cracking and fuzzing modules expect,
# verifies them, installs symlinks in the canonical locations and reports what
# is present. Safe to re-run: existing files are skipped unless --force.
#
# Sets downloaded (each is skipped if already present):
#   rockyou.txt             ~139 MB  classic leaked-password list
#   SecLists subsets        ~20 MB   discovery, passwords, usernames, fuzzing
#   dirb/common.txt         bundled with the dirb package
#   cyberdeck lists         generated locally (no network required)
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: curl or wget, gzip, coreutils
# Licence     : MIT - wordlists retain their own upstream licences (see below)
#
# Usage
# -----
#   ./download_wordlists.sh                  # download everything missing
#   ./download_wordlists.sh --update-only    # refresh only what already exists
#   ./download_wordlists.sh --force          # re-download everything
#   ./download_wordlists.sh --list           # show what is installed
#   ./download_wordlists.sh --minimal        # skip the large lists (>50 MB)
#   ./download_wordlists.sh --help
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${CYBERDECK_INSTALL_DIR:-/opt/cyberdeck-arsenal}"
LIB_DIR="${INSTALL_DIR}/lib"
[[ -d "${LIB_DIR}" ]] || LIB_DIR="${SCRIPT_DIR}/../../lib"

if [[ -f "${LIB_DIR}/cyberdeck_common.sh" ]]; then
    # shellcheck source=../../lib/cyberdeck_common.sh
    source "${LIB_DIR}/cyberdeck_common.sh"
else
    # Minimal fallback so the script is usable standalone
    C_GREEN=""; C_RED=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""; C_RESET=""; C_DIM=""
    cdeck::init() { CDECK_LOG_DIR="${INSTALL_DIR}/logs"; mkdir -p "${CDECK_LOG_DIR}" 2>/dev/null || true; }
    cdeck::info()  { printf '→ %s\n' "$*"; }
    cdeck::ok()    { printf '✔ %s\n' "$*"; }
    cdeck::warn()  { printf '! %s\n' "$*"; }
    cdeck::error() { printf '✘ %s\n' "$*" >&2; }
    cdeck::banner() { printf '\n== %s ==\n' "$*"; }
    cdeck::has_cmd() { command -v "$1" >/dev/null 2>&1; }
    cdeck::conf_get() { printf '%s' "${2:-}"; }
    cdeck::die() { printf 'fatal: %s\n' "$*" >&2; exit 1; }
fi

cdeck::init "wordlists"

WORDLIST_DIR="${INSTALL_DIR}/data/wordlists"
CANONICAL_DIR="/usr/share/wordlists"
FORCE=0
UPDATE_ONLY=0
MINIMAL=0
LIST_ONLY=0

# --------------------------------------------------------------------------- #
# Help
# --------------------------------------------------------------------------- #
usage() {
    cat <<EOF
${C_BOLD}download_wordlists.sh${C_RESET} - fetch wordlists for cyberdeck-arsenal

${C_BOLD}USAGE${C_RESET}
  $0 [options]

${C_BOLD}OPTIONS${C_RESET}
  -f, --force         re-download files that already exist
  -u, --update-only   only refresh lists that are already present
  -m, --minimal       skip lists larger than 50 MB (rockyou and equivalents)
  -l, --list          list installed wordlists and exit with a size report
  -d, --dir PATH      install into PATH (default: ${WORDLIST_DIR})
      --help, -h      this help

${C_BOLD}LAYOUT${C_RESET}
  ${WORDLIST_DIR}            primary location used by the suite
  ${CANONICAL_DIR}/cyberdeck -> symlink to the directory above
  ${CANONICAL_DIR}/rockyou.txt        expected by aircrack-ng, john, hashcat

${C_DIM}Licences: rockyou.txt is distributed for password auditing; SecLists is
MIT licensed. Do not use these lists against systems you are not authorised
to test.${C_RESET}
EOF
}

while (( $# )); do
    case "$1" in
        --help|-h)       usage; exit 0 ;;
        -f|--force)      FORCE=1 ;;
        -u|--update-only) UPDATE_ONLY=1 ;;
        -m|--minimal)    MINIMAL=1 ;;
        -l|--list)       LIST_ONLY=1 ;;
        -d|--dir)        shift; WORDLIST_DIR="${1:-}" ;;
        *) printf 'unknown option: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
    shift
done

mkdir -p "${WORDLIST_DIR}"
mkdir -p "${CANONICAL_DIR}" 2>/dev/null || cdeck::warn "cannot write ${CANONICAL_DIR} (run as root for symlinks)"

# --------------------------------------------------------------------------- #
# Listing mode
# --------------------------------------------------------------------------- #
list_wordlists() {
    cdeck::banner "installed wordlists"
    printf '  %-38s %10s  %s\n' "FILE" "SIZE" "LINES"
    local found=0 file
    for file in "${WORDLIST_DIR}"/*.txt "${CANONICAL_DIR}"/rockyou.txt; do
        [[ -f "${file}" ]] || continue
        found=$(( found + 1 ))
        local size lines
        size="$(du -h "${file}" 2>/dev/null | cut -f1)"
        lines="$(wc -l < "${file}" 2>/dev/null || echo '?')"
        printf '  %-38s %10s  %s\n' "$(basename "${file}")" "${size}" "${lines}"
    done
    # Git-cloned SecLists
    for dir in /usr/share/seclists /opt/SecLists "${WORDLIST_DIR}/SecLists"; do
        if [[ -d "${dir}" ]]; then
            found=$(( found + 1 ))
            printf '  %-38s %10s  %s\n' "${dir}" "$(du -sh "${dir}" 2>/dev/null | cut -f1)" "directory"
        fi
    done
    printf '\n  total space used: %s\n' "$(du -sh "${WORDLIST_DIR}" 2>/dev/null | cut -f1)"
    if (( found == 0 )); then
        printf '  no wordlists installed yet - re-run this script without --list\n'
    fi
}

if (( LIST_ONLY == 1 )); then
    list_wordlists
    exit 0
fi

# --------------------------------------------------------------------------- #
# Download helper
# --------------------------------------------------------------------------- #
download() {
    # download <url> <destination> [description] [min-bytes]
    local url="$1" destination="$2" description="${3:-$(basename "$2")}" min_bytes="${4:-1024}"
    if [[ -s "${destination}" ]] && (( FORCE == 0 )); then
        if (( UPDATE_ONLY == 1 )); then
            cdeck::debug "${description}: present, refreshing"
        else
            cdeck::ok "${description} already present ($(du -h "${destination}" | cut -f1))"
            return 0
        fi
    fi
    cdeck::info "downloading ${description}"
    local tmp="${destination}.part"
    local ok=0
    if cdeck::has_cmd curl; then
        curl -sSfL --retry 3 --retry-delay 2 -m 900 -o "${tmp}" "${url}" && ok=1 || ok=0
    elif cdeck::has_cmd wget; then
        wget -q -O "${tmp}" "${url}" && ok=1 || ok=0
    else
        cdeck::error "neither curl nor wget is installed"
        return 1
    fi
    if (( ok == 0 )) || [[ ! -s "${tmp}" ]]; then
        rm -f "${tmp}"
        cdeck::warn "download failed: ${description} (${url})"
        return 1
    fi
    local size
    size="$(stat -c %s "${tmp}" 2>/dev/null || echo 0)"
    if (( size < min_bytes )); then
        # Some mirrors return an HTML error page with a 200 status
        rm -f "${tmp}"
        cdeck::warn "${description}: downloaded file looks truncated (${size} bytes) - rejected"
        return 1
    fi
    mv -f "${tmp}" "${destination}"
    cdeck::ok "${description} installed ($(du -h "${destination}" | cut -f1))"
    return 0
}

# --------------------------------------------------------------------------- #
# Sanity
# --------------------------------------------------------------------------- #
if ! cdeck::has_cmd curl && ! cdeck::has_cmd wget; then
    cdeck::die "curl or wget is required to download wordlists"
fi

cdeck::banner "wordlists" "target: ${WORDLIST_DIR}"
if ! cdeck::have_connectivity 2>/dev/null && command -v cdeck::have_connectivity >/dev/null 2>&1; then
    :
fi

# --------------------------------------------------------------------------- #
# 1. rockyou.txt
# --------------------------------------------------------------------------- #
if (( MINIMAL == 0 )); then
    ROCKYOU_TARGET="${CANONICAL_DIR}/rockyou.txt"
    if [[ -s "${ROCKUYOU_TARGET}" ]]; then
        cdeck::ok "rockyou.txt present ($(du -h "${ROCKUYOU_TARGET}" | cut -f1))"
    elif [[ -s "${CANONICAL_DIR}/rockyou.txt.gz" ]]; then
        cdeck::info "decompressing the packaged rockyou.txt.gz"
        gunzip -f "${CANONICAL_DIR}/rockyou.txt.gz" && cdeck::ok "rockyou.txt ready" \
            || cdeck::warn "gunzip failed - check the archive"
    else
        if download "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
                    "${ROCKUYOU_TARGET}.gz" "rockyou.txt (139 MB)" 10000000; then
            gunzip -f "${ROCKUYOU_TARGET}.gz" && cdeck::ok "rockyou.txt decompressed" \
                || cdeck::warn "gunzip failed - the .gz stays in place"
        elif download "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz" \
                      "${ROCKUYOU_TARGET}.gz" "rockyou.txt (Kali mirror)" 10000000; then
            gunzip -f "${ROCKUYOU_TARGET}.gz" && cdeck::ok "rockyou.txt decompressed" \
                || cdeck::warn "gunzip failed"
        else
            cdeck::warn "rockyou.txt could not be downloaded - re-run with connectivity"
            cdeck::info "manual alternative: sudo pacman -S wordlists  (if packaged)"
        fi
    fi
else
    cdeck::info "minimal mode: skipping the large password lists"
fi

# --------------------------------------------------------------------------- #
# 2. SecLists subsets
# --------------------------------------------------------------------------- #
SECLISTS_BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
declare -A SECLISTS_FILES=(
    ["common.txt"]="Discovery/Web-Content/common.txt"
    ["directory-list-2.3-medium.txt"]="Discovery/Web-Content/directory-list-2.3-medium.txt"
    ["raft-medium-directories.txt"]="Discovery/Web-Content/raft-medium-directories.txt"
    ["raft-small-words.txt"]="Discovery/Web-Content/raft-small-words.txt"
    ["subdomains-top1million-5000.txt"]="Discovery/DNS/subdomains-top1million-5000.txt"
    ["subdomains-top1million-20000.txt"]="Discovery/DNS/subdomains-top1million-20000.txt"
    ["top-usernames-shortlist.txt"]="Usernames/top-usernames-shortlist.txt"
    ["xato-net-10-million-usernames.txt"]="Usernames/xato-net-10-million-usernames.txt"
    ["10-million-password-list-top-1000000.txt"]="Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
    ["best110.txt"]="Passwords/Common-Credentials/best110.txt"
    ["quick-SQLi.txt"]="Fuzzing/SQLi/quick-SQLi.txt"
    ["LFI-Jhaddix.txt"]="Fuzzing/LFI/LFI-Jhaddix.txt"
    ["traversal.txt"]="Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
    ["web-extensions.txt"]="Discovery/Web-Content/web-extensions.txt"
    ["api-endpoints.txt"]="Discovery/Web-Content/api/api-endpoints.txt"
)

cdeck::info "fetching SecLists subsets (${#SECLISTS_FILES[@]} files)"
SECLISTS_OK=0
SECLISTS_FAIL=0
for local_name in "${!SECLISTS_FILES[@]}"; do
    remote_path="${SECLISTS_FILES[${local_name}]}"
    if download "${SECLISTS_BASE}/${remote_path}" "${WORDLIST_DIR}/${local_name}" \
                "SecLists/${local_name}" 512; then
        SECLISTS_OK=$(( SECLISTS_OK + 1 ))
    else
        SECLISTS_FAIL=$(( SECLISTS_FAIL + 1 ))
    fi
done
cdeck::ok "SecLists subsets: ${SECLISTS_OK} installed, ${SECLISTS_FAIL} unavailable"

# A full SecLists clone is occasionally useful; offer it but never do it silently
if [[ ! -d /usr/share/seclists && ! -d "${WORDLIST_DIR}/SecLists" ]]; then
    cdeck::info "for the full SecLists collection (~1.5 GB): git clone --depth 1 \\"
    cdeck::info "    https://github.com/danielmiessler/SecLists /usr/share/seclists"
fi

# --------------------------------------------------------------------------- #
# 3. Locally generated lists (no network required)
# --------------------------------------------------------------------------- #
cat > "${WORDLIST_DIR}/cyberdeck-default-users.txt" <<'EOF'
# Default and common account names for credential auditing
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
cisco
nagios
tomcat
jenkins
git
svn
www-data
deploy
service
EOF

cat > "${WORDLIST_DIR}/cyberdeck-default-passwords.txt" <<'EOF'
# Default and common passwords for credential auditing
admin
administrator
password
Password1
password123
P@ssw0rd
123456
12345678
123456789
qwerty
qwerty123
letmein
welcome
changeme
admin123
root
toor
pass
Passw0rd!
cisco
ubnt
default
raspberry
cyberdeck
test123
EOF

cat > "${WORDLIST_DIR}/cyberdeck-wifi-common.txt" <<'EOF'
# Common WiFi passphrases (WPA/WPA2) for authorised wireless auditing
12345678
123456789
1234567890
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
changeme123
EOF

cat > "${WORDLIST_DIR}/cyberdeck-ssids.txt" <<'EOF'
# SSIDs commonly probed for by devices and used by rogue-AP lures
FreeWiFi
Free WiFi
Public WiFi
Airport WiFi
Hotel Guest
Guest
Guest WiFi
Starbucks WiFi
eduroam
Cafe WiFi
Mobile Hotspot
home
NETGEAR
linksys
TP-LINK
default
EOF

cat > "${WORDLIST_DIR}/cyberdeck-subdomains.txt" <<'EOF'
# Common subdomain labels for DNS enumeration
www
mail
remote
blog
webmail
server
ns1
ns2
smtp
secure
vpn
m
shop
ftp
mail2
test
portal
ns
ww1
host
support
dev
web
bbs
mx
email
cloud
1
2
3
api
staging
admin
intranet
jenkins
git
ci
cdn
assets
static
img
media
db
mysql
postgres
redis
mongo
elastic
kibana
grafana
prometheus
EOF

cdeck::ok "generated 5 cyberdeck-specific lists"

# --------------------------------------------------------------------------- #
# 4. Symlinks
# --------------------------------------------------------------------------- #
if [[ -w "${CANONICAL_DIR}" ]]; then
    ln -sfn "${WORDLIST_DIR}" "${CANONICAL_DIR}/cyberdeck" 2>/dev/null \
        && cdeck::ok "linked ${CANONICAL_DIR}/cyberdeck → ${WORDLIST_DIR}" \
        || cdeck::warn "could not create the ${CANONICAL_DIR}/cyberdeck symlink"
    for list in common.txt directory-list-2.3-medium.txt; do
        if [[ -f "${WORDLIST_DIR}/${list}" ]]; then
            ln -sf "${WORDLIST_DIR}/${list}" "${CANONICAL_DIR}/${list}" 2>/dev/null || true
        fi
    done
    # Tools that expect dirb's own tree benefit from a link too
    if [[ -d /usr/share/dirb/wordlists && ! -f /usr/share/dirb/wordlists/common.txt ]]; then
        cdeck::warn "dirb's common.txt is missing - install the dirb package"
    fi
else
    cdeck::warn "cannot write ${CANONICAL_DIR} - re-run as root to install symlinks"
fi

chmod -R a+r "${WORDLIST_DIR}" 2>/dev/null || true

# --------------------------------------------------------------------------- #
# 5. Report
# --------------------------------------------------------------------------- #
cdeck::banner "wordlist summary"
list_wordlists

cdeck::ok "wordlists are ready in ${WORDLIST_DIR}"
cdeck::info "used by: aircrack-ng, hashcat, john, hydra, gobuster, ffuf, wfuzz, dnsrecon"
exit 0
