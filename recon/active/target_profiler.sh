#!/usr/bin/env bash
# =============================================================================
# target_profiler.sh - comprehensive target profiling
# =============================================================================
#
# Description
# -----------
# Runs the standard three-stage reconnaissance workflow against a target and
# files everything into a timestamped engagement directory, finishing with a
# markdown report ready to hand to a client.
#
#   quick     whois + dig + whatweb                     (~1 minute)
#   standard  + nmap -sC -sV + dnsrecon + subfinder      (~5-15 minutes)
#   deep      + nikto + gobuster + enum4linux + sslscan  (30+ minutes)
#
# Everything degrades gracefully: missing tools are reported and skipped, and
# the report records which stages actually ran.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: whois, dig, whatweb, nmap, dnsrecon, subfinder, nikto,
#               gobuster, enum4linux, sslscan (all optional beyond whois/dig)
# Licence     : MIT - authorised use only, see docs/LEGAL.md
#
# Usage
# -----
#   ./target_profiler.sh example.com                 # standard depth
#   ./target_profiler.sh 10.0.0.5 deep
#   ./target_profiler.sh 192.168.1.0/24 quick
#   ./target_profiler.sh --help
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../../lib/cyberdeck_common.sh" ]]; then
    source "${SCRIPT_DIR}/../../lib/cyberdeck_common.sh"
elif [[ -f /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh ]]; then
    source /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh
else
    echo "fatal: cyberdeck_common.sh not found" >&2
    exit 1
fi

cdeck::init "target_profiler"

TARGET=""
DEPTH=""
WORDLIST=""
SKIP_PORTSCAN=0
TIMEOUT_SCALE=1

# --------------------------------------------------------------------------- #
# Help
# --------------------------------------------------------------------------- #
usage() {
    cdeck::usage_header \
        "Comprehensive target profiler (whois/dig/nmap/nikto/gobuster/enum4linux/sslscan)" \
        "$0 <target> [quick|standard|deep] [options]" \
        "$0 example.com" \
        "$0 10.0.0.5 deep" \
        "$0 192.168.1.0/24 quick" \
        "$0 example.com standard --wordlist /usr/share/wordlists/rockyou.txt"
    cat <<EOF

${C_BOLD}DEPTH LEVELS${C_RESET}
  quick     whois, dig (all common record types), whatweb fingerprint
  standard  + nmap -sC -sV, dnsrecon, subfinder, TLS certificate inspection
  deep      + nikto, gobuster, enum4linux, sslscan, nuclei (if installed)

${C_BOLD}OPTIONS${C_RESET}
  -w, --wordlist PATH   wordlist for gobuster (deep only)
  -n, --no-portscan     skip nmap entirely
  -t, --timeout-mult N  multiply every tool timeout by N (slow links)
  -o, --output DIR      use DIR as the engagement directory
      --yes             skip the authorisation confirmation
  --help, -h            this help

${C_YELLOW}⚠  Only profile systems you own or have written authorisation to test.${C_RESET}
EOF
}

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
OUTPUT_DIR=""
while (( $# )); do
    case "$1" in
        --help|-h)          usage; exit 0 ;;
        -w|--wordlist)      shift; WORDLIST="${1:-}" ;;
        -n|--no-portscan)   SKIP_PORTSCAN=1 ;;
        -t|--timeout-mult)  shift; TIMEOUT_SCALE="${1:-1}" ;;
        -o|--output)        shift; OUTPUT_DIR="${1:-}" ;;
        --yes|-y)           export CDECK_ASSUME_YES=1 ;;
        quick|standard|deep) DEPTH="$1" ;;
        -*)                 cdeck::error "unknown option: $1"; usage; exit 2 ;;
        *)                  if [[ -z "${TARGET}" ]]; then
                                TARGET="$1"
                            else
                                cdeck::warn "ignoring extra argument: $1"
                            fi ;;
    esac
    shift
done

if [[ -z "${TARGET}" ]]; then
    cdeck::error "no target specified"
    usage
    exit 2
fi
DEPTH="${DEPTH:-$(cdeck::conf_get scanning.default_depth standard)}"
case "${DEPTH}" in
    quick|standard|deep) ;;
    *) cdeck::error "invalid depth '${DEPTH}' (use quick, standard or deep)"; exit 2 ;;
esac
if [[ ! "${TARGET}" =~ ^[a-zA-Z0-9._:/-]+$ ]]; then
    cdeck::error "target contains unexpected characters: ${TARGET}"
    exit 2
fi

# --------------------------------------------------------------------------- #
# Setup
# --------------------------------------------------------------------------- #
cdeck::banner "target profiler" "${TARGET} · depth=${DEPTH}"

if [[ -z "${OUTPUT_DIR}" ]]; then
    BASE_DIR="$(cdeck::conf_get scanning.output_dir "${CDECK_REPORT_DIR}")"
    OUTPUT_DIR="$(cdeck::engagement_dir "${TARGET}" "${BASE_DIR}")"
fi
mkdir -p "${OUTPUT_DIR}"/{raw,logs,evidence,nmap,web,dns}
cdeck::ok "engagement directory: ${OUTPUT_DIR}"

cdeck::legal_warning "profiling ${TARGET}"
cdeck::confirm "Confirm you are authorised to test ${TARGET}?" y "--yes" || {
    cdeck::error "not confirmed - aborting"; exit 1; }

# Detect whether the target is an IP/network or a hostname
IS_IP=0
if [[ "${TARGET}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]{1,2})?$ ]]; then
    IS_IP=1
fi
HOST_FOR_HTTP="${TARGET%%/*}"

# Track what ran for the report
declare -a STAGES_RUN=()
declare -a STAGES_SKIPPED=()
declare -a FINDINGS=()
declare -a TOOLS_MISSING=()

run_stage() {
    # run_stage <name> <output-file> <timeout-seconds> <command...>
    local name="$1" outfile="$2" timeout_s="$3"; shift 3
    timeout_s=$(( timeout_s * TIMEOUT_SCALE ))
    if ! cdeck::has_cmd "$1"; then
        TOOLS_MISSING+=("$1")
        STAGES_SKIPPED+=("${name} (missing: $1)")
        cdeck::warn "${name}: '$1' not installed - skipped"
        return 1
    fi
    cdeck::info "${name} → ${outfile}"
    set +e
    timeout "${timeout_s}" "$@" > "${outfile}" 2>&1
    local rc=$?
    set -e
    if (( rc == 124 )); then
        cdeck::warn "${name}: timed out after ${timeout_s}s"
        STAGES_SKIPPED+=("${name} (timeout)")
        return 1
    fi
    STAGES_RUN+=("${name}")
    return 0
}

# --------------------------------------------------------------------------- #
# Stage 1: passive intelligence (always)
# --------------------------------------------------------------------------- #
cdeck::banner "stage 1" "passive intelligence"

run_stage "whois" "${OUTPUT_DIR}/dns/whois.txt" 60 whois "${TARGET%%/*}" || true

if (( IS_IP == 0 )); then
    for record_type in A AAAA MX NS TXT SOA CAA DNSKEY; do
        cdeck::has_cmd dig || break
        set +e
        dig +short "${record_type}" "${TARGET%%/*}" > "${OUTPUT_DIR}/dns/dig_${record_type}.txt" 2>&1
        set -e
    done
    if cdeck::has_cmd dig; then
        STAGES_RUN+=("dig (A/AAAA/MX/NS/TXT/SOA/CAA/DNSKEY)")
        cdeck::info "DNS records collected"
        # Zone transfer attempt (usually refused, worth trying on misconfigured DNS)
        NS_SERVER="$(dig +short NS "${TARGET%%/*}" | head -1)"
        if [[ -n "${NS_SERVER}" ]]; then
            set +e
            dig axfr "@${NS_SERVER%.}" "${TARGET%%/*}" > "${OUTPUT_DIR}/dns/axfr_attempt.txt" 2>&1
            set -e
            if grep -qE 'XFR size|Transfer failed|communications error' "${OUTPUT_DIR}/dns/axfr_attempt.txt"; then
                if grep -q "XFR size" "${OUTPUT_DIR}/dns/axfr_attempt.txt"; then
                    cdeck::alert "zone transfer SUCCEEDED on ${NS_SERVER} - serious misconfiguration"
                    FINDINGS+=("Zone transfer (AXFR) succeeded against ${NS_SERVER}: the full DNS zone is exposed.")
                else
                    cdeck::debug "zone transfer refused by ${NS_SERVER} (expected)"
                fi
            fi
        fi
    fi
else
    # Reverse DNS for IP targets
    cdeck::has_cmd dig && { set +e; dig +short -x "${TARGET%%/*}" > "${OUTPUT_DIR}/dns/reverse.txt" 2>&1; set -e; }
fi

# HTTP fingerprint
if cdeck::has_cmd whatweb; then
    run_stage "whatweb fingerprint" "${OUTPUT_DIR}/web/whatweb.txt" 90 \
        whatweb -a 3 --color=never "http://${HOST_FOR_HTTP}" || true
else
    TOOLS_MISSING+=("whatweb")
    STAGES_SKIPPED+=("whatweb (missing)")
fi

# TLS certificate inspection (no external tool needed)
if cdeck::has_cmd openssl && command -v timeout >/dev/null; then
    if timeout 10 bash -c "echo | openssl s_client -connect ${HOST_FOR_HTTP}:443 -servername ${HOST_FOR_HTTP} 2>/dev/null" \
        > "${OUTPUT_DIR}/web/tls_certificate.txt" 2>&1; then
        STAGES_RUN+=("TLS certificate inspection")
        if grep -q "Verify return code" "${OUTPUT_DIR}/web/tls_certificate.txt"; then
            verify="$(grep "Verify return code" "${OUTPUT_DIR}/web/tls_certificate.txt" | tail -1)"
            if ! grep -q "Verify return code: 0" <<< "${verify}"; then
                FINDINGS+=("TLS certificate problem: ${verify}")
            fi
        fi
    fi
fi

# --------------------------------------------------------------------------- #
# Stage 2: standard depth
# --------------------------------------------------------------------------- #
if [[ "${DEPTH}" != "quick" ]]; then
    cdeck::banner "stage 2" "port scanning and deeper DNS"

    if (( SKIP_PORTSCAN == 0 )); then
        NMAP_TIMING="$(cdeck::conf_get scanning.nmap_timing T4)"
        NMAP_BASE=(-sS -sC -sV -Pn -T"${NMAP_TIMING#T}" --open)
        [[ "${EUID}" -ne 0 ]] && NMAP_BASE=(-sT -sC -sV -Pn -T"${NMAP_TIMING#T}" --open)
        NMAP_OUT="${OUTPUT_DIR}/nmap/nmap_standard"
        if run_stage "nmap -sC -sV" "${NMAP_OUT}.nmap" 1800 \
            nmap "${NMAP_BASE[@]}" -oN "${NMAP_OUT}.nmap" -oX "${NMAP_OUT}.xml" \
            -oG "${NMAP_OUT}.gnmap" "${TARGET}"; then
            # Extract notable findings from the script output
            while IFS= read -r line; do
                FINDINGS+=("nmap script: ${line}")
            done < <(grep -E '^\|.*(VULNERABLE|CVE-|State: OPEN|Anonymous FTP|Weak)' "${NMAP_OUT}.nmap" 2>/dev/null | head -10 || true)
            OPEN_COUNT="$(grep -c '/tcp.*open' "${NMAP_OUT}.nmap" 2>/dev/null || echo 0)"
            cdeck::ok "nmap found ${OPEN_COUNT} open TCP port(s)"
        fi
    else
        STAGES_SKIPPED+=("nmap (--no-portscan)")
    fi

    if (( IS_IP == 0 )); then
        run_stage "dnsrecon" "${OUTPUT_DIR}/dns/dnsrecon.txt" 300 \
            dnsrecon -d "${TARGET%%/*}" -t std || true
        run_stage "subfinder" "${OUTPUT_DIR}/dns/subfinder.txt" 300 \
            subfinder -d "${TARGET%%/*}" -silent -all || true
        if cdeck::has_cmd amass; then
            run_stage "amass enum" "${OUTPUT_DIR}/dns/amass.txt" 420 \
                amass enum -passive -d "${TARGET%%/*}" || true
        fi
        if [[ -s "${OUTPUT_DIR}/dns/subfinder.txt" ]]; then
            SUBDOMAIN_COUNT="$(wc -l < "${OUTPUT_DIR}/dns/subfinder.txt")"
            cdeck::ok "subfinder discovered ${SUBDOMAIN_COUNT} subdomain(s)"
        fi
    fi

    # Service-specific enumeration for common ports on standard depth too
    if [[ -f "${OUTPUT_DIR}/nmap/nmap_standard.nmap" ]]; then
        if grep -qE '^445/tcp.*open' "${OUTPUT_DIR}/nmap/nmap_standard.nmap"; then
            cdeck::info "SMB detected - running a share listing"
            {
                echo "# SMB share listing for ${TARGET}"
                cdeck::has_cmd smbclient && timeout 120 smbclient -L "//${TARGET%%/*}" -N 2>&1 || echo "smbclient not installed"
                cdeck::has_cmd nmap && timeout 180 nmap -p 445 --script "smb-enum-shares,smb-os-discovery" "${TARGET%%/*}" 2>&1
            } > "${OUTPUT_DIR}/raw/smb_enumeration.txt" 2>&1 || true
            STAGES_RUN+=("SMB enumeration")
            FINDINGS+=("SMB (445/tcp) is exposed - verify share permissions and signing requirements.")
        fi
        if grep -qE '^21/tcp.*open' "${OUTPUT_DIR}/nmap/nmap_standard.nmap"; then
            FTP_BANNER="$(grep -A2 '^21/tcp' "${OUTPUT_DIR}/nmap/nmap_standard.nmap" | head -3)"
            FINDINGS+=("FTP (21/tcp) is exposed: ${FTP_BANNER}")
            if grep -qi "anonymous" "${OUTPUT_DIR}/nmap/nmap_standard.nmap"; then
                FINDINGS+=("Anonymous FTP access is enabled - data may be publicly readable.")
            fi
        fi
    fi
fi

# --------------------------------------------------------------------------- #
# Stage 3: deep depth
# --------------------------------------------------------------------------- #
if [[ "${DEPTH}" == "deep" ]]; then
    cdeck::banner "stage 3" "deep enumeration (slow, noisy)"

    # Web server assessment
    HTTP_PORTS=()
    if [[ -f "${OUTPUT_DIR}/nmap/nmap_standard.nmap" ]]; then
        while read -r port; do HTTP_PORTS+=("${port}"); done < <(
            grep -oE '^[0-9]+/tcp\s+open\s+.*(http|http-proxy|ssl/http)' \
                "${OUTPUT_DIR}/nmap/nmap_standard.nmap" 2>/dev/null | cut -d/ -f1)
    fi
    if (( ${#HTTP_PORTS[@]} == 0 )) && (( IS_IP == 0 )); then
        HTTP_PORTS=(80 443)
    fi

    for port in "${HTTP_PORTS[@]:-}"; do
        [[ -z "${port}" ]] && continue
        SCHEME="http"; (( port == 443 )) && SCHEME="https"
        URL="${SCHEME}://${HOST_FOR_HTTP}:${port}"
        run_stage "nikto (${port})" "${OUTPUT_DIR}/web/nikto_${port}.txt" 900 \
            nikto -host "${URL}" -nointeractive -maxtime 15m || true
        run_stage "sslscan (${port})" "${OUTPUT_DIR}/web/sslscan_${port}.txt" 300 \
            sslscan "${HOST_FOR_HTTP}:${port}" || true

        WORDLIST_TO_USE="${WORDLIST:-/usr/share/wordlists/cyberdeck/common.txt}"
        [[ -f "${WORDLIST_TO_USE}" ]] || WORDLIST_TO_USE="/usr/share/wordlists/dirb/common.txt"
        if [[ -f "${WORDLIST_TO_USE}" ]]; then
            if cdeck::has_cmd gobuster; then
                run_stage "gobuster (${port})" "${OUTPUT_DIR}/web/gobuster_${port}.txt" 900 \
                    gobuster dir -u "${URL}" -w "${WORDLIST_TO_USE}" -q -t 20 -k \
                    --timeout 10s || true
            elif cdeck::has_cmd dirb; then
                run_stage "dirb (${port})" "${OUTPUT_DIR}/web/dirb_${port}.txt" 900 \
                    dirb "${URL}" "${WORDLIST_TO_USE}" -S -r || true
            fi
            if cdeck::has_cmd ffuf; then
                run_stage "ffuf (${port})" "${OUTPUT_DIR}/web/ffuf_${port}.txt" 600 \
                    ffuf -u "${URL}/FUZZ" -w "${WORDLIST_TO_USE}" -mc 200,204,301,302,307,401,403 \
                    -s -t 30 || true
            fi
        else
            cdeck::warn "no wordlist found for directory brute forcing - install seclists or pass --wordlist"
        fi
    done

    if cdeck::has_cmd nuclei; then
        run_stage "nuclei" "${OUTPUT_DIR}/web/nuclei.txt" 1800 \
            nuclei -u "http://${HOST_FOR_HTTP}" -severity critical,high,medium -silent || true
    else
        STAGES_SKIPPED+=("nuclei (not installed)")
    fi

    if cdeck::has_cmd enum4linux; then
        run_stage "enum4linux" "${OUTPUT_DIR}/raw/enum4linux.txt" 600 \
            enum4linux -a "${TARGET%%/*}" || true
        if grep -qiE '\[\+\] (Users|Shares)' "${OUTPUT_DIR}/raw/enum4linux.txt" 2>/dev/null; then
            FINDINGS+=("enum4linux enumerated users/shares over SMB - review the file raw/enum4linux.txt")
        fi
    else
        STAGES_SKIPPED+=("enum4linux (not installed)")
    fi

    if cdeck::has_cmd enum4linux-ng; then
        run_stage "enum4linux-ng" "${OUTPUT_DIR}/raw/enum4linux-ng.json" 600 \
            enum4linux-ng -A -oJ "${OUTPUT_DIR}/raw/enum4linux-ng.json" "${TARGET%%/*}" || true
    fi

    # Metasploit auxiliary scanner (only when the DB is initialised)
    if cdeck::has_cmd msfconsole && [[ -f "${HOME}/.msf4/database.yml" ]]; then
        cdeck::info "metasploit auxiliary scan available - run manually for full control:"
        cdeck::info "  msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS ${TARGET%%/*}; run'"
    fi
fi

# --------------------------------------------------------------------------- #
# Report generation
# --------------------------------------------------------------------------- #
REPORT="${OUTPUT_DIR}/PROFILE.md"
{
    printf '# Target profile: %s\n\n' "${TARGET}"
    printf -- '- **Depth**: %s\n' "${DEPTH}"
    printf -- '- **Date**: %s\n' "$(date -Is)"
    printf -- '- **Operator**: %s\n' "$(cdeck::conf_get general.operator_name operator)"
    printf -- '- **Host**: %s\n' "$(hostname)"
    printf -- '- **Engagement directory**: `%s`\n\n' "${OUTPUT_DIR}"

    printf '## Summary\n\n'
    printf 'This profile was produced by cyberdeck-arsenal `target_profiler.sh`. '
    printf 'Stages marked as skipped either lacked the required tool or timed out; '
    printf 'see the notes below.\n\n'

    printf '## Stages executed\n\n'
    if (( ${#STAGES_RUN[@]} )); then
        for stage in "${STAGES_RUN[@]}"; do printf -- '- ✔ %s\n' "${stage}"; done
    else
        printf -- '- none\n'
    fi
    printf '\n'
    if (( ${#STAGES_SKIPPED[@]} )); then
        printf '## Stages skipped\n\n'
        for stage in "${STAGES_SKIPPED[@]}"; do printf -- '- ⚠ %s\n' "${stage}"; done
        printf '\n'
    fi

    printf '## Findings requiring attention\n\n'
    if (( ${#FINDINGS[@]} )); then
        for finding in "${FINDINGS[@]}"; do printf -- '- ⚠ %s\n' "${finding}"; done
    else
        printf 'No high-signal findings were extracted automatically. Review the raw output below.\n'
    fi
    printf '\n'

    printf '## DNS\n\n```\n'
    for record in A AAAA MX NS TXT; do
        if [[ -s "${OUTPUT_DIR}/dns/dig_${record}.txt" ]]; then
            printf '%s: %s\n' "${record}" "$(tr '\n' ' ' < "${OUTPUT_DIR}/dns/dig_${record}.txt")"
        fi
    done
    printf '```\n\n'

    if [[ -s "${OUTPUT_DIR}/dns/subfinder.txt" ]]; then
        printf '## Subdomains discovered (%s)\n\n```\n' "$(wc -l < "${OUTPUT_DIR}/dns/subfinder.txt")"
        head -50 "${OUTPUT_DIR}/dns/subfinder.txt"
        printf '```\n\n'
    fi

    if [[ -s "${OUTPUT_DIR}/nmap/nmap_standard.nmap" ]]; then
        printf '## Open ports\n\n```\n'
        grep -E '^[0-9]+/tcp\s+open' "${OUTPUT_DIR}/nmap/nmap_standard.nmap" | sort -n || true
        printf '```\n\n'
    fi

    printf '## Raw artefacts\n\n'
    find "${OUTPUT_DIR}" -type f ! -name 'PROFILE.md' -printf -- '- `%P` (%s bytes)\n' | sort

    printf '\n## Suggested next steps\n\n'
    printf -- '1. Review `nmap/nmap_standard.nmap` for service versions and script output.\n'
    printf -- '2. Validate every exposed service against a current CVE database.\n'
    printf -- '3. For web services, review `web/*` and confirm findings manually.\n'
    printf -- '4. Re-run with `deep` depth for full enumeration once noise is acceptable.\n'
    printf -- '5. Import the XML into your reporting tool: `report_generator.py %s`\n' "${OUTPUT_DIR}"
    printf '\n---\n'
    printf 'Generated by cyberdeck-arsenal v%s on %s. Authorised testing only.\n' \
        "${CDECK_VERSION}" "$(date -Is)"
} > "${REPORT}"

cdeck::ok "profile written to ${REPORT}"

# Generate the client-facing report as well when the reporting module is present
REPORT_GEN="${SCRIPT_DIR}/../reporting/report_generator.py"
if [[ -f "${REPORT_GEN}" ]]; then
    cdeck::info "generating the formatted report"
    if python3 "${REPORT_GEN}" "${OUTPUT_DIR}" --formats md,html >/dev/null 2>&1; then
        cdeck::ok "report_generator.py produced the final reports"
    else
        cdeck::warn "report_generator.py could not complete (run it manually for details)"
    fi
fi

# Summary of missing tooling so the operator knows what to install
if (( ${#TOOLS_MISSING[@]} )); then
    cdeck::warn "missing tools (install for deeper coverage): ${TOOLS_MISSING[*]}"
    cdeck::info "install with: sudo pacman -S ${TOOLS_MISSING[*]}"
fi

cdeck::banner "profile complete" "${OUTPUT_DIR}"
exit 0
