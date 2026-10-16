#!/usr/bin/env bash
# =============================================================================
# web_recon.sh - web application reconnaissance
# =============================================================================
#
# Description
# -----------
# Standard web application assessment pipeline:
#
#   1. reachability and redirect chain          (curl)
#   2. technology fingerprinting                (whatweb)
#   3. web application firewall detection       (wafw00f)
#   4. TLS configuration review                 (sslscan / openssl)
#   5. vulnerability scanning                   (nikto, nuclei)
#   6. content discovery                        (gobuster/ffuf/dirb)
#   7. CMS-specific checks                      (wpscan for WordPress)
#   8. visual evidence                          (cutycapt / eyewitness)
#
# Every step is optional; unavailable tools are reported and skipped. Output is
# stored in a timestamped engagement directory and summarised as markdown.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: curl, whatweb, wafw00f, nikto, nuclei, gobuster, ffuf, dirb,
#               wpscan, cutycapt, eyewitness (all optional beyond curl)
# Licence     : MIT - authorised use only, see docs/LEGAL.md
#
# Usage
# -----
#   ./web_recon.sh https://example.com
#   ./web_recon.sh example.com --wordlist /usr/share/wordlists/cyberdeck/common.txt
#   ./web_recon.sh https://example.com --fast --no-screenshot
#   ./web_recon.sh --help
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

cdeck::init "web_recon"

TARGET=""
WORDLIST=""
FAST=0
SCREENSHOT=1
OUTPUT_DIR=""
EXTRA_URLS=()

# --------------------------------------------------------------------------- #
# Help
# --------------------------------------------------------------------------- #
usage() {
    cdeck::usage_header \
        "Web application reconnaissance pipeline" \
        "$0 <url|host> [options]" \
        "$0 https://example.com" \
        "$0 example.com --wordlist /usr/share/wordlists/cyberdeck/common.txt" \
        "$0 https://10.0.0.5:8443 --fast" \
        "$0 example.com/subpath --no-screenshot"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -w, --wordlist PATH    wordlist for content discovery
  -f, --fast             skip the slow stages (nikto, full nuclei, brute force)
  -s, --no-screenshot    skip visual evidence capture
  -o, --output DIR       engagement directory to use
  -u, --url PATH         additional URL/path to include (repeatable)
      --yes              skip the authorisation confirmation
  --help, -h             this help

${C_YELLOW}⚠  Only test web applications you are authorised to assess.${C_RESET}
EOF
}

while (( $# )); do
    case "$1" in
        --help|-h)          usage; exit 0 ;;
        -w|--wordlist)      shift; WORDLIST="${1:-}" ;;
        -f|--fast)          FAST=1 ;;
        -s|--no-screenshot) SCREENSHOT=0 ;;
        -o|--output)        shift; OUTPUT_DIR="${1:-}" ;;
        -u|--url)           shift; EXTRA_URLS+=("${1:-}") ;;
        --yes|-y)           export CDECK_ASSUME_YES=1 ;;
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

# Normalise the URL
if [[ "${TARGET}" != http://* && "${TARGET}" != https://* ]]; then
    TARGET="https://${TARGET}"
fi
HOST="$(sed -E 's#^https?://##; s#/.*$##' <<< "${TARGET}")"
SCHEME="$(sed -E 's#^(https?)://.*#\1#' <<< "${TARGET}")"

cdeck::require_cmds curl || exit 1
cdeck::banner "web recon" "${TARGET}"

if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="$(cdeck::engagement_dir "${HOST}")"
fi
mkdir -p "${OUTPUT_DIR}"/{web,raw,evidence}
WEB_DIR="${OUTPUT_DIR}/web"

cdeck::legal_warning "web application testing of ${HOST}"
cdeck::confirm "Confirm you are authorised to test ${TARGET}?" y "--yes" || {
    cdeck::error "not confirmed - aborting"; exit 1; }

declare -a FINDINGS=()
declare -a SKIPPED=()
declare -a RUN=()

# --------------------------------------------------------------------------- #
# 1. Reachability, headers, redirects
# --------------------------------------------------------------------------- #
cdeck::info "[1/8] checking reachability and headers"
if curl -sS -k -L -m 20 -o /dev/null -w '%{http_code} %{url_effective}\n' "${TARGET}" \
    > "${WEB_DIR}/reachability.txt" 2>&1; then
    HTTP_CODE="$(awk '{print $1}' < "${WEB_DIR}/reachability.txt")"
    cdeck::ok "reachable (HTTP ${HTTP_CODE})"
    RUN+=("reachability check")
else
    cdeck::warn "target did not respond to curl - continuing anyway"
    SKIPPED+=("reachability (connection failed)")
fi

{ printf '=== curl -I %s ===\n' "${TARGET}"; curl -sSI -k -L -m 20 "${TARGET}" 2>&1 || true;
  printf '\n=== redirect chain ===\n';
  curl -sS -k -L -m 20 -o /dev/null -w '%{num_redirects} redirects, final: %{url_effective}\n' \
      "${TARGET}" 2>&1 || true; } > "${WEB_DIR}/headers.txt" 2>&1

# Security header audit - a classic quick win in any report
{
    missing=()
    for header in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" \
                  "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy"; do
        grep -qi "^${header}:" "${WEB_DIR}/headers.txt" || missing+=("${header}")
    done
    printf '=== missing security headers ===\n'
    if (( ${#missing[@]} )); then
        printf '%s\n' "${missing[@]}"
    else
        printf 'none - all recommended headers present\n'
    fi
} > "${WEB_DIR}/security_headers.txt" 2>&1

if grep -q "missing security headers" "${WEB_DIR}/security_headers.txt"; then
    MISSING_COUNT="$(grep -cE '^[A-Z]' "${WEB_DIR}/security_headers.txt" || echo 0)"
    if grep -qv "none - all" "${WEB_DIR}/security_headers.txt"; then
        FINDINGS+=("${MISSING_COUNT} recommended security header(s) missing - see web/security_headers.txt")
    fi
fi

# --------------------------------------------------------------------------- #
# 2. Technology fingerprint
# --------------------------------------------------------------------------- #
cdeck::info "[2/8] fingerprinting the technology stack"
if cdeck::has_cmd whatweb; then
    timeout 120 whatweb -a 3 --color=never "${TARGET}" > "${WEB_DIR}/whatweb.txt" 2>&1 || true
    RUN+=("whatweb")
    cdeck::ok "whatweb: $(head -1 "${WEB_DIR}/whatweb.txt" | cut -c1-140)"
else
    cdeck::warn "whatweb not installed - install with: sudo pacman -S whatweb"
    SKIPPED+=("whatweb")
fi

# CMS detection from the fingerprint plus a WordPress-specific probe
if grep -qi "wordpress" "${WEB_DIR}/whatweb.txt" 2>/dev/null; then
    FINDINGS+=("WordPress detected - run wpscan for plugin/theme vulnerabilities")
fi
if curl -sSk -m 15 "${TARGET%/}/wp-login.php" -o /dev/null -w '%{http_code}\n' 2>/dev/null | grep -q '^200'; then
    FINDINGS+=("WordPress login page is reachable at /wp-login.php - brute-force exposure")
    if cdeck::has_cmd wpscan && (( FAST == 0 )); then
        cdeck::info "running wpscan (this can take a few minutes)"
        timeout 900 wpscan --url "${TARGET}" --no-banner --disable-tls-checks \
            > "${WEB_DIR}/wpscan.txt" 2>&1 || true
        RUN+=("wpscan")
    fi
fi

# --------------------------------------------------------------------------- #
# 3. WAF detection
# --------------------------------------------------------------------------- #
cdeck::info "[3/8] detecting a web application firewall"
if cdeck::has_cmd wafw00f; then
    timeout 120 wafw00f "${TARGET}" > "${WEB_DIR}/wafw00f.txt" 2>&1 || true
    RUN+=("wafw00f")
    if grep -qi "is behind" "${WEB_DIR}/wafw00f.txt"; then
        WAF_NAME="$(grep -i "is behind" "${WEB_DIR}/wafw00f.txt" | head -1)"
        cdeck::ok "${WAF_NAME}"
        FINDINGS+=("WAF present: ${WAF_NAME} - expect filtering; slow scans and rotate user agents")
    else
        cdeck::info "no WAF detected"
    fi
else
    SKIPPED+=("wafw00f")
fi

# --------------------------------------------------------------------------- #
# 4. TLS review
# --------------------------------------------------------------------------- #
cdeck::info "[4/8] reviewing TLS configuration"
if [[ "${SCHEME}" == "https" ]]; then
    if cdeck::has_cmd sslscan; then
        timeout 300 sslscan --no-colour "${HOST}" > "${WEB_DIR}/sslscan.txt" 2>&1 || true
        RUN+=("sslscan")
        if grep -qE 'SSLv2|SSLv3|TLSv1\.0|TLSv1\.1' "${WEB_DIR}/sslscan.txt"; then
            FINDINGS+=("Legacy TLS/SSL protocols are enabled - see web/sslscan.txt")
        fi
        if grep -qi "Accepted" "${WEB_DIR}/sslscan.txt"; then
            cdeck::debug "sslscan enumerated accepted cipher suites"
        fi
    else
        SKIPPED+=("sslscan")
    fi
    # Certificate sanity check with plain openssl
    timeout 20 bash -c "echo | openssl s_client -connect ${HOST}:443 -servername ${HOST} 2>/dev/null |
        openssl x509 -noout -subject -issuer -dates 2>/dev/null" > "${WEB_DIR}/certificate.txt" 2>&1 || true
    if grep -q "notAfter" "${WEB_DIR}/certificate.txt"; then
        RUN+=("certificate inspection")
        NOT_AFTER="$(grep notAfter "${WEB_DIR}/certificate.txt" | sed 's/notAfter=//')"
        if ! date -d "${NOT_AFTER}" +%s >/dev/null 2>&1; then
            cdeck::debug "could not parse certificate expiry: ${NOT_AFTER}"
        elif (( $(date -d "${NOT_AFTER}" +%s) < $(date +%s) )); then
            FINDINGS+=("TLS certificate EXPIRED on ${NOT_AFTER}")
        fi
    fi
else
    cdeck::warn "target is plain HTTP - credentials and sessions are exposed on the wire"
    FINDINGS+=("No TLS: the site is served over plain HTTP")
fi

# --------------------------------------------------------------------------- #
# 5. Vulnerability scanning
# --------------------------------------------------------------------------- #
cdeck::info "[5/8] vulnerability scanning"
if (( FAST == 0 )) && cdeck::has_cmd nikto; then
    timeout 900 nikto -host "${TARGET}" -nointeractive -maxtime 12m -output "${WEB_DIR}/nikto.txt" \
        -Format txt > /dev/null 2>&1 || true
    RUN+=("nikto")
    if [[ -s "${WEB_DIR}/nikto.txt" ]]; then
        NIKTO_FINDINGS="$(grep -c '^+' "${WEB_DIR}/nikto.txt" 2>/dev/null || echo 0)"
        cdeck::ok "nikto reported ${NIKTO_FINDINGS} item(s)"
        (( NIKTO_FINDINGS > 0 )) && FINDINGS+=("nikto reported ${NIKTO_FINDINGS} item(s) - review web/nikto.txt")
    fi
elif (( FAST == 0 )); then
    SKIPPED+=("nikto")
fi

if cdeck::has_cmd nuclei; then
    SEVERITY="critical,high,medium"
    (( FAST == 1 )) && SEVERITY="critical,high"
    timeout 1800 nuclei -u "${TARGET}" -severity "${SEVERITY}" -silent -no-color \
        -o "${WEB_DIR}/nuclei.txt" > /dev/null 2>&1 || true
    RUN+=("nuclei")
    if [[ -s "${WEB_DIR}/nuclei.txt" ]]; then
        NUCLEI_COUNT="$(wc -l < "${WEB_DIR}/nuclei.txt")"
        cdeck::ok "nuclei found ${NUCLEI_COUNT} template match(es)"
        FINDINGS+=("nuclei matched ${NUCLEI_COUNT} template(s) - review web/nuclei.txt")
        while IFS= read -r hit; do
            FINDINGS+=("nuclei: ${hit}")
        done < <(head -5 "${WEB_DIR}/nuclei.txt")
    fi
else
    SKIPPED+=("nuclei")
fi

# --------------------------------------------------------------------------- #
# 6. Content discovery
# --------------------------------------------------------------------------- #
cdeck::info "[6/8] content discovery"
if (( FAST == 0 )); then
    WORDLIST_TO_USE="${WORDLIST:-}"
    if [[ -z "${WORDLIST_TO_USE}" ]]; then
        for candidate in /usr/share/wordlists/cyberdeck/common.txt \
                         /opt/cyberdeck-arsenal/data/wordlists/common.txt \
                         /usr/share/wordlists/dirb/common.txt \
                         /usr/share/seclists/Discovery/Web-Content/common.txt; do
            [[ -f "${candidate}" ]] && { WORDLIST_TO_USE="${candidate}"; break; }
        done
    fi
    if [[ -n "${WORDLIST_TO_USE}" && -f "${WORDLIST_TO_USE}" ]]; then
        cdeck::info "using wordlist: ${WORDLIST_TO_USE}"
        if cdeck::has_cmd gobuster; then
            timeout 900 gobuster dir -u "${TARGET}" -w "${WORDLIST_TO_USE}" -q -t 20 -k \
                --timeout 10s -o "${WEB_DIR}/gobuster.txt" > /dev/null 2>&1 || true
            RUN+=("gobuster")
            INTERESTING="$(grep -cE '^/' "${WEB_DIR}/gobuster.txt" 2>/dev/null || echo 0)"
            cdeck::ok "gobuster found ${INTERESTING} path(s)"
            while IFS= read -r path; do
                case "${path}" in
                    */admin*|*/.git*|*/backup*|*/config*|*/.env*|*/api/*)
                        FINDINGS+=("sensitive path exposed: ${path}") ;;
                esac
            done < <(grep -E '^/' "${WEB_DIR}/gobuster.txt" 2>/dev/null | head -30 || true)
        fi
        if cdeck::has_cmd ffuf; then
            timeout 900 ffuf -u "${TARGET%/}/FUZZ" -w "${WORDLIST_TO_USE}" \
                -mc 200,204,301,302,307,401,403 -s -t 40 -o "${WEB_DIR}/ffuf.json" \
                -of json > /dev/null 2>&1 || true
            RUN+=("ffuf")
        fi
        if ! cdeck::has_cmd gobuster && ! cdeck::has_cmd ffuf && cdeck::has_cmd dirb; then
            timeout 900 dirb "${TARGET}" "${WORDLIST_TO_USE}" -S -r -o "${WEB_DIR}/dirb.txt" \
                > /dev/null 2>&1 || true
            RUN+=("dirb")
        fi
    else
        cdeck::warn "no wordlist available - skipping content discovery"
        cdeck::info "download one with: cdeck update   (or pass --wordlist)"
        SKIPPED+=("content discovery (no wordlist)")
    fi
else
    SKIPPED+=("content discovery (--fast)")
fi

# --------------------------------------------------------------------------- #
# 7. Additional URLs
# --------------------------------------------------------------------------- #
cdeck::info "[7/8] checking additional paths"
if (( ${#EXTRA_URLS[@]} )); then
    {
        printf '=== extra path checks ===\n'
        for path in "${EXTRA_URLS[@]}"; do
            url="${TARGET%/}/${path#/}"
            code="$(curl -sSk -m 15 -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || echo "err")"
            printf '%-60s %s\n' "${url}" "${code}"
        done
    } > "${WEB_DIR}/extra_paths.txt" 2>&1
    RUN+=("extra path checks")
fi

# --------------------------------------------------------------------------- #
# 8. Visual evidence
# --------------------------------------------------------------------------- #
cdeck::info "[8/8] capturing visual evidence"
if (( SCREENSHOT == 1 )); then
    SHOT="${OUTPUT_DIR}/evidence/screenshot.png"
    if cdeck::has_cmd cutycapt; then
        timeout 120 cutycapt --url="${TARGET}" --out="${SHOT}" --insecure \
            --javascript=on --delay=1500 > /dev/null 2>&1 || true
        [[ -f "${SHOT}" ]] && { RUN+=("screenshot (cutycapt)"); cdeck::ok "screenshot: ${SHOT}"; }
    elif cdeck::has_cmd chromium; then
        timeout 120 chromium --headless --disable-gpu --no-sandbox --hide-scrollbars \
            --screenshot="${SHOT}" --window-size=1440,900 "${TARGET}" > /dev/null 2>&1 || true
        [[ -f "${SHOT}" ]] && { RUN+=("screenshot (chromium)"); cdeck::ok "screenshot: ${SHOT}"; }
    elif cdeck::has_cmd eyewitness; then
        timeout 300 eyewitness --single "${TARGET}" -d "${OUTPUT_DIR}/evidence" \
            --no-prompt > /dev/null 2>&1 || true
        RUN+=("screenshot (eyewitness)")
    elif cdeck::has_cmd wkhtmltoimage; then
        timeout 120 wkhtmltoimage --quiet "${TARGET}" "${SHOT}" > /dev/null 2>&1 || true
        [[ -f "${SHOT}" ]] && RUN+=("screenshot (wkhtmltoimage)")
    else
        SKIPPED+=("screenshots (install cutycapt, chromium or eyewitness)")
    fi
fi

# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
REPORT="${OUTPUT_DIR}/WEB_RECON.md"
{
    printf '# Web reconnaissance: %s\n\n' "${TARGET}"
    printf -- '- **Host**: %s\n' "${HOST}"
    printf -- '- **Scheme**: %s\n' "${SCHEME}"
    printf -- '- **Date**: %s\n' "$(date -Is)"
    printf -- '- **Operator**: %s\n' "$(cdeck::conf_get general.operator_name operator)"
    printf -- '- **Mode**: %s\n\n' "$( (( FAST == 1 )) && echo fast || echo full )"

    printf '## Headline findings\n\n'
    if (( ${#FINDINGS[@]} )); then
        local_index=0
        for finding in "${FINDINGS[@]}"; do
            printf -- '- ⚠ %s\n' "${finding}"
        done
    else
        printf 'No automatic findings. Manual review of the raw output is still required.\n'
    fi
    printf '\n## Stages executed\n\n'
    for stage in "${RUN[@]:-}"; do [[ -n "${stage}" ]] && printf -- '- ✔ %s\n' "${stage}"; done
    printf '\n## Stages skipped\n\n'
    if (( ${#SKIPPED[@]} )); then
        for stage in "${SKIPPED[@]}"; do printf -- '- ⚠ %s\n' "${stage}"; done
    else
        printf -- '- none\n'
    fi
    printf '\n## Server headers\n\n```\n'
    head -30 "${WEB_DIR}/headers.txt" 2>/dev/null || printf 'unavailable\n'
    printf '```\n\n## Raw artefacts\n\n'
    find "${OUTPUT_DIR}" -type f ! -name 'WEB_RECON.md' -printf -- '- `%P` (%s bytes)\n' | sort
    printf '\n---\nGenerated by cyberdeck-arsenal v%s. Authorised testing only.\n' "${CDECK_VERSION}"
} > "${REPORT}"

cdeck::ok "web recon report: ${REPORT}"

REPORT_GEN="${SCRIPT_DIR}/../reporting/report_generator.py"
if [[ -f "${REPORT_GEN}" ]]; then
    python3 "${REPORT_GEN}" "${OUTPUT_DIR}" --formats md,html >/dev/null 2>&1 \
        && cdeck::ok "formatted reports generated in ${OUTPUT_DIR}" \
        || cdeck::warn "report_generator.py did not complete - run it manually"
fi

if (( ${#SKIPPED[@]} )); then
    cdeck::info "install the missing tools for full coverage: sudo pacman -S whatweb wafw00f nikto nuclei gobuster cutycapt"
fi

cdeck::banner "web recon complete" "${OUTPUT_DIR}"
exit 0
