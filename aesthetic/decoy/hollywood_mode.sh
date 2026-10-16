#!/usr/bin/env bash
# =============================================================================
# hollywood_mode.sh - the decoy "hard at work" screen
# =============================================================================
#
# Description
# -----------
# Fills the terminal with convincing, entirely fake activity so that a glance
# over your shoulder shows a developer or an analyst deep in their work rather
# than a packet capture. Nothing here touches the network, the radios or the
# filesystem - every line is generated locally.
#
# Scenes (all generated, none of them real):
#   compile     a multi-threaded build with warnings, tests and a green finish
#   audit       a security review with findings, tickets and a fix queue
#   surveillance  a "camera wall" status board with timestamps and checksums
#   ml          a training run with loss curves and epoch tables
#   support     a ticket queue being triaged, with SLA timers
#   mixed       rotates between all of the above (default)
#
# It honours an exit key, runs for a duration, writes a plausible log file so the
# screen has something to tail, and restores the terminal on the way out
# (alternate screen buffer, cursor, colours) even when interrupted.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash 4+, coreutils, awk
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./hollywood_mode.sh                          # mixed scenes until Ctrl-C
#   ./hollywood_mode.sh --scene audit --duration 300
#   ./hollywood_mode.sh --scene compile --speed fast --no-colour
#   ./hollywood_mode.sh --scene support --log /tmp/tickets.log
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../../lib/cyberdeck_common.sh" ]]; then
    # shellcheck source=lib/cyberdeck_common.sh
    source "${SCRIPT_DIR}/../../lib/cyberdeck_common.sh"
elif [[ -f /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh ]]; then
    source /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh
else
    echo "fatal: cyberdeck_common.sh not found" >&2
    exit 1
fi

cdeck::init "hollywood_mode"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"

SCENE="mixed"
DURATION=0
SPEED="normal"
COLOUR=1
LOG_FILE=""
TITLE=""
FAKE_USER="${USER:-operator}"
FAKE_HOST="$(hostname -s 2>/dev/null || echo deck)"
EXIT_KEY=""
STARTED=0
LINES=0

usage() {
    cdeck::usage_header \
        "Fill the screen with convincing, entirely fake activity" \
        "$0 [--scene NAME] [--duration SECONDS] [--speed slow|normal|fast] [--log FILE] [--no-colour]" \
        "$0                            # mixed scenes until interrupted" \
        "$0 --scene audit --duration 600   # ten minutes of an audit" \
        "$0 --scene compile --speed fast    # a build that never ends"
    cat <<EOF

${C_BOLD}SCENES${C_RESET}
  compile        build output: threads, warnings, unit tests, coverage
  audit          security review: findings, severity, tickets, remediation
  surveillance   camera wall: stream health, checksums, retention
  ml             training run: epochs, loss, accuracy, checkpoints
  support        ticket queue: triage, SLA clocks, escalations
  mixed          rotates through all of the above (default)

${C_BOLD}OPTIONS${C_RESET}
  -s, --scene NAME       pick a scene
  -d, --duration SEC     stop after this many seconds (default: forever)
  --speed slow|normal|fast   how fast lines appear
  --log FILE             append the fake output here as well
  --title TEXT           banner text shown in the header
  --user NAME            account shown in the fake prompt
  --host NAME            host shown in the fake prompt
  --exit-key KEY         quit when this key is pressed (single characters only)
  --no-colour            plain output (for a serial console or a photo)
  -q, --quiet            print the banner and exit (sanity check)
  -h, --help             this help
  -V, --version          version

${C_YELLOW}⚠${C_RESET} Every line is generated locally. This script never touches the network.

${C_BOLD}STOPPING${C_RESET}
  Ctrl-C always works. The terminal is restored (cursor, colours, screen buffer)
  by an EXIT trap, so an interrupted run cannot leave a broken shell behind.
EOF
}

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
C_OK=""; C_INFO=""; C_WARN=""; C_ERR=""; C_DIM=""; C_BOLD=""; C_HEAD=""; C_RESET=""
if (( COLOUR )) && [[ -t 1 ]]; then
    C_OK=$'\033[32m'; C_INFO=$'\033[36m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
    C_DIM=$'\033[90m'; C_BOLD=$'\033[1m'; C_HEAD=$'\033[1;32m'; C_RESET=$'\033[0m'
fi

emit() {
    # emit <text> [style]
    local text="$1"
    local style="${2:-}"
    case "${style}" in
        ok)   printf '%s%s%s\n' "${C_OK}" "${text}" "${C_RESET}" ;;
        info) printf '%s%s%s\n' "${C_INFO}" "${text}" "${C_RESET}" ;;
        warn) printf '%s%s%s\n' "${C_WARN}" "${text}" "${C_RESET}" ;;
        err)  printf '%s%s%s\n' "${C_ERR}" "${text}" "${C_RESET}" ;;
        dim)  printf '%s%s%s\n' "${C_DIM}" "${text}" "${C_RESET}" ;;
        bold) printf '%s%s%s\n' "${C_BOLD}" "${text}" "${C_RESET}" ;;
        *)    printf '%s\n' "${text}" ;;
    esac
    LINES=$(( LINES + 1 ))
    if [[ -n "${LOG_FILE}" ]]; then
        printf '%s\n' "${text}" >> "${LOG_FILE}" 2>/dev/null || LOG_FILE=""
    fi
}

fake_timestamp() {
    date '+%Y-%m-%d %H:%M:%S.%3N' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S'
}

sleep_between_lines() {
    local base
    case "${SPEED}" in
        slow) base=90 ;;
        fast) base=4 ;;
        *)    base=22 ;;
    esac
    local jitter=$(( RANDOM % (base + 1) ))
    # sleep accepts fractions of a second
    awk -v ms=$(( base + jitter )) 'BEGIN { printf "%.3f", ms / 1000 }' > /tmp/.hollywood_sleep.$$ 2>/dev/null || true
    local seconds
    seconds="$(cat /tmp/.hollywood_sleep.$$ 2>/dev/null || echo 0.05)"
    rm -f /tmp/.hollywood_sleep.$$ 2>/dev/null || true
    sleep "${seconds}" 2>/dev/null || sleep 1
}

banner() {
    local title="${TITLE:-$1}"
    printf '\n'
    emit "╔════════════════════════════════════════════════════════════════════════════╗" head_only
    emit "║  ${title}" head_only
    emit "║  local session · ${FAKE_USER}@${FAKE_HOST} · engine build 7.4.2 · $(date '+%Y-%m-%d')" head_only
    emit "╚════════════════════════════════════════════════════════════════════════════╝" head_only
}

emit_head() {
    # a bold header without logging it
    printf '%s%s%s\n' "${C_HEAD}" "$1" "${C_RESET}"
    if [[ -n "${LOG_FILE}" ]]; then printf '%s\n' "$1" >> "${LOG_FILE}" 2>/dev/null || true; fi
}

array_pick() {
    local -a items=("$@")
    printf '%s' "${items[$(( RANDOM % ${#items[@]} ))]}"
}

random_hex() {
    printf '%x' "$(( (RANDOM << 8 | RANDOM) & 0xffff ))"
}

# --------------------------------------------------------------------------- #
# Scenes
# --------------------------------------------------------------------------- #
scene_compile() {
    emit_head "[build] starting full rebuild of staging target"
    emit "  cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_ANALYSIS=ON" dim
    local threads=12 i warnings=0
    emit "  ninja: $(awk -v n=${threads} 'BEGIN {print int(n*1.4)}') tasks, ${threads} workers" info
    for (( i = 1; i <= 90; i++ )); do
        local file percent
        file="$(array_pick src/parser/tokenizer.cc src/net/session.cc src/codec/h264.cc \
            src/store/wal.cc src/ui/widgets.cc src/util/alloc.cc libs/vendor/json.cc)"
        percent=$(( i * 100 / 90 ))
        if (( RANDOM % 9 == 0 )); then
            warnings=$(( warnings + 1 ))
            emit "  [$(printf '%3d' "${percent}")%] warning: unused parameter 'ctx' in ${file} [-Wunused-parameter]" warn
        elif (( RANDOM % 14 == 0 )); then
            emit "  [$(printf '%3d' "${percent}")%] warning: comparison of integers of different signs in ${file}" warn
        else
            emit "  [$(printf '%3d' "${percent}")%] building CXX object ${file}.o" dim
        fi
        sleep_between_lines
    done
    emit "  [100%] linking CXX executable bin/engine" info
    emit "[build] $(awk -v w=${warnings} 'BEGIN {print w}') warning(s), 0 error(s) in 4m$(printf '%02d' $(( RANDOM % 60 )))s" ok
    printf '\n'
    emit_head "[test] running ctest -j ${threads} --output-on-failure"
    local suite pass fail
    for suite in core.net core.codec store.wal ui.widgets util.alloc integration.smoke; do
        local total=$(( 20 + RANDOM % 180 ))
        pass=$(( total - (RANDOM % 3) ))
        fail=$(( total - pass ))
        emit "  Test #$(( RANDOM % 400 )): ${suite} .............. Passed  $(( RANDOM % 400 + 20 )) ms" ok
        if (( fail > 0 )); then
            emit "  Test #$(( RANDOM % 400 )): ${suite}.regression ...... Failed  (retry 1 of 3)" warn
        fi
    done
    emit "[test] 100% tests passed, 0 tests failed out of ${pass}" ok
    printf '\n'
    emit_head "[coverage] gcovr summary"
    emit "  lines: 91.$(( RANDOM % 9 ))%   functions: 88.$(( RANDOM % 9 ))%   branches: 79.$(( RANDOM % 9 ))%" info
    printf '\n'
}

scene_audit() {
    emit_head "[audit] scope: 3 subnets, 214 hosts, 61 services enumerated"
    emit "  framework: internal-appsec-v3 · evidence root: /srv/audit/2026-q4" dim
    printf '\n'
    local -a findings=(
        "TLS 1.0 still enabled on 4 endpoints|HIGH|CWE-327|upgrade ciphers to TLS 1.2+"
        "Session cookie missing Secure attribute|MEDIUM|CWE-614|set Secure; SameSite=Lax"
        "Verbose server banner discloses patch level|LOW|CWE-200|set server_tokens off"
        "Unrestricted file upload on /api/v2/import|CRITICAL|CWE-434|validate MIME + extension allow-list"
        "Outdated jQuery 1.9.1 in the admin console|MEDIUM|CWE-1104|upgrade to 3.7.1"
        "Account lockout absent after 20 failed logins|MEDIUM|CWE-307|add exponential backoff"
        "S3 bucket policy allows public list|HIGH|CWE-732|restrict to the CDN principal"
        "Missing HSTS on the apex domain|LOW|CWE-319|add max-age=31536000; includeSubDomains"
    )
    local count=0 finding severity cwe fix
    for finding in "${findings[@]}"; do
        IFS='|' read -r title severity cwe fix <<< "${finding}"
        count=$(( count + 1 ))
        case "${severity}" in
            CRITICAL) emit "  [$(printf '%02d' "${count}")] ${severity} ${title}" err ;;
            HIGH)     emit "  [$(printf '%02d' "${count}")] ${severity} ${title}" warn ;;
            MEDIUM)   emit "  [$(printf '%02d' "${count}")] ${severity} ${title}" info ;;
            *)        emit "  [$(printf '%02d' "${count}")] ${severity} ${title}" dim ;;
        esac
        emit "       ${cwe} · ${fix} · owner $(array_pick platform-team netops appsec data-eng)" dim
        emit "       retest scheduled $(date -d "+$(( RANDOM % 14 + 1 )) days" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')" dim
        sleep_between_lines
    done
    printf '\n'
    emit_head "[review] control coverage"
    local control coverage
    for control in "logging & monitoring|94" "backup & restore|88" "key management|73" \
                   "change management|91" "incident response|66"; do
        IFS='|' read -r name coverage <<< "${control}"
        local bar="" filled=$(( coverage / 5 )) i
        for (( i = 0; i < 20; i++ )); do
            if (( i < filled )); then bar+="█"; else bar+="░"; fi
        done
        emit "  $(printf '%-22s' "${name}") [${bar}] ${coverage}%" info
        sleep_between_lines
    done
    printf '\n'
    emit "[audit] report draft written: findings.md, evidence/ (chain of custody sealed)" ok
    printf '\n'
}

scene_surveillance() {
    emit_head "[wall] 16 streams registered · retention 30 days · clock synced (NTP offset 0.00$(( RANDOM % 99 ))s)"
    printf '\n'
    emit "  $(printf '%-6s %-14s %-10s %-12s %-10s %s' 'CAM' 'STATUS' 'FPS' 'BITRATE' 'DISK' 'CHECKSUM')" bold
    emit "  $(printf '%-6s %-14s %-10s %-12s %-10s %s' '──────' '──────────────' '──────────' '────────────' '──────────' '────────────────')" dim
    local camera status fps bitrate disk checksum i
    for camera in ent-01 ent-02 lobby-a lobby-b yard-n yard-s dock-1 dock-2 \
                  server-rack lab-01 stair-n stair-s lift-1 car-park roof-2 gate-3; do
        status="recording"
        case $(( RANDOM % 10 )) in
            0) status="dropped frames" ;;
            1) status="reconnecting" ;;
        esac
        fps="$(( 24 + RANDOM % 6 )).$(( RANDOM % 10 ))"
        bitrate="$(( 1800 + RANDOM % 900 )) kb/s"
        disk="$(( 30 + RANDOM % 60 ))%"
        checksum="$(random_hex)$(random_hex)"
        if [[ "${status}" == "recording" ]]; then
            emit "  $(printf '%-6s %-14s %-10s %-12s %-10s %s' "${camera}" "${status}" "${fps}" "${bitrate}" "${disk}" "${checksum}")" ok
        else
            emit "  $(printf '%-6s %-14s %-10s %-12s %-10s %s' "${camera}" "${status}" "${fps}" "${bitrate}" "${disk}" "${checksum}")" warn
        fi
        sleep_between_lines
    done
    printf '\n'
    emit_head "[integrity] verifying segment checksums"
    for i in 1 2 3 4 5 6; do
        emit "  segment $(date '+%Y-%m-%d')-$(printf '%02d' $(( i )))/hour-$(( RANDOM % 24 )): $(random_hex)$(random_hex)$(random_hex)$(random_hex) ok" dim
        sleep_between_lines
    done
    printf '\n'
}

scene_ml() {
    emit_head "[train] run 47a3 · resnet-ish · 12.4M params · 8 workers · fp16"
    printf '\n'
    emit "  $(printf '%-8s %-12s %-12s %-12s %-8s %s' 'EPOCH' 'TRAIN LOSS' 'VAL LOSS' 'ACCURACY' 'LR' 'TIME')" bold
    emit "  $(printf '%-8s %-12s %-12s %-12s %-8s %s' '──────' '─────────' '─────────' '──────────' '─────' '─────')" dim
    local epoch loss val_loss accuracy lr i
    loss="2.31"
    for (( epoch = 1; epoch <= 24; epoch++ )); do
        loss="$(awk -v l="${loss}" 'BEGIN { printf "%.4f", l * 0.87 }')"
        val_loss="$(awk -v l="${loss}" 'BEGIN { printf "%.4f", l * 1.06 }')"
        accuracy="$(awk -v e="${epoch}" 'BEGIN { printf "%.2f", 100 * (1 - 0.9 ^ e) + 0.4 }')"
        lr="$(awk -v e="${epoch}" 'BEGIN { printf "%.5f", 0.003 * (0.94 ^ e) }')"
        emit "  $(printf '%-8s %-12s %-12s %-12s %-8s %s' "${epoch}/24" "${loss}" "${val_loss}" "${accuracy}%" "${lr}" "$(( RANDOM % 40 + 55 ))s")" info
        if (( epoch % 6 == 0 )); then
            emit "  checkpoint written: checkpoints/epoch_${epoch}_$(random_hex).pt ($(awk 'BEGIN {printf "%.1f", 40 + RANDOM % 20}') MiB)" dim
        fi
        sleep_between_lines
    done
    printf '\n'
    emit "[train] best accuracy $(awk 'BEGIN {printf "%.2f", 93 + RANDOM % 6}')% at epoch 21 · early stopping patience 4" ok
    emit "[eval] confusion matrix written to reports/eval/confusion_$(random_hex).png" ok
    printf '\n'
}

scene_support() {
    emit_head "[queue] 42 open tickets · 3 breaching SLA in <30m · on-call ${FAKE_USER}"
    printf '\n'
    local ticket subject priority status i
    local -a subjects=(
        "VPN drops every 15 minutes for the finance VLAN"
        "Printer queue stuck on the third floor"
        "SSO login loop after the identity provider update"
        "Laptop will not wake from sleep on battery"
        "Shared drive permissions wrong after the group change"
        "Badge reader offline in the west entrance"
        "Email attachment blocked by the new filter policy"
        "Backup job failing with a tape checksum error"
    )
    for i in $(seq 1 18); do
        ticket="INC-$(printf '%06d' $(( 100000 + RANDOM % 899999 )))"
        subject="$(array_pick "${subjects[@]}")"
        case $(( RANDOM % 4 )) in
            0) priority="P1"; status="escalated" ;;
            1) priority="P2"; status="in progress" ;;
            2) priority="P3"; status="triaged" ;;
            *) priority="P4"; status="waiting on user" ;;
        esac
        case "${priority}" in
            P1) emit "  ${ticket}  ${priority}  ${status}  ${subject}" err ;;
            P2) emit "  ${ticket}  ${priority}  ${status}  ${subject}" warn ;;
            *)  emit "  ${ticket}  ${priority}  ${status}  ${subject}" dim ;;
        esac
        if (( RANDOM % 5 == 0 )); then
            emit "       sla: response 00:1$(( RANDOM % 9 )):$(( RANDOM % 60 )) · resolution due $(date -d "+$(( RANDOM % 8 + 1 )) hours" '+%H:%M' 2>/dev/null || echo '%-')" dim
        fi
        sleep_between_lines
    done
    printf '\n'
    emit_head "[housekeeping] auto-triage rules"
    emit "  rule 118 matched 4 tickets → priority raised to P2" info
    emit "  rule 204 matched 1 ticket → assigned to network team" info
    emit "  rule 331 matched 9 tickets → linked to change CHG-$(printf '%05d' $(( RANDOM % 99999 )))" info
    printf '\n'
}

# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
SCENES=( compile audit surveillance ml support )

scenes_for_mode() {
    case "${SCENE}" in
        mixed) printf '%s\n' "${SCENES[@]}" ;;
        compile|audit|surveillance|ml|support) printf '%s\n' "${SCENE}" ;;
        *) return 1 ;;
    esac
}

finish() {
    # Always leave the terminal exactly as we found it
    printf '\n%s' "${C_RESET}"
    if (( COLOUR )) && [[ -t 1 ]]; then
        printf '\033[?25h'          # show the cursor again
    fi
    printf '\n'
    if (( LINES > 0 )) && [[ -t 1 ]]; then
        printf '%s[hollywood] %d line(s) generated · nothing was executed%s\n' \
            "${C_DIM}" "${LINES}" "${C_RESET}"
        printf '%s[hollywood] this was a decoy screen: no network, radio or file access%s\n\n' \
            "${C_DIM}" "${C_RESET}"
    fi
    if [[ -n "${LOG_FILE}" ]]; then
        printf '[hollywood] output also appended to %s\n' "${LOG_FILE}"
    fi
    trap - EXIT
    exit 0
}

run_scene() {
    case "$1" in
        compile)      scene_compile ;;
        audit)        scene_audit ;;
        surveillance) scene_surveillance ;;
        ml)           scene_ml ;;
        support)      scene_support ;;
    esac
}

main() {
    mapfile -t wanted < <(scenes_for_mode)
    if ((${#wanted[@]} == 0)); then
        cdeck::error "unknown scene: ${SCENE}"
        cdeck::info "valid scenes: ${SCENES[*]} mixed"
        return 2
    fi

    if [[ ! -t 1 ]]; then
        # Piped or redirected: emit one scene and stop, so logs stay readable
        emit_head "cyberdeck decoy screen (non-interactive, scene ${SCENE})"
        run_scene "${wanted[0]}"
        return 0
    fi

    trap finish EXIT
    printf '\033[?25l'                     # hide the cursor while the show runs
    if [[ -n "${EXIT_KEY}" ]]; then
        printf '%s[press %s to exit]%s\n' "${C_DIM}" "${EXIT_KEY}" "${C_RESET}"
    fi
    STARTED="$(date +%s)"

    if [[ -n "${EXIT_KEY}" ]]; then
        # Read one key at a time without eating the scrollback
        local key
        while :; do
            for scene in "${wanted[@]}"; do
                banner "${scene} · cyberdeck decoy"
                run_scene "${scene}"
                if (( DURATION > 0 )) && (( $(date +%s) - STARTED >= DURATION )); then
                    finish
                fi
                if read -r -t 0.1 -n 1 key 2>/dev/null; then
                    [[ "${key}" == "${EXIT_KEY}" ]] && finish
                fi
            done
        done
    fi

    while :; do
        for scene in "${wanted[@]}"; do
            banner "${scene} · cyberdeck decoy"
            run_scene "${scene}"
            if (( DURATION > 0 )) && (( $(date +%s) - STARTED >= DURATION )); then
                finish
            fi
            # Interruptible pause between scenes
            sleep 1 2>/dev/null || true
        done
    done
}

while (( $# )); do
    case "$1" in
        --help|-h)        usage; exit 0 ;;
        --version|-V)     printf 'hollywood_mode %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -s|--scene)       shift; SCENE="${1:-mixed}" ;;
        -d|--duration)    shift; DURATION="${1:-0}" ;;
        --speed)          shift; SPEED="${1:-normal}" ;;
        --log)            shift; LOG_FILE="${1:-}" ;;
        --title)          shift; TITLE="${1:-}" ;;
        --user)           shift; FAKE_USER="${1:-operator}" ;;
        --host)           shift; FAKE_HOST="${1:-deck}" ;;
        --exit-key)       shift; EXIT_KEY="${1:-q}" ;;
        --no-colour|--no-color) COLOUR=0 ;;
        -q|--quiet)
            printf 'hollywood_mode %s · scenes: %s mixed\n' "${CDECK_VERSION}" "${SCENES[*]}"
            exit 0 ;;
        *)                cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

case "${SPEED}" in
    slow|normal|fast) : ;;
    *) cdeck::error "speed must be slow, normal or fast"; exit 2 ;;
esac

if [[ -n "${LOG_FILE}" ]]; then
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    if ! : >> "${LOG_FILE}" 2>/dev/null; then
        cdeck::warn "cannot write ${LOG_FILE} - continuing without the log"
        LOG_FILE=""
    else
        printf '# cyberdeck decoy screen log · %s · scene %s\n' "$(cdeck::iso_stamp)" "${SCENE}" >> "${LOG_FILE}"
    fi
fi

if (( DURATION > 0 )); then
    # A hard stop in the background keeps even a busy loop from overrunning
    ( sleep "${DURATION}"; kill -TERM "$$" 2>/dev/null || true ) &
    WATCHDOG=$!
    trap 'kill '"${WATCHDOG}"' 2>/dev/null || true; finish' TERM INT
fi

main
