#!/usr/bin/env bash
# =============================================================================
# theme_switcher.sh - apply, preview and rotate the deck's visual themes
# =============================================================================
#
# Description
# -----------
# Themes are plain ``KEY=value`` files under aesthetic/themes/ (cyberpunk,
# stealth, matrix and anything you add). Selecting one applies it everywhere it
# matters on a cyberdeck:
#
#   * writes state/theme.env - the file every other tool sources for colours
#   * updates display.theme in cyberdeck.conf (comments are preserved)
#   * recolours the current terminal through OSC escapes (12/10/11)
#   * recolours the tmux status bar and window list when running inside tmux
#   * regenerates state/conky_active.conf with this theme's colours
#   * writes state/Xresources.cyberdeck for X11 terminals
#   * exports CYBERDECK_THEME_* through /etc/profile.d/cyberdeck-theme.sh (root)
#   * prints the theme's splash art (unless --quiet)
#
# The interactive mode lists the themes with a live colour swatch and asks for a
# number; --cycle moves to the next theme, which is what the tmux binding and
# Super+Shift+y use.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash; optional: tmux, conky, python3 (comment-preserving config)
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./theme_switcher.sh                    # interactive picker
#   ./theme_switcher.sh --list
#   ./theme_switcher.sh --set matrix
#   ./theme_switcher.sh --cycle
#   ./theme_switcher.sh --preview stealth --show
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

cdeck::init "theme_switcher"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
THEME_DIR="${SCRIPT_DIR}/themes"
[[ -d "${THEME_DIR}" ]] || THEME_DIR="${INSTALL_DIR}/aesthetic/themes"
STATE_DIR="${INSTALL_DIR}/state"
ENV_FILE="${STATE_DIR}/theme.env"
XRES_FILE="${STATE_DIR}/Xresources.cyberdeck"
CONKY_FILE="${STATE_DIR}/conky_active.conf"
PROFILE_FILE="/etc/profile.d/cyberdeck-theme.sh"

ACTION=""
THEME=""
QUIET=0
JSON=0
APPLY=1

usage() {
    cdeck::usage_header \
        "Apply, preview and rotate the deck's visual themes" \
        "$0 [--list | --current | --set NAME | --cycle | --preview NAME] [--show] [--no-apply] [--json]" \
        "$0                          # interactive picker with colour swatches" \
        "$0 --list                   # every theme with its palette" \
        "$0 --set matrix             # apply the matrix theme" \
        "$0 --cycle                  # next theme (bound to Super+Shift+y)" \
        "$0 --preview stealth --show # print a theme without applying it"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  --list                 list the available themes (default when not a tty)
  --current              print the active theme
  --set NAME             apply a theme
  --cycle                apply the next theme in the list
  --preview NAME         print a theme's palette, art and settings
  --show                 also dump the theme's variables
  --no-apply             only write the files, do not touch the terminal
  --theme-dir PATH       look for themes somewhere else (${THEME_DIR})
  --install-dir PATH     override the install directory (${INSTALL_DIR})
  --json                 machine-readable output
  -q, --quiet            suppress the splash art
  -h, --help             this help
  -V, --version          version

${C_BOLD}FILES${C_RESET}
  ${ENV_FILE}
  ${XRES_FILE}
  ${CONKY_FILE}
  ${PROFILE_FILE}   (written only when running as root)

${C_YELLOW}⚠${C_RESET} Themes only change look and feel; no theme touches tool behaviour.
EOF
}

# --------------------------------------------------------------------------- #
# Theme handling
# --------------------------------------------------------------------------- #
theme_files() {
    local file
    for file in "${THEME_DIR}"/*.theme; do
        [[ -f "${file}" ]] && printf '%s\n' "${file}"
    done | sort
}

theme_names() {
    local file
    while IFS= read -r file; do
        basename "${file}" .theme
    done < <(theme_files)
}

# theme_value <theme> <KEY> [default]
theme_value() {
    local theme="$1" key="$2" default="${3:-}"
    local file="${THEME_DIR}/${theme}.theme"
    [[ -f "${file}" ]] || { printf '%s' "${default}"; return 0; }
    local value
    value="$(grep -E "^[[:space:]]*${key}=" "${file}" | tail -1 | cut -d= -f2-)"
    if [[ -z "${value}" ]]; then
        printf '%s' "${default}"
        return 0
    fi
    # A quoted multi-line value (the ASCII art) is delimited by single quotes
    if [[ "${value}" == \'* ]]; then
        value="${value#\'}"
        printf '%s' "${value}"
        return 0
    fi
    value="${value%\"}"; value="${value#\"}"
    printf '%s' "${value}"
}

# theme_block <theme> -> prints the whole KEY=value block, safe to source
theme_block() {
    local theme="$1"
    local file="${THEME_DIR}/${theme}.theme"
    [[ -f "${file}" ]] || return 1
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /^[A-Za-z_][A-Za-z0-9_]*=/ { print }
    ' "${file}"
}

theme_exists() {
    [[ -f "${THEME_DIR}/${1}.theme" ]]
}

current_theme() {
    local theme=""
    if [[ -f "${ENV_FILE}" ]]; then
        theme="$(grep -E '^THEME_NAME=' "${ENV_FILE}" | tail -1 | cut -d= -f2-)"
    fi
    if [[ -z "${theme}" ]]; then
        theme="$(cdeck::conf_get display.theme cyberpunk)"
    fi
    printf '%s' "${theme}"
}

hex_to_rgb() {
    local hex="${1#\#}"
    printf '%d;%d;%d' "0x${hex:0:2}" "0x${hex:2:2}" "0x${hex:4:2}"
}

# Print text in a true-colour hex value (falls back to plain text)
hex_print() {
    local hex="$1" text="$2"
    if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
        printf '\033[38;2;%sm%s\033[0m' "$(hex_to_rgb "${hex}")" "${text}"
    else
        printf '%s' "${text}"
    fi
}

# --------------------------------------------------------------------------- #
# Display
# --------------------------------------------------------------------------- #
swatch() {
    local theme="$1"
    local primary secondary accent warning error
    primary="$(theme_value "${theme}" THEME_PRIMARY '#ffffff')"
    secondary="$(theme_value "${theme}" THEME_SECONDARY '#cccccc')"
    accent="$(theme_value "${theme}" THEME_ACCENT '#888888')"
    warning="$(theme_value "${theme}" THEME_WARNING '#ffcc00')"
    error="$(theme_value "${theme}" THEME_ERROR '#ff0000')"
    if [[ -t 1 ]]; then
        printf '\033[48;2;%sm  \033[0m\033[48;2;%sm  \033[0m\033[48;2;%sm  \033[0m\033[48;2;%sm  \033[0m\033[48;2;%sm  \033[0m' \
            "$(hex_to_rgb "${primary}")" "$(hex_to_rgb "${secondary}")" \
            "$(hex_to_rgb "${accent}")" "$(hex_to_rgb "${warning}")" \
            "$(hex_to_rgb "${error}")"
    else
        printf '[%s %s %s %s %s]' "${primary}" "${secondary}" "${accent}" \
            "${warning}" "${error}"
    fi
}

list_themes() {
    local current; current="$(current_theme)"
    if (( JSON )); then
        printf '['
        local first=1 file name
        while IFS= read -r name; do
            (( first )) || printf ','
            first=0
            printf '{"name":"%s","title":"%s","description":"%s","primary":"%s","current":%s}' \
                "${name}" \
                "$(theme_value "${name}" THEME_TITLE "${name}")" \
                "$(theme_value "${name}" THEME_DESCRIPTION '')" \
                "$(theme_value "${name}" THEME_PRIMARY '#ffffff')" \
                "$([[ "${name}" == "${current}" ]] && echo true || echo false)"
        done < <(theme_names)
        printf ']\n'
        return 0
    fi

    cdeck::banner "themes" "install dir ${INSTALL_DIR}"
    printf '  %-4s %-12s %-26s %s\n' "" "THEME" "SWATCH" "DESCRIPTION"
    printf '  %s\n' "$(printf '─%.0s' {1..100})"
    local index=1 name marker
    while IFS= read -r name; do
        marker=" "
        [[ "${name}" == "${current}" ]] && marker="*"
        printf '  %-4s %-12s ' "${marker}${index}" "${name}"
        swatch "${name}"
        printf '  %s\n' "$(theme_value "${name}" THEME_DESCRIPTION '')"
        index=$(( index + 1 ))
    done < <(theme_names)
    printf '\n  %b*%b active theme · switch with: %btheme --set <name>%b or %btheme --cycle%b\n\n' \
        "${C_GREEN}" "${C_RESET}" "${C_BOLD}" "${C_RESET}" "${C_BOLD}" "${C_RESET}"
}

preview_theme() {
    local theme="$1"
    theme_exists "${theme}" || { cdeck::error "no such theme: ${theme}"; return 2; }
    local primary; primary="$(theme_value "${theme}" THEME_PRIMARY '#ffffff')"
    printf '\n  %s · %s\n' \
        "$(hex_print "${primary}" "$(theme_value "${theme}" THEME_TITLE "${theme}")")" \
        "$(theme_value "${theme}" THEME_DESCRIPTION '')"
    printf '  swatch: '; swatch "${theme}"; printf '\n\n'
    local art; art="$(theme_value "${theme}" THEME_SPLASH_ART '')"
    if [[ -n "${art}" ]]; then
        if (( QUIET )); then
            cdeck::info "splash art hidden (--quiet)"
        else
            printf '%s\n' "${art}" | while IFS= read -r line; do hex_print "${primary}" "${line}"; printf '\n'; done
        fi
    fi
    printf '  tagline: %s\n' "$(theme_value "${theme}" THEME_MOTD_TAGLINE '')"
    printf '  motd   : %s\n' "$(theme_value "${theme}" THEME_SPLASH_TAGLINE '')"
    if (( SHOW )); then
        printf '\n  %bvars%b\n' "${C_BOLD}" "${C_RESET}"
        theme_block "${theme}" | sed 's/^/    /'
    fi
    printf '\n'
}

# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #
apply_terminal() {
    local theme="$1"
    [[ -t 1 ]] || return 0
    local bg fg cursor
    bg="$(theme_value "${theme}" THEME_TERM_BG '#101010')"
    fg="$(theme_value "${theme}" THEME_TERM_FG '#dddddd')"
    cursor="$(theme_value "${theme}" THEME_CURSOR "${fg}")"
    # OSC 11 = background, OSC 10 = foreground, OSC 12 = cursor
    printf '\033]11;%s\007\033]10;%s\007\033]12;%s\007' "${bg}" "${fg}" "${cursor}"
}

apply_tmux() {
    local theme="$1"
    [[ -n "${TMUX:-}" ]] || return 0
    cdeck::has_cmd tmux || return 0
    local status_bg status_fg active_bg active_fg
    status_bg="$(theme_value "${theme}" THEME_TMUX_STATUS_BG '#101010')"
    status_fg="$(theme_value "${theme}" THEME_TMUX_STATUS_FG '#00ff00')"
    active_bg="$(theme_value "${theme}" THEME_TMUX_ACTIVE_BG '#00ff00')"
    active_fg="$(theme_value "${theme}" THEME_TMUX_ACTIVE_FG '#000000')"
    tmux set -g status-bg "${status_bg}" 2>/dev/null || true
    tmux set -g status-fg "${status_fg}" 2>/dev/null || true
    tmux set -g status-left-fg "${status_fg}" 2>/dev/null || true
    tmux set -g window-status-current-bg "${active_bg}" 2>/dev/null || true
    tmux set -g window-status-current-fg "${active_fg}" 2>/dev/null || true
    tmux set -g pane-border-fg "${status_fg}" 2>/dev/null || true
    tmux refresh-client -S 2>/dev/null || true
    cdeck::ok "tmux status bar recoloured"
}

apply_conky() {
    local theme="$1"
    local template="${INSTALL_DIR}/config/conky/cyberdeck_conky.conf"
    [[ -f "${template}" ]] || template="${SCRIPT_DIR}/../config/conky/cyberdeck_conky.conf"
    [[ -f "${template}" ]] || { cdeck::info "conky template not found - skipping"; return 0; }
    mkdir -p "${STATE_DIR}"
    # Replace the palette names the template uses with this theme's colours
    sed \
        -e "s/#39ff14/#$(theme_value "${theme}" THEME_CONKY_COLOUR 39ff14)/g" \
        -e "s/#ffb000/#$(theme_value "${theme}" THEME_CONKY_WARN_COLOUR ffb000)/g" \
        -e "s/#ff3355/#$(theme_value "${theme}" THEME_CONKY_CRIT_COLOUR ff3355)/g" \
        "${template}" > "${CONKY_FILE}"
    cdeck::ok "conky configuration written to ${CONKY_FILE}"
    if cdeck::has_cmd conky && pgrep -x conky >/dev/null 2>&1; then
        pkill -USR1 conky 2>/dev/null || true
        cdeck::info "asked a running conky to reload"
    fi
}

apply_xresources() {
    local theme="$1"
    mkdir -p "${STATE_DIR}"
    local primary secondary bg fg
    primary="$(theme_value "${theme}" THEME_PRIMARY '#39ff14')"
    secondary="$(theme_value "${theme}" THEME_SECONDARY '#00d9ff')"
    bg="$(theme_value "${theme}" THEME_BACKGROUND '#0b0f14')"
    fg="$(theme_value "${theme}" THEME_FOREGROUND '#c7f9ff')"
    cat > "${XRES_FILE}" <<EOF
! Generated by theme_switcher.sh for the '${theme}' theme - do not edit by hand
! load with:  xrdb -merge ${XRES_FILE}
*background:   ${bg}
*foreground:   ${fg}
*cursorColor:  ${primary}
*color4:       ${secondary}
*color2:       ${primary}
*color1:       #ff5555
*color11:      #ff5555
URxvt*background: ${bg}
URxvt*foreground: ${fg}
XTerm*background: ${bg}
XTerm*foreground: ${fg}
XTerm*cursorColor: ${primary}
EOF
    cdeck::ok "X11 resources written to ${XRES_FILE}"
    if cdeck::has_cmd xrdb && [[ -n "${DISPLAY:-}" ]]; then
        xrdb -merge "${XRES_FILE}" 2>/dev/null && cdeck::ok "xrdb reloaded" \
            || cdeck::info "xrdb merge failed (non-fatal)"
    fi
}

apply_profile() {
    local theme="$1"
    if [[ "${EUID}" -ne 0 ]]; then
        return 0
    fi
    {
        printf '# Generated by cyberdeck-arsenal theme_switcher.sh - theme: %s\n' "${theme}"
        printf 'export CYBERDECK_THEME=%s\n' "${theme}"
        printf 'export CYBERDECK_THEME_PRIMARY="%s"\n' "$(theme_value "${theme}" THEME_PRIMARY '#39ff14')"
        printf 'export CYBERDECK_THEME_SECONDARY="%s"\n' "$(theme_value "${theme}" THEME_SECONDARY '#00d9ff')"
        printf 'export CYBERDECK_THEME_ACCENT="%s"\n' "$(theme_value "${theme}" THEME_ACCENT '#ff2e88')"
        printf 'export CYBERDECK_THEME_BG="%s"\n' "$(theme_value "${theme}" THEME_BACKGROUND '#0b0f14')"
    } > "${PROFILE_FILE}.tmp" 2>/dev/null || { cdeck::info "cannot write ${PROFILE_FILE} (non-fatal)"; return 0; }
    mv "${PROFILE_FILE}.tmp" "${PROFILE_FILE}"
    chmod 0644 "${PROFILE_FILE}" 2>/dev/null || true
    cdeck::ok "shell profile updated (${PROFILE_FILE})"
}

apply_config() {
    local theme="$1"
    local conf="${CDECK_CONFIG:-${INSTALL_DIR}/cyberdeck.conf}"
    [[ -f "${conf}" ]] || { cdeck::warn "no configuration at ${conf} - display.theme not updated"; return 0; }
    if ! python3 - "${conf}" "${theme}" <<'PYEOF'
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), "lib"))
sys.path.insert(0, "/opt/cyberdeck-arsenal/lib")
from cyberlib import Config
config = Config(sys.argv[1]).load(sys.argv[1])
config.set("display.theme", sys.argv[2])
config.save(sys.argv[1])
PYEOF
    then
        # Fall back to sed, keeping the comment-preserving property
        sed -i "0,/^\([[:space:]]*\)theme:/s//\1theme: ${theme}/" "${conf}" \
            && cdeck::ok "display.theme updated with sed" \
            || cdeck::warn "could not update display.theme"
        return 0
    fi
    cdeck::ok "display.theme updated in ${conf}"
}

apply_theme() {
    local theme="$1"
    theme_exists "${theme}" || { cdeck::error "no such theme: ${theme}"; return 2; }
    mkdir -p "${STATE_DIR}"

    {
        printf '# Generated by theme_switcher.sh on %s - do not edit by hand\n' "$(cdeck::timestamp)"
        printf '# source this file to get the deck palette in shell scripts\n'
        theme_block "${theme}"
    } > "${ENV_FILE}.tmp"
    mv "${ENV_FILE}.tmp" "${ENV_FILE}"
    chmod 0644 "${ENV_FILE}" || true
    cdeck::ok "palette written to ${ENV_FILE}"

    apply_config "${theme}"
    apply_conky "${theme}"
    apply_xresources "${theme}"
    apply_profile "${theme}"
    if (( APPLY )); then
        apply_terminal "${theme}"
        apply_tmux "${theme}"
    fi

    local hooks; hooks="$(theme_value "${theme}" THEME_POST_HOOKS '')"
    if [[ -n "${hooks}" ]]; then
        cdeck::info "running theme hooks: ${hooks}"
        # shellcheck disable=SC2086
        bash -c "${hooks}" || cdeck::warn "a theme hook failed (non-fatal)"
    fi

    cd_tool_log "theme switched to ${theme}"
    return 0
}

cd_tool_log() {
    # Record the change in the shared events database (best effort)
    (
        cd "${INSTALL_DIR}" 2>/dev/null || exit 0
        CYBERDECK_INSTALL_DIR="${INSTALL_DIR}" python3 - "$1" <<'PYEOF' 2>/dev/null || true
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("CYBERDECK_INSTALL_DIR", "/opt/cyberdeck-arsenal"), "lib"))
try:
    from cyberlib import Database
    with Database("events") as db:
        db.event("theme_switcher", "display", sys.argv[1])
except Exception:
    pass
PYEOF
    )
}

cycle_theme() {
    local current; current="$(current_theme)"
    local -a names; mapfile -t names < <(theme_names)
    ((${#names[@]})) || { cdeck::error "no themes found in ${THEME_DIR}"; return 3; }
    local index=0 next i
    for i in "${!names[@]}"; do
        [[ "${names[$i]}" == "${current}" ]] && index=$i
    done
    next="${names[$(( (index + 1) % ${#names[@]} ))]}"
    cdeck::info "${current} → ${next}"
    apply_theme "${next}"
}

interactive_select() {
    local -a names; mapfile -t names < <(theme_names)
    ((${#names[@]})) || { cdeck::error "no themes found in ${THEME_DIR}"; return 3; }
    local current; current="$(current_theme)"
    cdeck::banner "theme switcher" "current: ${current}"
    printf '  %-4s %-12s %-26s %s\n' "#" "THEME" "SWATCH" "DESCRIPTION"
    printf '  %s\n' "$(printf '─%.0s' {1..100})"
    local i=1 name
    for name in "${names[@]}"; do
        local marker=" "
        [[ "${name}" == "${current}" ]] && marker="*"
        printf '  %-4s %-12s ' "${marker}${i}" "${name}"
        swatch "${name}"
        printf '  %s\n' "$(theme_value "${name}" THEME_DESCRIPTION '')"
        i=$(( i + 1 ))
    done
    printf '\n  choose a theme [1-%d, c to cycle, q to quit] ' "${#names[@]}"
    local reply=""
    read -r reply || reply="q"
    case "${reply}" in
        q|Q|"") cdeck::info "no change"; return 0 ;;
        c|C) cycle_theme; return $? ;;
        *[!0-9]*) cdeck::error "not a number: ${reply}"; return 2 ;;
    esac
    if (( reply < 1 || reply > ${#names[@]} )); then
        cdeck::error "choose a number between 1 and ${#names[@]}"
        return 2
    fi
    apply_theme "${names[$(( reply - 1 ))]}"
}

json_summary() {
    local current; current="$(current_theme)"
    printf '{"theme":"%s","title":"%s","primary":"%s","background":"%s","env_file":"%s","themes_dir":"%s"}\n' \
        "${current}" \
        "$(theme_value "${current}" THEME_TITLE "${current}")" \
        "$(theme_value "${current}" THEME_PRIMARY '#39ff14')" \
        "$(theme_value "${current}" THEME_BACKGROUND '#0b0f14')" \
        "${ENV_FILE}" "${THEME_DIR}"
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
SHOW=0
while (( $# )); do
    case "$1" in
        --help|-h)          usage; exit 0 ;;
        --version|-V)       printf 'theme_switcher %s\n' "${CDECK_VERSION}"; exit 0 ;;
        --list|-l)          ACTION="list" ;;
        --current)          ACTION="current" ;;
        --set)              shift; ACTION="set"; THEME="${1:-}" ;;
        --cycle|-c)         ACTION="cycle" ;;
        --preview|-p)       shift; ACTION="preview"; THEME="${1:-}" ;;
        --show)             SHOW=1 ;;
        --no-apply)         APPLY=0 ;;
        --theme-dir)        shift; THEME_DIR="${1:-${THEME_DIR}}" ;;
        --install-dir)      shift; INSTALL_DIR="${1:-${INSTALL_DIR}}"
                            STATE_DIR="${INSTALL_DIR}/state"
                            ENV_FILE="${STATE_DIR}/theme.env"
                            XRES_FILE="${STATE_DIR}/Xresources.cyberdeck"
                            CONKY_FILE="${STATE_DIR}/conky_active.conf" ;;
        --json)             JSON=1 ;;
        -q|--quiet)         QUIET=1 ;;
        --yes|-y)           export CDECK_ASSUME_YES=1 ;;
        *)                  cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

if [[ -z "${ACTION}" ]]; then
    if [[ -t 0 && -t 1 && ${JSON} -eq 0 ]]; then
        ACTION="interactive"
    else
        ACTION="list"
    fi
fi

case "${ACTION}" in
    list)   list_themes ;;
    current)
        if (( JSON )); then json_summary; else printf '%s\n' "$(current_theme)"; fi ;;
    preview)
        [[ -n "${THEME}" ]] || { cdeck::error "--preview needs a theme name"; exit 2; }
        preview_theme "${THEME}" ;;
    set)
        [[ -n "${THEME}" ]] || { cdeck::error "--set needs a theme name"; exit 2; }
        cdeck::banner "theme → ${THEME}" "applying"
        apply_theme "${THEME}" || exit $?
        (( JSON )) && json_summary
        (( QUIET )) || preview_theme "${THEME}"
        ;;
    cycle)
        cycle_theme || exit $?
        (( JSON )) && json_summary
        ;;
    interactive)
        interactive_select || exit $?
        (( JSON )) && json_summary
        ;;
    *)
        cdeck::error "unknown action: ${ACTION}"; exit 2 ;;
esac

exit 0
