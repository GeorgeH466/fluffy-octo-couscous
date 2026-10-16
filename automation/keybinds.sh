#!/usr/bin/env bash
# =============================================================================
# keybinds.sh - install, inspect and document the deck's key bindings
# =============================================================================
#
# Description
# -----------
# Every binding the deck ships lives in one table inside this script, so the
# generated configuration files and the printable cheat sheet can never drift
# apart. It writes marker-delimited blocks (so your own lines are untouched and
# --uninstall is exact) into:
#
#   * tmux        - ~/.tmux.conf sources the shipped config/tmux.conf
#   * X11         - ~/.config/sxhkd/sxhkdrc block launching cdeck actions
#   * Wayland     - ~/.config/sway/config include block with the same actions
#   * i3          - ~/.config/i3/config block, when i3 is the session
#
# Nothing is installed until --install is given; --dry-run shows the exact files
# and lines first, --cheatsheet prints the operator reference, and --test checks
# that the tools each binding calls actually exist.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash; optional: tmux, sxhkd (X11), sway (Wayland), i3
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./keybinds.sh --list
#   ./keybinds.sh --dry-run --install
#   ./keybinds.sh --install --session x11
#   ./keybinds.sh --uninstall
#   ./keybinds.sh --cheatsheet
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

cdeck::init "keybinds"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
MARKER_BEGIN="# >>> cyberdeck-arsenal keybinds >>>"
MARKER_END="# <<< cyberdeck-arsenal keybinds <<<"

ACTION="list"
DRY_RUN=0
SESSION="auto"
BACKUP=1

usage() {
    cdeck::usage_header \
        "Install and document the cyberdeck key bindings" \
        "$0 <--list | --install | --uninstall | --cheatsheet | --test> [--session x11|wayland|tmux|auto] [--dry-run]" \
        "$0 --list                                  # show every binding" \
        "$0 --dry-run --install                     # show what would be written" \
        "$0 --install --session x11                 # lock the desktop bindings to sxhkd" \
        "$0 --cheatsheet                            # print the operator reference" \
        "$0 --uninstall                             # remove the generated blocks"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  -i, --install          write the binding blocks
  -u, --uninstall        remove the binding blocks
  -l, --list             list the bindings (default)
  -c, --cheatsheet       print the cheat sheet
  -t, --test             verify the tools behind the bindings
  --session x11|wayland|tmux|auto   which desktop session to configure
  --install-dir PATH     override the install directory (${INSTALL_DIR})
  --no-backup            do not keep a .bak copy of files you already had
  -n, --dry-run          show what would happen, change nothing
  --yes                  skip confirmations
  --help, -h             this help

${C_BOLD}FILES TOUCHED${C_RESET}
  ~/.tmux.conf                     a source line for config/tmux.conf
  ~/.config/sxhkd/sxhkdrc          desktop bindings (X11)
  ~/.config/sway/config            include block (Wayland)
  ~/.config/i3/config              bindings block (i3)

${C_YELLOW}⚠  Existing lines are never rewritten:${C_RESET} everything this tool adds sits
  between the two cyberdeck marker comments and --uninstall removes exactly that.
EOF
}

# --------------------------------------------------------------------------- #
# The single source of truth for every binding
# --------------------------------------------------------------------------- #
# Fields: keys | context | command | description
BINDINGS=(
    "Super+Shift+h|x11|${INSTALL_DIR}/bin/cdeck dashboard|Launch the main HUD"
    "Super+Shift+t|x11|${INSTALL_DIR}/bin/cdeck status --oneline|Deck status one-liner"
    "Super+Shift+p|x11|${INSTALL_DIR}/bin/cdeck profile \$TARGET|Profile the target in \$TARGET"
    "Super+Shift+y|x11|${INSTALL_DIR}/aesthetic/theme_switcher.sh --cycle|Cycle the theme"
    "Super+Shift+d|x11|${INSTALL_DIR}/bin/cdeck doctor --full|Run the full health check"
    "Super+Shift+v|x11|${INSTALL_DIR}/bin/cdeck vault --open|Open the encrypted vault"
    "Super+Shift+x|x11|${INSTALL_DIR}/utilities/self_destruct.sh --soft --dry-run|Panic button (dry-run first)"
    "Super+Shift+n|x11|${INSTALL_DIR}/bin/cdeck netmap|Open the network map"
    "Super+Shift+r|x11|${INSTALL_DIR}/bin/cdeck rf|Open the RF spectrum view"
    "Super+Shift+k|x11|${INSTALL_DIR}/automation/keybinds.sh --cheatsheet|Show this cheat sheet"
    "Super+Shift+h|wayland|${INSTALL_DIR}/bin/cdeck dashboard|Launch the main HUD"
    "Super+Shift+t|wayland|${INSTALL_DIR}/bin/cdeck status --oneline|Deck status one-liner"
    "Super+Shift+y|wayland|${INSTALL_DIR}/aesthetic/theme_switcher.sh --cycle|Cycle the theme"
    "Super+Shift+v|wayland|${INSTALL_DIR}/bin/cdeck vault --open|Open the encrypted vault"
    "Super+Shift+x|wayland|${INSTALL_DIR}/utilities/self_destruct.sh --soft --dry-run|Panic button (dry-run first)"
    "C-a d|tmux|detach-client|Detach from the session"
    "C-a r|tmux|source-file ${INSTALL_DIR}/config/tmux.conf|Reload the deck tmux config"
    "C-a D|tmux|new-session -A -s deck|Attach or create the deck session"
    "C-a t|tmux|display-popup -E \"${INSTALL_DIR}/bin/cdeck status --oneline\"|Status popup"
)

describe_bindings() {
    local session_filter="${1:-all}"
    printf '\n  %-18s %-9s %-46s %s\n' "KEYS" "CONTEXT" "COMMAND" "WHAT IT DOES"
    printf '  %s\n' "$(printf '─%.0s' {1..108})"
    local entry keys context command description
    for entry in "${BINDINGS[@]}"; do
        IFS='|' read -r keys context command description <<< "${entry}"
        if [[ "${session_filter}" != "all" && "${session_filter}" != "${context}" ]]; then
            continue
        fi
        printf '  %-18s %-9s %-46s %s\n' "${keys}" "${context}" "${command:0:44}" "${description}"
    done
    printf '\n'
}

list_bindings() {
    cdeck::banner "key bindings" "install dir ${INSTALL_DIR}"
    describe_bindings all
    cdeck::info "install them with: $0 --install"
    cdeck::info "print the reference with: $0 --cheatsheet"
}

detect_session() {
    local session="${XDG_SESSION_TYPE:-}"
    if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then printf 'wayland'; return 0; fi
    if [[ -n "${DISPLAY:-}" ]]; then
        if cdeck::has_cmd i3 && pgrep -x i3 >/dev/null 2>&1; then printf 'i3'; return 0; fi
        printf 'x11'; return 0
    fi
    if [[ "${session}" == "wayland" ]]; then printf 'wayland'; return 0; fi
    if [[ "${session}" == "x11" ]]; then printf 'x11'; return 0; fi
    printf 'none'
}

# --------------------------------------------------------------------------- #
# Block helpers
# --------------------------------------------------------------------------- #
backup_file() {
    local file="$1"
    [[ -f "${file}" ]] || return 0
    if grep -qF "${MARKER_BEGIN}" "${file}" 2>/dev/null; then
        return 0
    fi
    if (( BACKUP )); then
        local backup="${file}.cyberdeck.bak"
        if [[ ! -f "${backup}" ]]; then
            cp -a "${file}" "${backup}"
            cdeck::info "backed up ${file} → ${backup}"
        fi
    fi
}

write_block() {
    # write_block <file> <content-file>
    local file="$1" content_file="$2"
    if (( DRY_RUN )); then
        printf '    [dry-run] would write %s:\n' "${file}"
        sed 's/^/      /' "${content_file}" | head -30
        return 0
    fi
    mkdir -p "$(dirname "${file}")"
    backup_file "${file}"
    local tmp; tmp="$(mktemp)"
    if [[ -f "${file}" ]]; then
        # Copy everything except the previous cyberdeck block
        awk -v begin="${MARKER_BEGIN}" -v end="${MARKER_END}" '
            $0 == begin { inside=1; next }
            $0 == end   { inside=0; next }
            inside != 1 { print }
        ' "${file}" > "${tmp}"
    fi
    {
        cat "${tmp}"
        printf '%s\n' "${MARKER_BEGIN}"
        cat "${content_file}"
        printf '%s\n' "${MARKER_END}"
    } > "${file}"
    rm -f "${tmp}"
    cdeck::ok "wrote bindings to ${file}"
}

remove_block() {
    local file="$1"
    [[ -f "${file}" ]] || { cdeck::info "nothing to remove in ${file}"; return 0; }
    if ! grep -qF "${MARKER_BEGIN}" "${file}" 2>/dev/null; then
        cdeck::info "${file} has no cyberdeck block"
        return 0
    fi
    if (( DRY_RUN )); then
        printf '    [dry-run] would remove the cyberdeck block from %s\n' "${file}"
        return 0
    fi
    local tmp; tmp="$(mktemp)"
    awk -v begin="${MARKER_BEGIN}" -v end="${MARKER_END}" '
        $0 == begin { inside=1; next }
        $0 == end   { inside=0; next }
        inside != 1 { print }
    ' "${file}" > "${tmp}"
    # Drop a trailing run of blank lines the removal may leave behind
    python3 - "${tmp}" <<'PYEOF'
import sys
lines = open(sys.argv[1]).read().splitlines()
while lines and not lines[-1].strip():
    lines.pop()
open(sys.argv[1], "w").write("\n".join(lines) + ("\n" if lines else ""))
PYEOF
    mv "${tmp}" "${file}"
    cdeck::ok "removed the cyberdeck block from ${file}"
}

# --------------------------------------------------------------------------- #
# Per-session writers
# --------------------------------------------------------------------------- #
install_tmux() {
    local file="${HOME}/.tmux.conf"
    local tmp; tmp="$(mktemp)"
    {
        printf '# cyberdeck-arsenal: the full tmux configuration lives in the install dir\n'
        printf 'if-shell "[ -f %s/config/tmux.conf ]" "source-file %s/config/tmux.conf"\n' \
            "${INSTALL_DIR}" "${INSTALL_DIR}"
        printf '# C-a r reloads it in place (see the keybinds cheat sheet)\n'
    } > "${tmp}"
    write_block "${file}" "${tmp}"
    rm -f "${tmp}"
}

install_x11() {
    local file="${HOME}/.config/sxhkd/sxhkdrc"
    if ! cdeck::has_cmd sxhkd; then
        cdeck::warn "sxhkd is not installed - the X11 block is still written"
        cdeck::info "install it with: sudo pacman -S sxhkd"
    fi
    local tmp; tmp="$(mktemp)"
    {
        printf '# cyberdeck-arsenal desktop bindings (sxhkd syntax)\n'
        local entry keys context command description
        for entry in "${BINDINGS[@]}"; do
            IFS='|' read -r keys context command description <<< "${entry}"
            [[ "${context}" == "x11" ]] || continue
            printf '# %s\n%s\n\t%s\n\n' "${description}" "${keys}" "${command}"
        done
    } > "${tmp}"
    write_block "${file}" "${tmp}"
    rm -f "${tmp}"
}

install_wayland() {
    local file="${HOME}/.config/sway/config"
    if ! cdeck::has_cmd sway; then
        cdeck::warn "sway is not installed - the Wayland block is still written"
    fi
    local tmp; tmp="$(mktemp)"
    {
        printf '# cyberdeck-arsenal desktop bindings (sway syntax)\n'
        printf 'exec_always %s/bin/cdeck status --json >/dev/null 2>&1\n\n' "${INSTALL_DIR}"
        local entry keys context command description
        for entry in "${BINDINGS[@]}"; do
            IFS='|' read -r keys context command description <<< "${entry}"
            [[ "${context}" == "wayland" ]] || continue
            printf '# %s\nbindsym %s exec %s\n' "${description}" "${keys}" "${command}"
        done
    } > "${tmp}"
    write_block "${file}" "${tmp}"
    rm -f "${tmp}"
}

install_i3() {
    local file="${HOME}/.config/i3/config"
    local tmp; tmp="$(mktemp)"
    {
        printf '# cyberdeck-arsenal desktop bindings (i3 syntax)\n'
        local entry keys context command description
        for entry in "${BINDINGS[@]}"; do
            IFS='|' read -r keys context command description <<< "${entry}"
            [[ "${context}" == "x11" ]] || continue
            printf '# %s\nbindsym %s exec --no-startup-id %s\n' "${description}" "${keys}" "${command}"
        done
    } > "${tmp}"
    write_block "${file}" "${tmp}"
    rm -f "${tmp}"
}

install_all() {
    local session="$1"
    cdeck::banner "installing key bindings" "session ${session}"
    install_tmux
    case "${session}" in
        x11)
            install_x11
            if cdeck::has_cmd i3; then install_i3; fi
            ;;
        i3)
            install_x11
            install_i3
            ;;
        wayland)
            install_wayland
            ;;
        none|auto|*)
            cdeck::warn "no graphical session detected - installing X11 and Wayland blocks"
            install_x11
            install_wayland
            ;;
    esac
    printf '\n'
    cdeck::ok "bindings installed"
    cdeck::info "reload: tmux → C-a r · sxhkd → pkill -USR1 sxhkd · sway → swaymsg reload"
    cdeck::info "the operator reference is: $0 --cheatsheet"
    log_event "key bindings installed for session ${session}"
}

uninstall_all() {
    cdeck::banner "removing key bindings" "session ${SESSION}"
    remove_block "${HOME}/.tmux.conf"
    remove_block "${HOME}/.config/sxhkd/sxhkdrc"
    remove_block "${HOME}/.config/sway/config"
    remove_block "${HOME}/.config/i3/config"
    printf '\n'
    cdeck::ok "done"
    log_event "key bindings removed"
}

cheatsheet() {
    cdeck::banner "operator cheat sheet" "cyberdeck-arsenal ${CDECK_VERSION}"
    printf '\n%s%s%s\n' "${C_BOLD}" "DESKTOP" "${C_RESET}"
    describe_bindings x11
    printf '%s%s%s\n' "${C_BOLD}" "WAYLAND (sway)" "${C_RESET}"
    describe_bindings wayland
    printf '%s%s%s\n' "${C_BOLD}" "TMUX (prefix is C-a)" "${C_RESET}"
    cat <<EOF
  C-a d        detach                     C-a |  split vertically    C-a -  split horizontally
  C-a r        reload the deck config     C-a D  attach/create 'deck' session
  C-a t        status popup               C-a Y  threat ticker popup
  C-a C-t      cycle the theme            C-a ?  list every tmux binding
  C-a [        copy mode (vi keys)        C-a z  zoom the current pane

${C_BOLD}SHELL${C_RESET}
  cdeck / cyberdeck        launch the main HUD
  cdeck scan <target>      network scan            cdeck profile <target>   full profile
  cdeck wifi               wireless survey         cdeck vault             encrypted vault
  cdeck status --oneline   one-line status         cdeck panic             emergency stop
  cdeck doctor --full      health check            cdeck config            edit the config
  engage <name>            start an engagement     disengage                close it
  deck-vitals              system snapshot         deck-help                alias list

${C_BOLD}EMERGENCY${C_RESET}
  Super+Shift+x            panic button (dry-run first, always)
  cdeck panic             stop the platform, keep the data
  sudo utilities/self_destruct.sh --hard --keep-reports    shred local data
EOF
    printf '\n'
}

test_bindings() {
    cdeck::banner "checking the binding targets" "${INSTALL_DIR}"
    local failures=0 entry keys context command description binary
    for entry in "${BINDINGS[@]}"; do
        IFS='|' read -r keys context command description <<< "${entry}"
        binary="$(printf '%s' "${command}" | awk '{print $1}')"
        if [[ -x "${binary}" ]]; then
            printf '  %s✓%s %-52s %s\n' "${C_GREEN}" "${C_RESET}" "${binary}" "${description}"
        elif cdeck::has_cmd "${binary}"; then
            printf '  %s✓%s %-52s %s\n' "${C_GREEN}" "${C_RESET}" "${binary}" "(on PATH)"
        else
            printf '  %s✘%s %-52s missing\n' "${C_RED}" "${C_RESET}" "${binary}"
            failures=$(( failures + 1 ))
        fi
    done
    printf '\n'
    for tool in tmux sxhkd sway i3; do
        if cdeck::has_cmd "${tool}"; then
            cdeck::ok "${tool} is installed"
        else
            cdeck::info "${tool} is not installed (bindings for it would be inert)"
        fi
    done
    if (( failures )); then
        cdeck::warn "${failures} binding target(s) are missing - run setup.sh to install the suite"
        return 1
    fi
    cdeck::ok "every binding target exists"
    return 0
}

log_event() {
    local message="$1"
    python3 - "${message}" <<'PYEOF' 2>/dev/null || true
import sys
try:
    sys.path.insert(0, "/opt/cyberdeck-arsenal/lib")
    from cyberlib import Database
    with Database("events") as db:
        db.event("keybinds", "automation", sys.argv[1])
except Exception:
    pass
PYEOF
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)     usage; exit 0 ;;
        --version|-V)  printf 'keybinds %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -i|--install)  ACTION="install" ;;
        -u|--uninstall) ACTION="uninstall" ;;
        -l|--list)     ACTION="list" ;;
        -c|--cheatsheet) ACTION="cheatsheet" ;;
        -t|--test)     ACTION="test" ;;
        --session)     shift; SESSION="${1:-auto}" ;;
        --install-dir) shift; INSTALL_DIR="${1:-${INSTALL_DIR}}" ;;
        --no-backup)   BACKUP=0 ;;
        -n|--dry-run)  DRY_RUN=1 ;;
        --yes|-y)      export CDECK_ASSUME_YES=1 ;;
        *)             cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

if [[ "${SESSION}" == "auto" ]]; then
    SESSION="$(detect_session)"
fi

case "${ACTION}" in
    list)      list_bindings ;;
    cheatsheet) cheatsheet ;;
    test)      test_bindings ;;
    install)   install_all "${SESSION}" ;;
    uninstall) uninstall_all ;;
    *)         cdeck::error "unknown action ${ACTION}"; exit 2 ;;
esac
