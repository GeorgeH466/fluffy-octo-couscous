#!/usr/bin/env bash
# =============================================================================
# encrypted_vault.sh - encrypted evidence vault
# =============================================================================
#
# Description
# -----------
# A single encrypted container for the material that must never sit in plain
# text on a deck that might be lost or seized: credentials captured during an
# engagement, client reports, key files, screenshots and case notes.
#
# The vault is a tar archive of a directory tree, encrypted as one file:
#
#   <install>/vault/cyberdeck.vault              gpgsym (AES-256) container
#   <install>/vault/cyberdeck.vault.sha256       integrity manifest
#   <install>/state/vault.session                open session (ramdisk path, pid)
#
# Workflow
#   --init        create an empty vault (prompts twice for the passphrase)
#   --open        decrypt into a tmpfs directory and remember it
#   --add ...     copy files into the open vault
#   --ls          list the vault contents (creates a container if missing)
#   --cat FILE    print one file from the vault
#   --extract     copy the whole vault tree to a directory
#   --close       re-encrypt, shred the plaintext and forget the session
#   --verify      check the container against its sha256 manifest
#   --info        show container path, size, age and session state
#   --rekey       change the passphrase
#
# The plaintext only ever exists inside a tmpfs (RAM) mount while the vault is
# open, and is overwritten with random data before the mount is removed.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: gpg (preferred) or openssl, tar, coreutils, shred
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./encrypted_vault.sh --init
#   ./encrypted_vault.sh --open && ./encrypted_vault.sh --add captures/report.md
#   ./encrypted_vault.sh --ls
#   ./encrypted_vault.sh --close
#   ./encrypted_vault.sh --help
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

cdeck::init "encrypted_vault"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
VAULT_DIR="${CDECK_INSTALL_DIR}/vault"
VAULT_FILE="${VAULT_DIR}/cyberdeck.vault"
MANIFEST="${VAULT_FILE}.sha256"
STATE_FILE="${CDECK_INSTALL_DIR}/state/vault.session"
SESSION_SH="${CDECK_INSTALL_DIR}/state/vault_env.sh"
CIPHER="$(cdeck::conf_get vault.cipher AES256)"
PASSPHRASE_FILE="$(cdeck::conf_get vault.passphrase_file "")"
MOUNT_SIZE="$(cdeck::conf_get vault.size_mb 64)"
MOUNT_SIZE=$(( MOUNT_SIZE * 1024 * 1024 ))

ACTION="info"
PATHS=()
TARGET=""
WANT_CONFIRM=1

usage() {
    cdeck::usage_header \
        "Encrypted vault for captures, reports and credentials" \
        "$0 <--init | --open | --close | --add PATH... | --ls | --cat FILE | --extract [DIR] | --verify | --info | --rekey>" \
        "$0 --init                                  # create the vault" \
        "$0 --open                                  # decrypt into RAM" \
        "$0 --add captures/hashes.txt reports/*.md  # store files" \
        "$0 --ls                                    # list contents" \
        "$0 --close                                 # re-encrypt and wipe" \
        "eval \"\$($0 --env)\"                        # export the open path"
    cat <<EOF

${C_BOLD}OPTIONS${C_RESET}
  --init                 create a new vault (asks for a passphrase twice)
  --open                 decrypt the vault into a tmpfs directory
  --close                re-encrypt, shred the plaintext, clear the session
  --add PATH...          copy files or directories into an open vault
  --rm PATH...           delete paths from an open vault (prompts)
  --ls                   list the vault contents without opening it
  --cat FILE             print a file from the vault to stdout
  --extract [DIR]        extract the whole vault to DIR (default: cwd)
  --verify               verify the container against its sha256 manifest
  --info                 container details and session state (default)
  --rekey                change the passphrase
  --env                  print shell exports for the open vault
  --passphrase-file FILE read the passphrase from FILE (mode 0600 only)
  --mount-size MB        tmpfs size for the plaintext (default ${LOOSE_MB:-64})
  --yes                  skip confirmations
  --help, -h             this help

${C_BOLD}WHAT ENDS UP ON DISK${C_RESET}
  ${VAULT_FILE}
      one AES-256 encrypted tar file; nothing else in the vault directory
      contains plaintext, ever
  ${MANIFEST}
      sha256 of the container, checked by --verify
  ${STATE_FILE}
      only the tmpfs path and pid while the vault is open

${C_YELLOW}⚠  A lost passphrase means a lost vault.${C_RESET}
  There is no recovery path and no backdoor. Write it down once, store it
  somewhere physical, and never keep it on this machine.
EOF
}

# --------------------------------------------------------------------------- #
# Arguments
# --------------------------------------------------------------------------- #
while (( $# )); do
    case "$1" in
        --help|-h)        usage; exit 0 ;;
        --version|-V)     printf 'encrypted_vault %s\n' "${CDECK_VERSION}"; exit 0 ;;
        --init)           ACTION="init" ;;
        --open)           ACTION="open" ;;
        --close)          ACTION="close" ;;
        --add)            ACTION="add" ;;
        --rm|--remove)    ACTION="remove" ;;
        --ls|--list)      ACTION="list" ;;
        --cat)            shift; ACTION="cat"; TARGET="${1:-}" ;;
        --extract)        ACTION="extract"
                          if [[ -n "${2:-}" && "${2:0:1}" != "-" ]]; then TARGET="$2"; shift; fi ;;
        --verify)         ACTION="verify" ;;
        --info|--status)  ACTION="info" ;;
        --rekey)          ACTION="rekey" ;;
        --env)            ACTION="env" ;;
        --passphrase-file) shift; PASSPHRASE_FILE="${1:-}" ;;
        --mount-size)     shift; MOUNT_SIZE=$(( ${1:-64} * 1024 * 1024 )) ;;
        --yes|-y)         export CDECK_ASSUME_YES=1; WANT_CONFIRM=0 ;;
        --)               shift
                          while (( $# )); do PATHS+=("$1"); shift; done
                          break ;;
        -*)               cdeck::error "unknown option: $1"; usage; exit 2 ;;
        *)                PATHS+=("$1") ;;
    esac
    shift
done

# Treat bare arguments as paths to add
if (( ${#PATHS[@]} )) && [[ "${ACTION}" == "info" ]]; then
    ACTION="add"
fi

# --------------------------------------------------------------------------- #
# Crypto backend
# --------------------------------------------------------------------------- #
detect_backend() {
    if cdeck::has_cmd gpg; then
        BACKEND="gpg"
    elif cdeck::has_cmd openssl; then
        BACKEND="openssl"
        cdeck::warn "gpg is not installed - falling back to openssl enc (AES-256)"
        cdeck::info "install gnupg for a memory-hard passphrase KDF: sudo pacman -S gnupg"
    else
        cdeck::error "neither gpg nor openssl is installed"
        cdeck::info "install with: sudo pacman -S gnupg openssl"
        return 1
    fi
    return 0
}

gpg_args() {
    # Symmetric AES-256 with SHA-512 KDF; --batch keeps it non-interactive when a
    # passphrase file is configured.
    local args=(--symmetric --cipher-algo "${CIPHER}" --s2k-mode 3 --s2k-count 65011712
                --s2k-digest-algo SHA512 --compress-algo zlib --quiet --yes)
    if [[ -n "${PASSPHRASE_FILE}" ]]; then
        [[ -r "${PASSPHRASE_FILE}" ]] || {
            cdeck::error "passphrase file not readable: ${PASSPHRASE_FILE}"; return 1; }
        local mode
        mode="$(stat -c '%a' "${PASSPHRASE_FILE}" 2>/dev/null || echo "?")"
        if [[ "${mode}" != "600" && "${mode}" != "400" ]]; then
            cdeck::error "passphrase file ${PASSPHRASE_FILE} has mode ${mode}; use chmod 600"
            return 1
        fi
        args+=(--batch --passphrase-file "${PASSPHRASE_FILE}")
    fi
    printf '%s\n' "${args[@]}"
}

gpg_decrypt_args() {
    local args=(--decrypt --quiet)
    if [[ -n "${PASSPHRASE_FILE}" ]]; then
        args+=(--batch --passphrase-file "${PASSPHRASE_FILE}")
    fi
    printf '%s\n' "${args[@]}"
}

resolve_passphrase() {
    # Print a passphrase for the openssl backend, prompting if necessary.
    if [[ -n "${PASSPHRASE_FILE}" ]]; then
        [[ -r "${PASSPHRASE_FILE}" ]] || {
            cdeck::error "passphrase file not readable: ${PASSPHRASE_FILE}"; return 1; }
        cat "${PASSPHRASE_FILE}"
        return 0
    fi
    local pass1 pass2 prompt
    prompt="${1:-Vault passphrase: }"
    read -r -s -p "${prompt}" pass1; printf '\n' >&2
    if [[ "${2:-once}" == "twice" ]]; then
        read -r -s -p "Repeat passphrase: " pass2; printf '\n' >&2
        [[ "${pass1}" == "${pass2}" ]] || { cdeck::error "passphrases do not match"; return 1; }
        if (( ${#pass1} < 12 )); then
            cdeck::warn "short passphrase: use at least 12 characters, ideally a passphrase"
        fi
    fi
    [[ -n "${pass1}" ]] || { cdeck::error "empty passphrase refused"; return 1; }
    printf '%s' "${pass1}"
    return 0
}

encrypt_stream() {
    # encrypt_stream <plaintext-tar> <output>
    local source="$1" output="$2"
    case "${BACKEND}" in
        gpg)
            local -a args
            mapfile -t args < <(gpg_args) || return 1
            if gpg "${args[@]}" -o "${output}" "${source}"; then
                return 0
            fi
            cdeck::error "encryption failed (gpg)"
            return 1
            ;;
        openssl)
            local pass
            pass="$(resolve_passphrase "Vault passphrase: " once)" || return 1
            if openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
                    -pass "pass:${pass}" -in "${source}" -out "${output}" 2>/dev/null; then
                unset pass
                return 0
            fi
            cdeck::error "encryption failed (openssl)"
            return 1
            ;;
    esac
    return 1
}

decrypt_stream() {
    # decrypt_stream <container> <output-file-or-dir>
    local container="$1" output="$2"
    case "${BACKEND}" in
        gpg)
            local -a args
            mapfile -t args < <(gpg_decrypt_args) || return 1
            gpg "${args[@]}" -o "${output}" "${container}" 2>/dev/null && return 0
            cdeck::error "decryption failed - wrong passphrase or corrupt vault"
            return 1
            ;;
        openssl)
            local pass
            pass="$(resolve_passphrase "Vault passphrase: " once)" || return 1
            if openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
                    -pass "pass:${pass}" -in "${container}" -out "${output}" 2>/dev/null; then
                unset pass
                return 0
            fi
            unset pass
            cdeck::error "decryption failed - wrong passphrase or corrupt vault"
            return 1
            ;;
    esac
    return 1
}

# --------------------------------------------------------------------------- #
# Session handling (tmpfs plaintext directory)
# --------------------------------------------------------------------------- #
session_dir() {
    [[ -f "${STATE_FILE}" ]] || return 1
    local dir
    dir="$(awk -F= '/^path=/ {print $2}' "${STATE_FILE}")"
    [[ -d "${dir}" ]] || return 1
    printf '%s' "${dir}"
    return 0
}

is_open() {
    session_dir >/dev/null 2>&1
}

mount_tmpfs() {
    local target="$1"
    mkdir -p "${target}"
    if cdeck::has_cmd mount; then
        # 2>/dev/null: a failed mount is fine, we fall back to a normal mkdir
        if mount -t tmpfs -o "size=${MOUNT_SIZE},mode=0700,noexec" tmpfs "${target}" 2>/dev/null; then
            return 0
        fi
    fi
    cdeck::warn "could not create a tmpfs mount (needs root) - using a directory with 0700"
    cdeck::warn "plaintext will be written to disk while the vault is open"
    chmod 0700 "${target}"
    return 0
}

open_vault() {
    if is_open; then
        cdeck::warn "the vault is already open at $(session_dir)"
        cdeck::info "close it first with: $0 --close"
        return 1
    fi
    [[ -f "${VAULT_FILE}" ]] || {
        cdeck::error "no vault at ${VAULT_FILE}"
        cdeck::info "create one with: $0 --init"
        return 1
    }
    detect_backend || return 1

    local workdir
    workdir="$(mktemp -d /run/cyberdeck-vault.XXXXXX 2>/dev/null || mktemp -d "${TMPDIR:-/tmp}/cyberdeck-vault.XXXXXX")"
    chmod 0700 "${workdir}"
    if [[ "${workdir}" != /run/* ]]; then
        cdeck::warn "using ${workdir} instead of /run - if this is not a tmpfs the"
        cdeck::warn "plaintext will touch disk until --close shreds it"
    fi

    mount_tmpfs "${workdir}"
    local tarball="${workdir}/.vault.tar.gz"
    if ! decrypt_stream "${VAULT_FILE}" "${tarball}"; then
        rm -rf "${workdir}"
        return 1
    fi
    if ! tar -xzf "${tarball}" -C "${workdir}" 2>/dev/null; then
        cdeck::warn "the decrypted data is not a valid tar archive"
        cdeck::info "it will still be made available so nothing is lost"
        mv "${tarball}" "${workdir}/vault_contents.bin"
    else
        shred -u "${tarball}" 2>/dev/null || rm -f "${tarball}"
    fi

    mkdir -p "${workdir}/contents"
    # If the archive stored a top-level directory, flatten it into contents/
    if [[ -d "${workdir}/cyberdeck-vault" ]]; then
        shopt -s dotglob nullglob
        mv "${workdir}/cyberdeck-vault/"* "${workdir}/contents/" 2>/dev/null || true
        shopt -u dotglob nullglob
        rmdir "${workdir}/cyberdeck-vault" 2>/dev/null || true
    fi

    mkdir -p "${CDECK_INSTALL_DIR}/state"
    {
        printf 'path=%s\n' "${workdir}"
        printf 'contents=%s\n' "${workdir}/contents"
        printf 'opened=%s\n' "$(date -Is)"
        printf 'pid=%s\n' "$$"
        printf 'backend=%s\n' "${BACKEND}"
    } > "${STATE_FILE}"
    chmod 0600 "${STATE_FILE}"
    {
        printf 'export CYBERDECK_VAULT_OPEN=%s\n' "${workdir}/contents"
        printf 'export CYBERDECK_VAULT_FILE=%s\n' "${VAULT_FILE}"
    } > "${SESSION_SH}"
    chmod 0600 "${SESSION_SH}"

    local count
    count="$(find "${workdir}/contents" -type f 2>/dev/null | wc -l | tr -d ' ')"
    cdeck::ok "vault open at ${workdir}/contents (${count} file(s))"
    cdeck::info "add files : $0 --add <path>..."
    cdeck::info "close it  : $0 --close"
    return 0
}

shred_path() {
    local target="$1"
    [[ -e "${target}" ]] || return 0
    if cdeck::has_cmd shred; then
        if [[ -d "${target}" ]]; then
            find "${target}" -type f -print0 2>/dev/null | xargs -0 -r shred -u 2>/dev/null || true
            rm -rf "${target}"
        else
            shred -u "${target}" 2>/dev/null || rm -f "${target}"
        fi
    else
        find "${target}" -type f -exec sh -c 'dd if=/dev/urandom of="$1" bs=1k count=1 conv=notrunc 2>/dev/null' _ {} \; 2>/dev/null || true
        rm -rf "${target}"
    fi
    return 0
}

close_vault() {
    local directory
    if ! directory="$(session_dir)"; then
        cdeck::info "the vault is not open"
        return 0
    fi
    local contents="${directory}/contents"
    if [[ ! -d "${contents}" ]]; then
        cdeck::error "session state points at ${directory} but it holds no contents"
        cdeck::warn "refusing to delete anything - inspect it manually, then remove ${STATE_FILE}"
        return 1
    fi

    detect_backend || return 1
    local stages
    stages="$(mktemp -d "${directory}/.staging.XXXXXX")" || return 1
    mkdir -p "${stages}/cyberdeck-vault"
    shopt -s dotglob nullglob
    cp -a "${contents}/"* "${stages}/cyberdeck-vault/" 2>/dev/null || true
    shopt -u dotglob nullglob

    local tarball="${stages}/.vault.tar.gz"
    if ! tar -czf "${tarball}" -C "${stages}" cyberdeck-vault 2>/dev/null; then
        cdeck::error "could not archive the vault contents - nothing was changed"
        rm -rf "${stages}"
        return 1
    fi
    local encrypted="${stages}/.vault.enc"
    if ! encrypt_stream "${tarball}" "${encrypted}"; then
        cdeck::error "encryption failed - the existing vault was left untouched"
        shred_path "${stages}"
        return 1
    fi

    # Rotate: keep one previous generation so a corruption cannot lose everything
    if [[ -f "${VAULT_FILE}" ]]; then
        mv "${VAULT_FILE}" "${VAULT_FILE}.previous" 2>/dev/null || true
    fi
    install -m 0600 "${encrypted}" "${VAULT_FILE}"
    if cdeck::has_cmd sha256sum; then
        sha256sum "${VAULT_FILE}" | awk '{print $1"  "FILENAME}' > "${MANIFEST}"
        chmod 0600 "${MANIFEST}"
    fi
    shred_path "${stages}"

    # Wipe the plaintext and take the tmpfs down
    shred_path "${contents}"
    if mountpoint -q "${directory}" 2>/dev/null; then
        umount "${directory}" 2>/dev/null && cdeck::ok "tmpfs unmounted (RAM released)" \
            || cdeck::warn "could not unmount ${directory} - unmount it manually"
    fi
    rm -rf "${directory}" 2>/dev/null || true
    rm -f "${STATE_FILE}" "${SESSION_SH}"
    cdeck::ok "vault closed and re-encrypted: ${VAULT_FILE} ($(du -h "${VAULT_FILE}" | cut -f1))"
    log_event "vault closed (${VAULT_FILE})" INFO
    return 0
}

init_vault() {
    [[ -f "${VAULT_FILE}" ]] && {
        cdeck::warn "a vault already exists at ${VAULT_FILE}"
        cdeck::confirm "Replace it? The existing vault cannot be recovered" n || {
            cdeck::info "keeping the existing vault"; return 0; }
        mv "${VAULT_FILE}" "${VAULT_FILE}.$(cdeck::stamp)" || return 1
    }
    detect_backend || return 1
    mkdir -p "${VAULT_DIR}"
    chmod 0700 "${VAULT_DIR}"

    local stages
    stages="$(mktemp -d)" || return 1
    mkdir -p "${stages}/cyberdeck-vault/credentials" "${stages}/cyberdeck-vault/reports" \
             "${stages}/cyberdeck-vault/captures"
    cat > "${stages}/cyberdeck-vault/README.txt" <<EOF
cyberdeck-arsenal encrypted vault
=================================
Created: $(date -Is)

Suggested layout
  credentials/   captured hashes, cookies, API keys, SSH keys
  reports/       client deliverables, ready and in progress
  captures/      pcaps, handshakes and screenshots worth keeping
  notes/         case notes and timeline entries

Everything in this tree is stored in ONE AES-256 encrypted file. Nothing is
written to disk in plaintext: --open decrypts into a tmpfs (RAM) directory and
--close shreds that directory before re-encrypting.

Passphrase policy
  * at least 16 characters, ideally a four-word phrase
  * never the same as any other credential on this deck
  * written down once and stored physically, never on this machine
EOF
    mkdir -p "${stages}/cyberdeck-vault/notes"

    local tarball="${stages}/.vault.tar.gz"
    tar -czf "${tarball}" -C "${stages}" cyberdeck-vault
    if ! encrypt_stream "${tarball}" "${VAULT_FILE}.new"; then
        cdeck::error "vault creation failed"
        shred_path "${stages}"
        rm -f "${VAULT_FILE}.new"
        return 1
    fi
    install -m 0600 "${VAULT_FILE}.new" "${VAULT_FILE}"
    rm -f "${VAULT_FILE}.new"
    shred_path "${stages}"

    sha256sum "${VAULT_FILE}" | awk '{print $1"  "FILENAME}' > "${MANIFEST}"
    chmod 0600 "${MANIFEST}"
    cdeck::ok "vault created: ${VAULT_FILE} ($(du -h "${VAULT_FILE}" | cut -f1))"
    cdeck::info "open it with: $0 --open"
    log_event "vault created" INFO
    return 0
}

add_paths() {
    local contents
    if ! contents="$(session_dir)"; then
        cdeck::error "the vault is closed"
        cdeck::info "open it first: $0 --open"
        return 1
    fi
    contents="${contents}/contents"
    (( ${#PATHS[@]} )) || { cdeck::error "--add needs at least one path"; return 2; }

    local added=0 skipped=0 path destination
    for path in "${PATHS[@]}"; do
        if [[ ! -e "${path}" ]]; then
            cdeck::warn "skipping ${path}: no such file or directory"
            skipped=$(( skipped + 1 ))
            continue
        fi
        destination="${contents}/$(basename "${path}")"
        if [[ -e "${destination}" ]]; then
            cdeck::warn "${basename "${path}"} is already in the vault"
            cdeck::confirm "Overwrite it?" n || { skipped=$(( skipped + 1 )); continue; }
            rm -rf "${destination}"
        fi
        cp -a "${path}" "${destination}" && {
            added=$(( added + 1 ))
            cdeck::ok "added $(basename "${path}")"
        } || {
            cdeck::error "could not copy ${path} into the vault"
            skipped=$(( skipped + 1 ))
        }
    done
    cdeck::info "${added} path(s) added, ${skipped} skipped"
    cdeck::warn "remember: nothing is encrypted until you run --close"
    return 0
}

remove_paths() {
    local contents
    if ! contents="$(session_dir)"; then
        cdeck::error "the vault is closed"; return 1
    fi
    contents="${contents}/contents"
    (( ${#PATHS[@]} )) || { cdeck::error "--rm needs at least one path"; return 2; }
    local path destination
    for path in "${PATHS[@]}"; do
        destination="${contents}/${path#/}"
        if [[ -e "${destination}" ]]; then
            cdeck::confirm "Delete ${path} from the vault?" n || continue
            shred_path "${destination}"
            cdeck::ok "removed ${path}"
        else
            cdeck::warn "not in the vault: ${path}"
        fi
    done
    return 0
}

list_vault() {
    if is_open; then
        cdeck::banner "vault contents (open)" "$(session_dir)/contents"
        ( cd "$(session_dir)/contents" && find . -mindepth 1 -maxdepth 3 -printf '    %y %10s  %p\n' 2>/dev/null | sort -k3 )
        return 0
    fi
    [[ -f "${VAULT_FILE}" ]] || { cdeck::error "no vault at ${VAULT_FILE}"; return 1; }
    detect_backend || return 1
    local stages
    stages="$(mktemp -d)" || return 1
    if ! decrypt_stream "${VAULT_FILE}" "${stages}/vault.tar.gz"; then
        shred_path "${stages}"; return 1
    fi
    cdeck::banner "vault contents" "$(basename "${VAULT_FILE}")"
    tar -tzf "${stages}/vault.tar.gz" 2>/dev/null | sed 's/^/    /' | head -200
    shred_path "${stages}"
    return 0
}

cat_file() {
    [[ -n "${TARGET}" ]] || { cdeck::error "--cat needs a file name"; return 2; }
    if is_open; then
        local contents="${1:-}" path
        contents="$(session_dir)/contents"
        path="${contents}/${TARGET#/}"
        [[ -f "${path}" ]] || { cdeck::error "not in the vault: ${TARGET}"; return 1; }
        cat "${path}"
        return 0
    fi
    detect_backend || return 1
    local stages
    stages="$(mktemp -d)" || return 1
    if ! decrypt_stream "${VAULT_FILE}" "${stages}/vault.tar.gz"; then
        shred_path "${stages}"; return 1
    fi
    local extracted
    if tar -xzf "${stages}/vault.tar.gz" -C "${stages}" \
            "cyberdeck-vault/${TARGET#/}" 2>/dev/null; then
        cat "${stages}/cyberdeck-vault/${TARGET#/}"
    else
        cdeck::error "not in the vault: ${TARGET}"
        shred_path "${stages}"
        return 1
    fi
    shred_path "${stages}"
    return 0
}

extract_vault() {
    local destination="${TARGET:-$(pwd)}"
    [[ -d "${destination}" ]] || { cdeck::error "no such directory: ${destination}"; return 1; }
    detect_backend || return 1
    cdeck::warn "extracting writes plaintext outside the vault: ${destination}"
    cdeck::warn "delete it securely afterwards (shred -u) or keep the copy on encrypted media"
    cdeck::confirm "Extract the whole vault into ${destination}?" n || return 0
    if ! decrypt_stream "${VAULT_FILE}" "${destination}/cyberdeck-vault.tar.gz"; then
        return 1
    fi
    tar -xzf "${destination}/cyberdeck-vault.tar.gz" -C "${destination}" \
        && cdeck::ok "extracted to ${destination}/cyberdeck-vault" \
        || { cdeck::error "extraction failed"; return 1; }
    return 0
}

verify_vault() {
    [[ -f "${VAULT_FILE}" ]] || { cdeck::error "no vault at ${VAULT_FILE}"; return 1; }
    cdeck::banner "vault integrity" "$(basename "${VAULT_FILE}")"
    if [[ ! -f "${MANIFEST}" ]]; then
        cdeck::warn "no manifest found - creating one now"
        sha256sum "${VAULT_FILE}" | awk '{print $1"  "FILENAME}' > "${MANIFEST}"
        chmod 0600 "${MANIFEST}"
    fi
    local expected actual
    expected="$(awk '{print $1}' "${MANIFEST}")"
    actual="$(sha256sum "${VAULT_FILE}" | awk '{print $1}')"
    if [[ "${expected}" == "${actual}" ]]; then
        cdeck::ok "container matches the manifest"
        printf '    sha256 : %s\n' "${actual}"
        printf '    size   : %s\n' "$(du -h "${VAULT_FILE}" | cut -f1)"
        printf '    mtime  : %s\n' "$(stat -c %y "${VAULT_FILE}" 2>/dev/null)"
        return 0
    fi
    cdeck::alert "the container has CHANGED since the manifest was written"
    printf '    expected: %s\n    actual  : %s\n' "${expected}" "${actual}"
    cdeck::info "this is expected after --close; run --verify right after sealing to reset it"
    return 1
}

vault_info() {
    cdeck::banner "vault" "${VAULT_DIR}"
    printf '\n'
    if [[ -f "${VAULT_FILE}" ]]; then
        printf '    %-14s %s\n' "container" "${VAULT_FILE}"
        printf '    %-14s %s\n' "size" "$(du -h "${VAULT_FILE}" | cut -f1)"
        printf '    %-14s %s\n' "modified" "$(stat -c %y "${VAULT_FILE}" 2>/dev/null | cut -d. -f1)"
        printf '    %-14s %s\n' "permissions" "$(stat -c '%a %U:%G' "${VAULT_FILE}" 2>/dev/null)"
        printf '    %-14s %s\n' "cipher" "${CIPHER} (symmetric)"
        [[ -f "${MANIFEST}" ]] && \
            printf '    %-14s %s\n' "manifest" "$(awk '{print substr($1,1,16)}' "${MANIFEST}")…"
    else
        printf '    %snone - create it with: %s --init%s\n' "${C_YELLOW}" "$0" "${C_RESET}"
    fi
    if is_open; then
        printf '    %-14s %s%s (open)%s\n' "session" "${C_GREEN}" "$(session_dir)" "${C_RESET}"
        printf '    %-14s %s\n' "files" "$(find "$(session_dir)/contents" -type f 2>/dev/null | wc -l | tr -d ' ')"
        [[ -f "${STATE_FILE}" ]] && printf '    %-14s %s\n' "opened" \
            "$(awk -F= '/^opened=/ {print $2}' "${STATE_FILE}")"
    else
        printf '    %-14s %sclosed%s\n' "session" "${C_DIM}" "${C_RESET}"
    fi
    if [[ -f "${VAULT_FILE}.previous" ]]; then
        printf '    %-14s %s\n' "previous" "${VAULT_FILE}.previous ($(du -h "${VAULT_FILE}.previous" | cut -f1))"
    fi
    printf '\n'
    if cdeck::has_cmd gpg; then
        printf '    %sbackend%s gpg (AES-256, SHA-512 KDF, 650M iterations)\n' "${C_BOLD}" "${C_RESET}"
    else
        printf '    %sbackend%s openssl enc (AES-256-CBC, pbkdf2 600k iterations)\n' "${C_BOLD}" "${C_RESET}"
    fi
    printf '\n'
    return 0
}

rekey_vault() {
    [[ -f "${VAULT_FILE}" ]] || { cdeck::error "no vault to re-key"; return 1; }
    detect_backend || return 1
    local stages
    stages="$(mktemp -d)" || return 1
    cdeck::info "decrypting with the current passphrase"
    if ! decrypt_stream "${VAULT_FILE}" "${stages}/vault.tar.gz"; then
        shred_path "${stages}"; return 1
    fi
    cdeck::info "re-encrypting with the new passphrase"
    if ! encrypt_stream "${stages}/vault.tar.gz" "${stages}/vault.new"; then
        cdeck::error "re-keying failed - the existing vault is unchanged"
        shred_path "${stages}"
        return 1
    fi
    install -m 0600 "${stages}/vault.new" "${VAULT_FILE}"
    sha256sum "${VAULT_FILE}" | awk '{print $1"  "FILENAME}' > "${MANIFEST}"
    chmod 0600 "${MANIFEST}"
    shred_path "${stages}"
    cdeck::ok "passphrase changed"
    log_event "vault re-keyed" WARNING
    return 0
}

log_event() {
    local message="$1" severity="${2:-INFO}"
    python3 - "${message}" "${severity}" <<'PYEOF' 2>/dev/null || true
import sys
try:
    sys.path.insert(0, "/opt/cyberdeck-arsenal/lib")
    from cyberlib import Database
    with Database("events") as db:
        db.event("encrypted_vault", "vault", sys.argv[1], sys.argv[2])
except Exception:
    pass
PYEOF
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
mkdir -p "${VAULT_DIR}" "${CDECK_INSTALL_DIR}/state"
chmod 0700 "${VAULT_DIR}" 2>/dev/null || true

case "${ACTION}" in
    init)    init_vault; exit $? ;;
    open)    open_vault; exit $? ;;
    close)   close_vault; exit $? ;;
    add)     add_paths; exit $? ;;
    remove)  remove_paths; exit $? ;;
    list)    list_vault; exit $? ;;
    cat)     cat_file; exit $? ;;
    extract) extract_vault; exit $? ;;
    verify)  verify_vault; exit $? ;;
    rekey)   rekey_vault; exit $? ;;
    env)
        if is_open; then
            cat "${SESSION_SH}" 2>/dev/null || printf 'export CYBERDECK_VAULT_OPEN=%s/contents\n' "$(session_dir)"
        else
            printf '# vault is closed\n' >&2
            exit 1
        fi
        exit 0
        ;;
    info|*)  vault_info
             cdeck::info "quick start: $0 --init → $0 --open → $0 --add <files> → $0 --close"
             exit 0 ;;
esac
