#!/usr/bin/env bash
# ==============================================================================
# utils.sh — dependency checks, validation helpers, and the interactive
#            "ask before every step" menu system.
# ==============================================================================

# ---- dependency handling ----------------------------------------------------

REQUIRED_TOOLS=(nmap ping curl dig)
OPTIONAL_TOOLS=(ftp smbclient enum4linux nc whois traceroute)

check_dependencies() {
    local missing=()
    local tool
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        for tool in "${missing[@]}"; do
            log_fail "$tool is not installed"
        done
        log_info "Install them, e.g.: sudo apt install ${missing[*]}"
        exit "$EXIT_MISSING_DEP"
    fi

    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            AVAILABLE_TOOLS["$tool"]=0
        else
            AVAILABLE_TOOLS["$tool"]=1
        fi
    done
}

tool_available() {
    # Usage: tool_available smbclient && ...
    local tool="$1"
    [[ "${AVAILABLE_TOOLS[$tool]:-0}" == "1" ]]
}

# ---- validation --------------------------------------------------------------

is_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local octet
    for octet in ${ip//./ }; do
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

resolve_target() {
    # Prints the IP for a hostname, or echoes the IP back unchanged.
    local target="$1"
    if is_ip "$target"; then
        printf '%s' "$target"
    else
        getent hosts "$target" 2>/dev/null | awk '{print $1; exit}'
    fi
}

check_reachable() {
    local target="$1"
    ping -c 2 -W 2 "$target" &>/dev/null
}

# ---- interactive menu system --------------------------------------------------
# Every "ask before a step" prompt in KarScan goes through ask_menu so the
# behaviour (numbering, validation, non-interactive fallback) stays consistent.
#
# Usage: ask_menu "<prompt title>" default_index "opt1" "opt2" "opt3" ...
# Returns the chosen option's 1-based index via $MENU_CHOICE.
# When AUTO_MODE=1 (non-interactive / batch mode), it silently picks the
# supplied default and prints what it picked, so logs stay legible.

ask_menu() {
    local title="$1"; shift
    local default_idx="$1"; shift
    local options=("$@")
    local i choice

    printf '\n%s %s%s%s\n' "$SYM_ASK" "$C_BOLD" "$title" "$C_RESET"
    for i in "${!options[@]}"; do
        local marker=" "
        (( i + 1 == default_idx )) && marker="${C_GREEN}*${C_RESET}"
        printf '   %s [%d] %s\n' "$marker" "$((i + 1))" "${options[$i]}"
    done

    if [[ "$AUTO_MODE" == "1" ]]; then
        printf '   %s→ auto mode: using default [%d] %s%s\n' "$C_DIM" "$default_idx" "${options[$((default_idx - 1))]}" "$C_RESET"
        MENU_CHOICE="$default_idx"
        return 0
    fi

    while true; do
        read -r -p "   Choice [default ${default_idx}]: " choice
        [[ -z "$choice" ]] && choice="$default_idx"
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            MENU_CHOICE="$choice"
            return 0
        fi
        printf '   %s invalid choice, try again\n' "$SYM_WARN"
    done
}

ask_yes_no() {
    # Usage: ask_yes_no "Question?" default_yes(0/1)  -> returns 0 for yes, 1 for no
    local prompt="$1" default="$2" reply
    local hint="y/N"
    (( default == 1 )) && hint="Y/n"

    if [[ "$AUTO_MODE" == "1" ]]; then
        return $(( default == 1 ? 0 : 1 ))
    fi

    read -r -p "$(printf '%s %s [%s]: ' "$SYM_ASK" "$prompt" "$hint")" reply
    reply="${reply,,}"
    if [[ -z "$reply" ]]; then
        return $(( default == 1 ? 0 : 1 ))
    fi
    [[ "$reply" == "y" || "$reply" == "yes" ]]
}

human_duration() {
    local secs="$1"
    printf '%dm%02ds' "$(( secs / 60 ))" "$(( secs % 60 ))"
}
