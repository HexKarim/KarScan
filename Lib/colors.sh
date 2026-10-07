#!/usr/bin/env bash
# ==============================================================================
# colors.sh — terminal colors, symbols, and small UI helpers for KarScan
# ==============================================================================

# Only emit color codes when writing to an actual terminal.
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'
    C_MAGENTA=$'\033[35m'
    C_CYAN=$'\033[36m'
    C_WHITE=$'\033[97m'
    C_GRAY=$'\033[90m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""
    C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_WHITE=""; C_GRAY=""
fi

SYM_OK="${C_GREEN}[+]${C_RESET}"
SYM_INFO="${C_CYAN}[*]${C_RESET}"
SYM_WARN="${C_YELLOW}[!]${C_RESET}"
SYM_FAIL="${C_RED}[-]${C_RESET}"
SYM_ASK="${C_MAGENTA}[?]${C_RESET}"

hr() {
    printf '%s\n' "${C_GRAY}────────────────────────────────────────────────────────────────${C_RESET}"
}

banner() {
    local title="$1"
    hr
    printf '  %s%s%s\n' "${C_BOLD}${C_WHITE}" "$title" "${C_RESET}"
    hr
}

section() {
    local title="$1"
    printf '\n%s%s▶ %s%s\n' "${C_BOLD}" "${C_CYAN}" "$title" "${C_RESET}"
}
