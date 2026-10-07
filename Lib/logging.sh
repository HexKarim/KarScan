#!/usr/bin/env bash
# ==============================================================================
# logging.sh — unified logging: console output + persistent log file
# ==============================================================================
# Requires colors.sh to be sourced first (uses SYM_* / C_* variables).
# Requires LOG_FILE to be set by the caller before any log_* call.

_log_ts() { date '+%Y-%m-%d %H:%M:%S'; }

_log_write() {
    # Always append a plain-text line to the log file, regardless of console color.
    [[ -n "${LOG_FILE:-}" ]] && printf '[%s] %s\n' "$(_log_ts)" "$1" >> "$LOG_FILE"
}

log_ok() {
    printf '%s %s\n' "$SYM_OK" "$1"
    _log_write "OK    | $1"
}

log_info() {
    printf '%s %s\n' "$SYM_INFO" "$1"
    _log_write "INFO  | $1"
}

log_warn() {
    printf '%s %s\n' "$SYM_WARN" "$1" >&2
    _log_write "WARN  | $1"
}

log_fail() {
    printf '%s %s\n' "$SYM_FAIL" "$1" >&2
    _log_write "FAIL  | $1"
}

log_finding() {
    # Structured, evidence-backed finding. Appears in console, log, and findings buffer.
    # Usage: log_finding "<severity>" "<title>" "<evidence>" "<recommendation>"
    local severity="$1" title="$2" evidence="$3" recommendation="$4"
    local sev_color="$C_YELLOW"
    case "$severity" in
        HIGH)   sev_color="$C_RED" ;;
        MEDIUM) sev_color="$C_YELLOW" ;;
        LOW)    sev_color="$C_BLUE" ;;
        INFO)   sev_color="$C_GRAY" ;;
    esac
    printf '%s %s[%s]%s %s\n' "$SYM_WARN" "$sev_color" "$severity" "$C_RESET" "$title"
    printf '    %sEvidence:%s %s\n' "$C_DIM" "$C_RESET" "$evidence"

    FINDINGS+=("${severity}|${title}|${evidence}|${recommendation}")
    _log_write "FINDING [$severity] | $title | Evidence: $evidence | Recommendation: $recommendation"
}
