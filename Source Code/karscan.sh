#!/usr/bin/env bash
# ==============================================================================
#  karscan.sh — Bash-Based Security Assessment Tool
#  Instant Software Solutions — Security Track (SEC-BASH-092226)
#
#  A mini automated security assessment framework: reconnaissance, port &
#  service enumeration, service-specific security checks, and a structured,
#  evidence-based report — with the operator choosing the approach for every
#  stage instead of the tool guessing silently.
#
#  Usage:
#    ./karscan.sh <target>                 Interactive single-target scan
#    ./karscan.sh -f targets.txt           Batch scan (auto mode, one report per host)
#    ./karscan.sh --auto <target>          Non-interactive single target (uses defaults)
#    ./karscan.sh --help | --version
#
#  Only scan hosts you own or are explicitly authorized to test.
# ==============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VERSION="1.0.0"

# ---- exit codes --------------------------------------------------------------
EXIT_OK=0
EXIT_USAGE=1
EXIT_MISSING_DEP=2
EXIT_UNREACHABLE=3
EXIT_INTERRUPTED=130

# ---- global state --------------------------------------------------------------
declare -A AVAILABLE_TOOLS
declare -A OPEN_PORTS
declare -A PORT_VERSION
FINDINGS=()
AUTO_MODE=0
TARGET=""
TARGET_IP=""
TARGETS_FILE=""
FW_EVADE="0"
SCAN_PROTOCOL="tcp"
STEALTH_PROFILE="pentest"
SCAN_TECHNIQUE_LABEL=""
STEALTH_LABEL=""

# ---- load libraries & modules ------------------------------------------------
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/utils.sh"
source "$SCRIPT_DIR/modules/recon.sh"
source "$SCRIPT_DIR/modules/evasion.sh"
source "$SCRIPT_DIR/modules/portscan.sh"
source "$SCRIPT_DIR/modules/ftp.sh"
source "$SCRIPT_DIR/modules/ssh.sh"
source "$SCRIPT_DIR/modules/smb.sh"
source "$SCRIPT_DIR/modules/smtp.sh"
source "$SCRIPT_DIR/modules/dns.sh"
source "$SCRIPT_DIR/modules/http.sh"
source "$SCRIPT_DIR/modules/report.sh"

trap 'printf "\n%s Interrupted — exiting.\n" "$SYM_FAIL"; exit $EXIT_INTERRUPTED' INT TERM

# ------------------------------------------------------------------------------
print_usage() {
    cat <<EOF
Usage: ./karscan.sh <target>
       ./karscan.sh -f <targets_file>
       ./karscan.sh [--auto] <target>
       ./karscan.sh --help
       ./karscan.sh --version

  <target>            IP address or hostname of an authorized lab host
  -f, --file <file>   Text file with one target per line (batch mode, auto settings)
  --auto              Skip interactive menus for a single target and use safe defaults
  -h, --help          Show this help and exit
  -v, --version       Show version and exit

Examples:
  ./karscan.sh 192.168.56.105
  ./karscan.sh -f targets.txt
  ./karscan.sh --auto 192.168.56.105

Only scan targets you own or are explicitly authorized to test.
EOF
}

print_version() {
    printf 'karscan.sh version %s\n' "$VERSION"
}

# ------------------------------------------------------------------------------
# Maps a detected service name (as nmap reports it) to a check_* function.
service_to_module() {
    case "$1" in
        ftp) echo "check_ftp" ;;
        ssh) echo "check_ssh" ;;
        microsoft-ds|netbios-ssn|smb) echo "check_smb" ;;
        smtp) echo "check_smtp" ;;
        domain) echo "check_dns" ;;
        http|http-proxy|http-alt) echo "check_http" ;;
        https|ssl/http) echo "check_http" ;;
        *) echo "" ;;
    esac
}

service_display_name() {
    case "$1" in
        ftp) echo "FTP" ;;
        ssh) echo "SSH" ;;
        microsoft-ds|netbios-ssn|smb) echo "SMB" ;;
        smtp) echo "SMTP" ;;
        domain) echo "DNS" ;;
        http|http-proxy|http-alt) echo "HTTP" ;;
        https|ssl/http) echo "HTTPS" ;;
        *) echo "$1" ;;
    esac
}

dispatch_enumeration() {
    section "Stage 3/4 — Automated Enumeration"

    # Build the list of ports whose service we actually know how to check.
    local checkable_ports=() p svc fn
    for p in "${!OPEN_PORTS[@]}"; do
        svc="${OPEN_PORTS[$p]}"
        fn="$(service_to_module "$svc")"
        [[ -n "$fn" ]] && checkable_ports+=("$p")
    done

    if (( ${#checkable_ports[@]} == 0 )); then
        log_warn "No open ports matched a known service module — nothing to enumerate"
        return
    fi

    local -a sorted_ports
    mapfile -t sorted_ports < <(printf '%s\n' "${checkable_ports[@]}" | sort -n)

    printf '   Services matched to a check module:\n'
    for p in "${sorted_ports[@]}"; do
        printf '     - port %-6s %s\n' "$p" "$(service_display_name "${OPEN_PORTS[$p]}")"
    done

    ask_menu "Run automated service checks?" 1 \
        "Run all matched checks automatically (recommended)" \
        "Let me choose which checks to run" \
        "Skip automated enumeration"
    local enum_choice="$MENU_CHOICE"

    [[ "$enum_choice" == "3" ]] && { log_warn "Automated enumeration skipped by user choice"; return; }

    local -a to_run=()
    if [[ "$enum_choice" == "1" ]]; then
        to_run=("${sorted_ports[@]}")
    else
        for p in "${sorted_ports[@]}"; do
            if ask_yes_no "Run $(service_display_name "${OPEN_PORTS[$p]}") check on port $p?" 1; then
                to_run+=("$p")
            fi
        done
    fi

    for p in "${to_run[@]}"; do
        svc="${OPEN_PORTS[$p]}"
        fn="$(service_to_module "$svc")"
        log_ok "$(service_display_name "$svc") detected on port $p"
        log_info "Starting $(service_display_name "$svc") enumeration..."
        "$fn" "$TARGET" "$p"
    done
}

# ------------------------------------------------------------------------------
run_single_target() {
    local target="$1"
    TARGET="$target"
    TARGET_IP=""
    OPEN_PORTS=()
    PORT_VERSION=()
    FINDINGS=()

    local ts safe_name
    ts="$(date '+%Y%m%d_%H%M%S')"
    safe_name="$(printf '%s' "$target" | tr -c 'A-Za-z0-9._-' '_')"
    REPORT_DIR="$SCRIPT_DIR/reports/${safe_name}_${ts}"
    mkdir -p "$REPORT_DIR"

    SCAN_FILE="$REPORT_DIR/scan.txt"
    FINDINGS_FILE="$REPORT_DIR/findings.txt"
    SUMMARY_FILE="$REPORT_DIR/summary.txt"
    HTML_FILE="$REPORT_DIR/report.html"
    LOG_FILE="$REPORT_DIR/karscan.log"
    : > "$SCAN_FILE"; : > "$LOG_FILE"

    banner "KarScan — target: $target"
    log_info "Report directory: $REPORT_DIR"

    local start_ts end_ts
    start_ts="$(date +%s)"

    if [[ "$AUTO_MODE" == "1" ]]; then
        RECON_LEVEL=2; SCAN_TYPE=1; REPORT_MODE=2
        evasion_defaults
    else
        recon_menu
        portscan_menu "$target"
        evasion_menu "$target"
        report_menu
    fi

    run_recon "$target"
    local recon_rc=$?
    if [[ $recon_rc -eq $EXIT_UNREACHABLE ]]; then
        end_ts="$(date +%s)"; SCAN_DURATION=$(( end_ts - start_ts ))
        generate_reports
        return $EXIT_UNREACHABLE
    fi

    run_portscan "$target"
    dispatch_enumeration

    end_ts="$(date +%s)"
    SCAN_DURATION=$(( end_ts - start_ts ))
    generate_reports
    return $EXIT_OK
}

# ------------------------------------------------------------------------------
main() {
    if (( $# == 0 )); then
        print_usage
        exit $EXIT_USAGE
    fi

    while (( $# > 0 )); do
        case "$1" in
            -h|--help) print_usage; exit $EXIT_OK ;;
            -v|--version) print_version; exit $EXIT_OK ;;
            --auto) AUTO_MODE=1; shift ;;
            -f|--file) TARGETS_FILE="${2:-}"; shift 2 ;;
            -*)
                log_fail "Unknown option: $1"
                print_usage
                exit $EXIT_USAGE
                ;;
            *)
                TARGET="$1"; shift ;;
        esac
    done

    check_dependencies

    if [[ -n "$TARGETS_FILE" ]]; then
        [[ -f "$TARGETS_FILE" ]] || { log_fail "Targets file not found: $TARGETS_FILE"; exit $EXIT_USAGE; }
        AUTO_MODE=1
        local overall_rc=$EXIT_OK
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="$(echo "$line" | xargs)"
            [[ -z "$line" || "$line" == \#* ]] && continue
            run_single_target "$line" || overall_rc=$?
            printf '\n'
        done < "$TARGETS_FILE"
        exit $overall_rc
    fi

    if [[ -z "$TARGET" ]]; then
        print_usage
        exit $EXIT_USAGE
    fi

    run_single_target "$TARGET"
    exit $?
}

main "$@"
