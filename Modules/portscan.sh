#!/usr/bin/env bash
# ==============================================================================
# portscan.sh — Stage 2: Port & Service Enumeration
# ==============================================================================
# Populates two global associative arrays that the rest of the tool relies on:
#   OPEN_PORTS[port]    = service name   (e.g. OPEN_PORTS[21]="ftp")
#   PORT_VERSION[port]  = version/banner string reported by nmap -sV

portscan_menu() {
    local root_note=""
    (( EUID != 0 )) && root_note=" (needs sudo — will fall back to connect scan)"

    ask_menu "Port scan type — how should we scan $1?" 1 \
        "Fast     — top 100 ports, service/version detection (recommended default)" \
        "Full     — all 65535 TCP ports, service/version detection (slow)" \
        "Custom   — you specify a port range" \
        "Stealth SYN scan${root_note}" \
        "TCP connect scan only — no version detection (fastest, least info)"
    SCAN_TYPE="$MENU_CHOICE"

    if [[ "$SCAN_TYPE" == "3" ]]; then
        read -r -p "   Enter port range (e.g. 1-1000 or 22,80,443): " CUSTOM_PORT_RANGE
        [[ -z "$CUSTOM_PORT_RANGE" ]] && CUSTOM_PORT_RANGE="1-1000"
    fi
}

_build_nmap_args() {
    local args=(-Pn)
    case "$SCAN_TYPE" in
        1) args+=(-sV --top-ports 100) ;;
        2) args+=(-sV -p-) ;;
        3) args+=(-sV -p "$CUSTOM_PORT_RANGE") ;;
        4)
            if (( EUID == 0 )); then
                args+=(-sS -sV --top-ports 100)
            else
                log_warn "Stealth SYN scan requires root — falling back to TCP connect scan"
                args+=(-sT -sV --top-ports 100)
            fi
            ;;
        5) args+=(-sT --top-ports 100) ;;
        *) args+=(-sV --top-ports 100) ;;
    esac
    printf '%s\n' "${args[@]}"
}

run_portscan() {
    local target="$1"
    section "Stage 2/4 — Port & Service Enumeration: $target"

    local -a nmap_args
    mapfile -t nmap_args < <(_build_nmap_args)

    # --- ADDITIVE: apply firewall-evasion / protocol / stealth-profile choices
    #     from evasion.sh on top of the base args above (see modules/evasion.sh) ---
    apply_evasion_overrides nmap_args

    section "Scan Profile"
    log_info "Firewall evasion: $([[ "$FW_EVADE" == "1" ]] && echo "Yes (Xmas scan)" || echo "No")"
    log_info "Protocol: ${SCAN_PROTOCOL^^}"
    log_info "Operational profile: $([[ "$STEALTH_PROFILE" == "redteam" ]] && echo "Red Team (maximum stealth)" || echo "Penetration Test (standard)")"
    log_info "Technique: $SCAN_TECHNIQUE_LABEL"
    {
        printf '\n=== SCAN PROFILE: %s ===\n' "$target"
        scan_profile_banner_text
    } >> "$SCAN_FILE"

    log_info "Running: nmap ${nmap_args[*]} -oG - $target"
    log_info "This can take a moment depending on scan type..."

    local grep_out
    grep_out="$(nmap "${nmap_args[@]}" -oG - "$target" 2>>"$LOG_FILE")"

    {
        printf '\n=== PORT SCAN: %s ===\n' "$target"
        printf 'nmap %s -oG - %s\n\n' "${nmap_args[*]}" "$target"
        printf '%s\n' "$grep_out"
    } >> "$SCAN_FILE"

    local ports_line
    ports_line="$(printf '%s\n' "$grep_out" | grep -F 'Ports:')"

    if [[ -z "$ports_line" ]]; then
        log_warn "No open ports detected"
        return 0
    fi

    # "Ports: 21/open/tcp//ftp//vsftpd 2.3.4/, 22/open/tcp//ssh//OpenSSH 4.7p1/"
    local ports_field entry port state proto owner service rpcinfo version
    ports_field="${ports_line#*Ports: }"
    IFS=',' read -ra entries <<< "$ports_field"

    printf '\n%-8s %-8s %-10s %-40s\n' "PORT" "STATE" "SERVICE" "VERSION" >> "$SCAN_FILE"
    printf '%s\n' "----------------------------------------------------------------------" >> "$SCAN_FILE"

    for entry in "${entries[@]}"; do
        entry="$(echo "$entry" | xargs)"   # trim whitespace
        # nmap -oG format: port/state/protocol/owner/service/rpc_info/version/
        IFS='/' read -r port state proto owner service rpcinfo version _ <<< "$entry"
        [[ "$state" != "open" ]] && continue
        [[ -z "$service" ]] && service="unknown"
        [[ -z "$version" ]] && version="(no banner captured)"

        OPEN_PORTS["$port"]="$service"
        PORT_VERSION["$port"]="$version"

        printf '%-8s %-8s %-10s %-40s\n' "$port" "$state" "$service" "$version" >> "$SCAN_FILE"
        log_ok "Port $port/$proto open — $service ${C_DIM}($version)${C_RESET}"
    done

    if (( ${#OPEN_PORTS[@]} == 0 )); then
        log_warn "Ports were reported but none parsed as open — check $SCAN_FILE for raw output"
    else
        log_ok "${#OPEN_PORTS[@]} open port(s) recorded"
    fi
}
