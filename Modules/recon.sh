#!/usr/bin/env bash
# ==============================================================================
# recon.sh — Stage 1: Reconnaissance
# ==============================================================================

recon_menu() {
    ask_menu "Recon depth — how thorough should reconnaissance be?" 2 \
        "Quick   — reachability + hostname resolution only" \
        "Standard — quick + traceroute + local ARP/route info (recommended)" \
        "Deep    — standard + whois lookup" \
        "Skip recon entirely"
    RECON_LEVEL="$MENU_CHOICE"
}

run_recon() {
    local target="$1"
    section "Stage 1/4 — Reconnaissance: $target"

    if [[ "$RECON_LEVEL" == "4" ]]; then
        log_warn "Recon skipped by user choice"
        return 0
    fi

    {
        printf '=== RECON: %s ===\n' "$target"
        printf 'Date: %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    } >> "$SCAN_FILE"

    # --- host availability ----------------------------------------------------
    log_info "Checking host availability (ping)..."
    local ping_out
    ping_out=$(ping -c 3 -W 2 "$target" 2>&1)
    echo "$ping_out" >> "$SCAN_FILE"

    if ! check_reachable "$target"; then
        log_fail "Target is unreachable"
        echo "$ping_out" | tail -n 3
        return "$EXIT_UNREACHABLE"
    fi
    log_ok "Target is reachable"

    # --- hostname / IP resolution ----------------------------------------------
    log_info "Resolving IP / hostname information..."
    local ip host
    ip="$(resolve_target "$target")"
    TARGET_IP="$ip"
    printf 'Resolved IP: %s\n' "${ip:-unknown}" | tee -a "$SCAN_FILE" >/dev/null
    log_ok "Resolved IP: ${ip:-unknown}"

    if command -v host &>/dev/null; then
        host="$(host "$ip" 2>/dev/null | head -n1)"
        [[ -n "$host" ]] && { printf 'Reverse DNS: %s\n' "$host" >> "$SCAN_FILE"; log_ok "Reverse DNS: $host"; }
    fi

    if [[ "$RECON_LEVEL" == "1" ]]; then
        return 0
    fi

    # --- basic network info (route / ARP) --------------------------------------
    log_info "Gathering basic local network information..."
    {
        printf '\n-- Local route to target --\n'
        ip route get "$ip" 2>/dev/null
        printf '\n-- ARP table entry (if on local segment) --\n'
        arp -n 2>/dev/null | grep -F "$ip" || printf '(no ARP entry yet — will populate after first packet exchange)\n'
    } >> "$SCAN_FILE"
    log_ok "Local network info captured"

    if command -v traceroute &>/dev/null; then
        log_info "Running traceroute (max 10 hops, 2s timeout)..."
        {
            printf '\n-- Traceroute --\n'
            traceroute -m 10 -w 2 "$ip" 2>&1
        } >> "$SCAN_FILE"
        log_ok "Traceroute captured"
    else
        log_warn "traceroute not installed — skipping hop analysis"
    fi

    if [[ "$RECON_LEVEL" == "3" ]]; then
        if tool_available whois; then
            log_info "Running whois lookup..."
            { printf '\n-- Whois --\n'; whois "$ip" 2>&1 | head -n 40; } >> "$SCAN_FILE"
            log_ok "Whois captured"
        else
            log_warn "whois not installed — skipping (this is expected/normal for private-range lab IPs)"
        fi
    fi

    return 0
}
