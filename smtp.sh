#!/usr/bin/env bash
# ==============================================================================
# smtp.sh — SMTP service checks
# ==============================================================================

check_smtp() {
    local target="$1" port="$2"
    log_info "Starting SMTP checks on port $port..."

    # --- banner ---
    local banner
    banner="$(timeout 5 bash -c "exec 3<>/dev/tcp/$target/$port; head -c 256 <&3" 2>/dev/null)"
    printf '\n=== SMTP banner on %s:%s ===\n%s\n' "$target" "$port" "$banner" >> "$SCAN_FILE"
    [[ -n "$banner" ]] && log_ok "SMTP banner: ${banner//$'\r'/}"

    # --- user enumeration via VRFY ---
    local vrfy_root vrfy_bogus
    vrfy_root="$(timeout 5 bash -c "
        exec 3<>/dev/tcp/$target/$port
        head -c 512 <&3 >/dev/null
        printf 'VRFY root\r\n' >&3
        timeout 3 head -c 256 <&3
    " 2>/dev/null)"

    vrfy_bogus="$(timeout 5 bash -c "
        exec 3<>/dev/tcp/$target/$port
        head -c 512 <&3 >/dev/null
        printf 'VRFY zzz_nonexistent_user_9182\r\n' >&3
        timeout 3 head -c 256 <&3
    " 2>/dev/null)"

    {
        printf '\n-- VRFY root --\n%s\n' "$vrfy_root"
        printf '\n-- VRFY bogus user --\n%s\n' "$vrfy_bogus"
    } >> "$SCAN_FILE"

    if printf '%s' "$vrfy_root" | grep -qE '^25[02]' && printf '%s' "$vrfy_bogus" | grep -qE '^55[0-9]'; then
        log_finding "MEDIUM" "SMTP user enumeration via VRFY on port $port" \
            "VRFY root -> \"${vrfy_root//$'\r\n'/ }\" (accepted); VRFY zzz_nonexistent_user_9182 -> \"${vrfy_bogus//$'\r\n'/ }\" (rejected) — distinguishable responses confirm valid usernames." \
            "Disable the VRFY/EXPN commands (disable_vrfy_command in Postfix, or equivalent) so responses do not confirm account existence."
    else
        log_ok "SMTP VRFY does not appear to distinguish valid/invalid users"
    fi

    # --- open relay check (safe: RCPT TO two external domains, never DATA/send) ---
    local relay_test
    relay_test="$(timeout 6 bash -c "
        exec 3<>/dev/tcp/$target/$port
        head -c 512 <&3 >/dev/null
        printf 'HELO karscan.local\r\n' >&3; timeout 2 head -c 256 <&3 >/dev/null
        printf 'MAIL FROM:<probe@karscan.local>\r\n' >&3; timeout 2 head -c 256 <&3 >/dev/null
        printf 'RCPT TO:<relaytest@external-domain-example.test>\r\n' >&3
        timeout 2 head -c 256 <&3
        printf 'QUIT\r\n' >&3
    " 2>/dev/null)"

    printf '\n-- Open relay probe (RCPT TO external domain) --\n%s\n' "$relay_test" >> "$SCAN_FILE"

    if printf '%s' "$relay_test" | grep -qE '^25[02]'; then
        log_finding "HIGH" "Possible open mail relay on port $port" \
            "MAIL FROM:<probe@karscan.local> / RCPT TO:<relaytest@external-domain-example.test> -> server replied 2xx (accepted) for an external, unauthenticated recipient." \
            "Restrict relaying to authenticated users / trusted networks only (smtpd_relay_restrictions); re-test with a real external mailbox before treating this as confirmed."
    else
        log_ok "Server rejected unauthenticated relay attempt to an external domain"
    fi
}
