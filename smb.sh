#!/usr/bin/env bash
# ==============================================================================
# smb.sh — SMB service checks
# ==============================================================================

check_smb() {
    local target="$1" port="$2"
    log_info "Starting SMB share enumeration on port $port..."

    local output=""

    if tool_available smbclient; then
        output="$(timeout 15 smbclient -N -L "//$target" -p "$port" 2>&1)"
        printf '\n=== smbclient -L //%s ===\n%s\n' "$target" "$output" >> "$SCAN_FILE"
    elif tool_available enum4linux; then
        output="$(timeout 25 enum4linux -S "$target" 2>&1)"
        printf '\n=== enum4linux -S %s ===\n%s\n' "$target" "$output" >> "$SCAN_FILE"
    else
        log_warn "Neither smbclient nor enum4linux installed — falling back to nmap smb-enum-shares script"
        output="$(timeout 30 nmap -p "$port" --script smb-enum-shares -Pn "$target" 2>&1)"
        printf '\n=== nmap smb-enum-shares on %s ===\n%s\n' "$target" "$output" >> "$SCAN_FILE"
    fi

    if [[ -z "$output" ]]; then
        log_warn "No SMB enumeration output obtained"
        return
    fi

    local shares
    shares="$(printf '%s' "$output" | grep -iE 'Disk|IPC|Sharename' | grep -viE '^Sharename' || true)"

    if printf '%s' "$output" | grep -qiE 'NT_STATUS_ACCESS_DENIED' && [[ -z "$shares" ]]; then
        log_ok "SMB share listing requires authentication (access denied for null/guest session)"
        return
    fi

    if [[ -n "$shares" ]]; then
        local shares_line
        shares_line="$(printf '%s' "$shares" | tr '\n' ';' | sed 's/;/; /g' | cut -c1-200)"
        log_finding "MEDIUM" "SMB shares listable without authentication on port $port" \
            "smbclient -N -L //$target -p $port -> shares: $shares_line" \
            "Disable null/guest SMB sessions; require authentication for all shares and restrict share permissions to least privilege."
    else
        log_ok "No shares listed via null/guest SMB session"
    fi
}
