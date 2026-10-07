#!/usr/bin/env bash
# ==============================================================================
# ftp.sh — FTP service checks
# ==============================================================================

check_ftp() {
    local target="$1" port="$2"
    log_info "Starting FTP enumeration on port $port..."

    if ! tool_available ftp; then
        log_warn "ftp client not installed — skipping anonymous login check (install: sudo apt install ftp)"
        return
    fi

    local response
    response="$(
        printf 'user anonymous anonymous@karscan.local\npassword\nls\nbye\n' | \
        timeout 10 ftp -inv "$target" "$port" 2>&1
    )"
    printf '\n=== FTP check on %s:%s ===\n%s\n' "$target" "$port" "$response" >> "$SCAN_FILE"

    if printf '%s' "$response" | grep -qiE '230 |login successful|anonymous access granted'; then
        local listing
        listing="$(printf '%s' "$response" | grep -A20 -iE '^(150|226|229)|drwx|^-rw' | head -n 10 | tr '\n' ';' | sed 's/;/; /g')"
        [[ -z "$listing" ]] && listing="(login succeeded but directory listing was empty)"
        log_finding "HIGH" "Anonymous FTP login allowed on port $port" \
            "ftp $target $port -> login as \"anonymous\" succeeded. Listing: ${listing:0:200}" \
            "Disable anonymous FTP access unless explicitly required; if required, restrict to read-only and a dedicated non-sensitive directory."
    else
        log_ok "Anonymous FTP login rejected"
    fi
}
