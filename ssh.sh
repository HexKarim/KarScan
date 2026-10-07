#!/usr/bin/env bash
# ==============================================================================
# ssh.sh — SSH service checks
# ==============================================================================

# A small, well-known set of end-of-life / historically vulnerable OpenSSH
# banners used only to flag "this looks outdated, verify the CVE yourself" —
# never treated as a confirmed exploit.
_ssh_is_old_banner() {
    # Accepts both the raw banner form (OpenSSH_5.3) and the nmap-formatted
    # fallback form (OpenSSH 5.3p1) — the space/underscore differs depending
    # on whether we grabbed the banner live or fell back to nmap's -sV data.
    local banner="$1"
    [[ "$banner" =~ OpenSSH[_\ ][1-6]\. ]] && return 0
    [[ "$banner" =~ OpenSSH[_\ ]7\.[0-4] ]] && return 0
    return 1
}

check_ssh() {
    local target="$1" port="$2"
    log_info "Starting SSH banner check on port $port..."

    local banner
    banner="$(timeout 5 bash -c "exec 3<>/dev/tcp/$target/$port; head -c 256 <&3" 2>/dev/null)"

    if [[ -z "$banner" ]]; then
        banner="${PORT_VERSION[$port]:-}"
    fi

    printf '\n=== SSH banner on %s:%s ===\n%s\n' "$target" "$port" "$banner" >> "$SCAN_FILE"

    if [[ -z "$banner" ]]; then
        log_warn "Could not retrieve SSH banner"
        return
    fi

    log_ok "SSH banner: $banner"

    if _ssh_is_old_banner "$banner"; then
        log_finding "MEDIUM" "Outdated OpenSSH version banner on port $port" \
            "Banner grabbed via raw TCP connect: \"${banner//$'\r'/}\"" \
            "Upgrade OpenSSH to a currently supported release and check the banner's version against the NVD for known CVEs."
    fi
}
