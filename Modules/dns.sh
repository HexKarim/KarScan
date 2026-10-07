#!/usr/bin/env bash
# ==============================================================================
# dns.sh — DNS service checks
# ==============================================================================

check_dns() {
    local target="$1" port="$2"
    log_info "Starting DNS checks on port $port..."

    if [[ -z "${DNS_DOMAIN:-}" ]]; then
        DNS_DOMAIN=""
        if ask_yes_no "Do you already know the domain name and want to enter it yourself?" 0; then
            read -r -p "   $SYM_ASK Domain name to test for zone transfer (blank = skip): " DNS_DOMAIN
        elif ask_yes_no "Do you want KarScan to try to auto-discover the domain name instead?" 1; then
            log_info "Attempting to auto-discover a domain name (reverse DNS / SOA)..."

            local ptr
            ptr="$(timeout 6 dig @"$target" -p "$port" -x "$target" +short 2>/dev/null | head -n1)"
            if [[ -n "$ptr" ]]; then
                DNS_DOMAIN="$(echo "$ptr" | sed -E 's/^[^.]+\.//; s/\.$//')"
            fi

            if [[ -z "$DNS_DOMAIN" ]]; then
                local guess soa
                for guess in localdomain local vulnos.local lan; do
                    soa="$(timeout 4 dig @"$target" -p "$port" "$guess" SOA +short 2>/dev/null)"
                    if [[ -n "$soa" ]]; then
                        DNS_DOMAIN="$guess"
                        break
                    fi
                done
            fi

            if [[ -z "$DNS_DOMAIN" && -f /etc/resolv.conf ]]; then
                DNS_DOMAIN="$(awk '/^search|^domain/{print $2; exit}' /etc/resolv.conf 2>/dev/null)"
            fi

            if [[ -n "$DNS_DOMAIN" ]]; then
                log_ok "Domain name auto-discovery succeeded: $DNS_DOMAIN"
            else
                log_warn "Domain name auto-discovery failed"
            fi
        else
            log_warn "Domain name step skipped by user choice"
        fi
    fi

    if [[ -z "$DNS_DOMAIN" ]]; then
        log_warn "No domain provided — skipping zone transfer check"
        return
    fi
log_finding "INFO" "Domain name identified for DNS testing on port $port" \
        "$DNS_DOMAIN" \
        "No action required — this is the domain name KarScan used to test the DNS server for a zone transfer (AXFR)."


    local axfr_out
    axfr_out="$(timeout 10 dig @"$target" -p "$port" "$DNS_DOMAIN" AXFR +time=5 2>&1)"
    printf '\n=== DNS AXFR check: dig @%s -p %s %s AXFR ===\n%s\n' "$target" "$port" "$DNS_DOMAIN" "$axfr_out" >> "$SCAN_FILE"

    if printf '%s' "$axfr_out" | grep -qiE 'Transfer failed|connection refused|communications error|timed out'; then
        log_ok "Zone transfer refused/failed for $DNS_DOMAIN"
        return
    fi

    local record_count
    record_count="$(printf '%s' "$axfr_out" | grep -cE '^[^;].*\s(IN|CH)\s')"

    if (( record_count > 0 )); then
        local sample
        sample="$(printf '%s' "$axfr_out" | grep -E '^[^;].*\s(IN|CH)\s' | head -n 5 | tr '\n' ';' | sed 's/;/; /g')"
        log_finding "HIGH" "DNS zone transfer (AXFR) allowed for $DNS_DOMAIN on port $port" \
            "dig @$target -p $port $DNS_DOMAIN AXFR -> returned $record_count records. Sample: ${sample:0:200}" \
            "Restrict AXFR to authorized secondary name servers only (allow-transfer in BIND, or equivalent)."
    else
        log_ok "Zone transfer returned no usable records"
    fi
}
