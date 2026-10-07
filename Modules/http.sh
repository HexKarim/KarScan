#!/usr/bin/env bash
# ==============================================================================
# http.sh — HTTP/HTTPS basic enumeration
# ==============================================================================

check_http() {
    local target="$1" port="$2"
    local scheme="http"
    [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
    local base_url="${scheme}://${target}:${port}"

    log_info "Starting HTTP enumeration on $base_url..."

    # --- headers ---
    local headers
    headers="$(timeout 10 curl -skI --max-time 8 "$base_url/" 2>&1)"
    printf '\n=== HTTP headers: %s ===\n%s\n' "$base_url" "$headers" >> "$SCAN_FILE"

    if [[ -z "$headers" ]]; then
        log_warn "No response from $base_url"
        return
    fi

    local server_hdr powered_hdr
    server_hdr="$(printf '%s' "$headers" | grep -i '^Server:' | tr -d '\r')"
    powered_hdr="$(printf '%s' "$headers" | grep -i '^X-Powered-By:' | tr -d '\r')"
    [[ -n "$server_hdr" ]] && log_ok "$server_hdr"
    [[ -n "$powered_hdr" ]] && log_ok "$powered_hdr"

    if [[ -n "$server_hdr" ]] || [[ -n "$powered_hdr" ]]; then
        log_finding "LOW" "Server/technology banner disclosed on port $port" \
            "curl -skI $base_url/ -> $(printf '%s %s' "$server_hdr" "$powered_hdr" | xargs)" \
            "Suppress or generalize the Server/X-Powered-By headers (ServerTokens/ServerSignature in Apache, expose_php off in PHP, etc.)."
    fi

    local sec_headers_missing=()
    for h in "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security"; do
        printf '%s' "$headers" | grep -qi "^${h}:" || sec_headers_missing+=("$h")
    done
    if (( ${#sec_headers_missing[@]} > 0 )); then
        log_finding "LOW" "Missing security headers on port $port" \
            "curl -skI $base_url/ -> missing: ${sec_headers_missing[*]}" \
            "Add the missing security headers appropriate to the application (CSP, X-Frame-Options, X-Content-Type-Options, HSTS for HTTPS)."
    fi

    # --- robots.txt ---
    local robots
    robots="$(timeout 8 curl -sk --max-time 6 "$base_url/robots.txt" 2>&1)"
    printf '\n=== robots.txt: %s/robots.txt ===\n%s\n' "$base_url" "$robots" >> "$SCAN_FILE"

    if [[ -n "$robots" ]] && ! printf '%s' "$robots" | grep -qi '404 Not Found\|<html'; then
        local disallow_count
        disallow_count="$(printf '%s' "$robots" | grep -ic '^Disallow:')"
        if (( disallow_count > 0 )); then
            local paths
            paths="$(printf '%s' "$robots" | grep -i '^Disallow:' | head -n 5 | tr '\n' ';' | sed 's/;/; /g')"
            log_finding "INFO" "robots.txt discloses $disallow_count restricted path(s) on port $port" \
                "curl $base_url/robots.txt -> ${paths:0:200}" \
                "Not a vulnerability by itself, but treat disclosed paths as a roadmap for further authorized testing; ensure they're properly access-controlled server-side."
        fi
    else
        log_ok "No robots.txt found (or empty)"
    fi

    # --- lightweight common-path probe (kept small & polite; not a full brute force) ---
    local common_paths=("admin" "login" "wp-admin" ".git/HEAD" "phpmyadmin" "config.php.bak")
    local found_paths=()
    local p code
    for p in "${common_paths[@]}"; do
        code="$(timeout 6 curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$base_url/$p")"
        [[ "$code" =~ ^(200|301|302|403)$ ]] && found_paths+=("$p [$code]")
    done
    if (( ${#found_paths[@]} > 0 )); then
        printf '\n=== Common path probe: %s ===\n%s\n' "$base_url" "${found_paths[*]}" >> "$SCAN_FILE"
        log_finding "INFO" "Potentially interesting paths found on port $port" \
            "curl probe of common paths on $base_url -> ${found_paths[*]}" \
            "Manually review each path's access control and whether it should be publicly reachable."
    fi
}
