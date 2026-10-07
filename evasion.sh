#!/usr/bin/env bash
# ==============================================================================
# evasion.sh — Pre-scan profiling stage (ADDITIVE, runs before Stage 2)
# ==============================================================================
# Asks three extra questions before the port scan and stores the answers in
# globals that portscan.sh reads to adjust the nmap command it builds:
#
#   FW_EVADE        "1" / "0"        — attempt firewall evasion (Xmas scan)?
#   SCAN_PROTOCOL   "tcp" / "udp"    — which protocol family to scan
#   STEALTH_PROFILE "redteam" / "pentest" — how much extra stealth to layer on
#
# Defaults ("0" / "tcp" / "pentest") reproduce the exact old scan behaviour,
# so this stage only ever *adds* capability — it never changes what already
# worked when the operator just accepts the defaults (or in --auto mode).

evasion_defaults() {
    FW_EVADE="0"
    SCAN_PROTOCOL="tcp"
    STEALTH_PROFILE="pentest"
    SCAN_TECHNIQUE_LABEL=""
    STEALTH_LABEL=""
}

evasion_menu() {
    local target="$1"

    if [[ "$AUTO_MODE" == "1" ]]; then
        evasion_defaults
        log_info "Auto mode: firewall evasion off, TCP, Penetration Test profile (unchanged default behavior)"
        return 0
    fi

    section "Pre-Scan Profile — $target"

    ask_menu "Do you want to try to evade the firewall/IDS?" 2 \
        "Yes — use a TCP Xmas scan (FIN+PSH+URG flags) to try to slip past simple packet filters" \
        "No  — scan normally (recommended unless you know a firewall is in the way)"
    [[ "$MENU_CHOICE" == "1" ]] && FW_EVADE="1" || FW_EVADE="0"

    ask_menu "Which protocol do you want to scan?" 1 \
        "TCP — the standard choice for this assignment's target services" \
        "UDP — scan UDP ports instead (slower; needed for services like DNS/SNMP/TFTP over UDP)"
    if [[ "$MENU_CHOICE" == "2" ]]; then
        SCAN_PROTOCOL="udp"
    else
        SCAN_PROTOCOL="tcp"
    fi

    ask_menu "What's your operational profile for this scan?" 2 \
        "Red Team    — prioritize staying hidden: slow timing, packet fragmentation, decoys, randomized order" \
        "Penetration Test — thoroughness over stealth: run the scan exactly as configured, at normal speed"
    if [[ "$MENU_CHOICE" == "1" ]]; then
        STEALTH_PROFILE="redteam"
    else
        STEALTH_PROFILE="pentest"
    fi

    printf '\n   %sProfile selected:%s evasion=%s, protocol=%s, mode=%s\n' \
        "$C_DIM" "$C_RESET" \
        "$([[ "$FW_EVADE" == "1" ]] && echo yes || echo no)" \
        "${SCAN_PROTOCOL^^}" \
        "$([[ "$STEALTH_PROFILE" == "redteam" ]] && echo "Red Team" || echo "Penetration Test")"
}

# Mutates the nmap argument array (passed by name / nameref) built by
# portscan.sh's existing _build_nmap_args, layering the evasion/protocol/
# stealth choices on top without touching that function's own case logic.
apply_evasion_overrides() {
    local -n _args="$1"
    local kept=() flag

    if [[ "$SCAN_PROTOCOL" == "udp" ]]; then
        # UDP scanning is a different technique entirely — swap out whichever
        # TCP technique flag _build_nmap_args chose (-sS/-sT) for -sU.
        for flag in "${_args[@]}"; do
            case "$flag" in
                -sS|-sT|-sX) continue ;;
                *) kept+=("$flag") ;;
            esac
        done
        _args=(-sU "${kept[@]}")

        if [[ "$FW_EVADE" == "1" ]]; then
            # Xmas doesn't exist for UDP (UDP has no flags to set) — apply the
            # closest generic evasion instead: fragmentation + padded length.
            _args+=(-f --data-length 16)
            SCAN_TECHNIQUE_LABEL="UDP scan (-sU) with generic evasion (-f fragmentation, --data-length 16) — Xmas doesn't apply to UDP, so packet fragmentation/padding was used instead"
        else
            SCAN_TECHNIQUE_LABEL="UDP scan (-sU)"
        fi

    elif [[ "$FW_EVADE" == "1" ]]; then
        for flag in "${_args[@]}"; do
            case "$flag" in
                -sS|-sT) continue ;;
                *) kept+=("$flag") ;;
            esac
        done
        if (( EUID == 0 )); then
            _args=(-sX "${kept[@]}")
            SCAN_TECHNIQUE_LABEL="TCP Xmas scan (-sX: FIN+PSH+URG flags set, no SYN/ACK) — firewall evasion mode"
        else
            _args=(-sT "${kept[@]}")
            SCAN_TECHNIQUE_LABEL="TCP connect scan (-sT) — Xmas scan needs root privileges, fell back automatically"
            log_warn "Xmas scan requires root — falling back to TCP connect scan"
        fi
    else
        SCAN_TECHNIQUE_LABEL="TCP scan (technique as selected in the port-scan menu)"
    fi

    if [[ "$STEALTH_PROFILE" == "redteam" ]]; then
        # Avoid stacking a duplicate -f / --data-length if the UDP-evasion
        # branch above already added one — keep the args clean either way.
        if [[ "$SCAN_PROTOCOL" == "udp" && "$FW_EVADE" == "1" ]]; then
            _args+=(-T1 --randomize-hosts)
            STEALTH_LABEL="Red Team — maximum practical stealth: -T1 (paranoid timing, minimizes IDS pattern triggers), --randomize-hosts (randomizes scan order); packet fragmentation (-f) and padding (--data-length 16) were already applied by the UDP evasion step above"
        else
            _args+=(-T1 -f --randomize-hosts --data-length 24)
            STEALTH_LABEL="Red Team — maximum practical stealth: -T1 (paranoid timing, minimizes IDS pattern triggers), -f (fragments packets across multiple IP datagrams), --randomize-hosts (randomizes scan order), --data-length 24 (pads packets to obscure the nmap fingerprint)"
        fi
    else
        _args+=(-T3)
        STEALTH_LABEL="Penetration Test — standard nmap timing (-T3), no additional stealth overhead, prioritizing speed and completeness"
    fi
}

# One-line + multi-line description used by the scan-profile banner in
# scan.txt / summary.txt / report.html.
scan_profile_banner_text() {
    cat <<PROFILE
Firewall evasion requested: $([[ "$FW_EVADE" == "1" ]] && echo "Yes (Xmas scan)" || echo "No")
Protocol:                   ${SCAN_PROTOCOL^^}
Operational profile:        $([[ "$STEALTH_PROFILE" == "redteam" ]] && echo "Red Team (maximum stealth)" || echo "Penetration Test (standard)")
Scan technique used:        ${SCAN_TECHNIQUE_LABEL}
Stealth measures applied:   ${STEALTH_LABEL}
PROFILE
}
