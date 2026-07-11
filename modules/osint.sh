#!/usr/bin/env bash
#
# modules/osint.sh — infrastructure + people/leak OSINT that expands scope.
# ASN mapping finds IP ranges (and thus assets) nothing else will; theHarvester
# pulls emails/hosts; whois gives registration + reverse-pivot data.
#
# Output: $OUTDIR/osint.txt   (single consolidated, human-readable summary)

module_osint() {
  [[ "$ENABLE_OSINT" == 1 ]] || { log_info "osint: disabled"; return 0; }
  log_step "OSINT — infrastructure & exposure"
  mkdir -p "$D_OSINT"
  local out="$OUTDIR/osint.txt"; : > "$out"

  {
    echo "# OSINT summary for $TARGET"
    echo "# generated $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo
  } >> "$out"

  # -- ASN / IP ranges --------------------------------------------------------
  if have_tool asnmap; then
    log_info "mapping ASNs & IP ranges (asnmap)…"
    {
      echo "## ASN / CIDR ranges"
      asnmap -d "$TARGET" -silent 2>/dev/null | sort -u
      echo
    } >> "$out"
  fi

  # -- WHOIS registration -----------------------------------------------------
  if have_tool whois; then
    log_info "whois lookup…"
    {
      echo "## WHOIS (registration)"
      whois "$TARGET" 2>/dev/null | grep -iE \
        'registrar|creation|created|expir|updated|name server|organization|registrant' \
        | sed 's/^[[:space:]]*//' | sort -u
      echo
    } >> "$out"
  fi

  # -- DNS records (MX/NS/TXT/SPF/DMARC) --------------------------------------
  if have_tool dnsx; then
    log_info "gathering DNS records…"
    {
      echo "## DNS records"
      printf '%s\n' "$TARGET" | dnsx -silent -a -aaaa -mx -ns -txt -cname -resp 2>/dev/null | sort -u
      echo
    } >> "$out"
  fi

  # -- Emails / hosts / names -------------------------------------------------
  if have_tool theHarvester; then
    log_info "harvesting emails & hosts (theHarvester)…"
    theHarvester -d "$TARGET" -b all -f "$D_OSINT/harvester" >/dev/null 2>&1 || true
    if [[ -f "$D_OSINT/harvester.json" ]] && have_tool jq; then
      {
        echo "## Emails"
        jq -r '.emails[]?' "$D_OSINT/harvester.json" 2>/dev/null | sort -u
        echo
      } >> "$out"
    fi
  fi

  # -- Favicon hash → pivot hint (mmh3) --------------------------------------
  if have_tool httpx; then
    local fh
    fh=$(printf 'https://%s\n' "$TARGET" \
         | httpx -silent -favicon -no-color 2>/dev/null | grep -oE '\-?[0-9]{5,}' | head -1)
    if [[ -n "$fh" ]]; then
      {
        echo "## Favicon hash (mmh3 — pivot on Shodan/FOFA)"
        echo "  http.favicon.hash:$fh"
        echo
      } >> "$out"
    fi
  fi

  log_ok "OSINT summary written: $out"
}
