#!/usr/bin/env bash
#
# modules/osint.sh — infrastructure + people/leak OSINT that expands scope.
# ASN mapping finds IP ranges (and thus assets) nothing else will; theHarvester
# pulls emails/hosts; whois gives registration + reverse-pivot data.
#
# Every tool is time-capped and runs in parallel, writing its own fragment.
# If one tool hangs (asnmap in particular can), its cap kills it and the others
# still finish — the stage never stalls the whole scan.
#
# Output: $OUTDIR/osint.txt   (single consolidated, human-readable summary)

module_osint() {
  [[ "$ENABLE_OSINT" == 1 ]] || { log_info "osint: disabled"; return 0; }
  log_step "OSINT — infrastructure & exposure (parallel)"
  mkdir -p "$D_OSINT"
  local out="$OUTDIR/osint.txt"
  local f="$D_OSINT/frag"; mkdir -p "$f"
  local pids=()

  # -- ASN / IP ranges (capped: asnmap can hang for hours on some networks) ---
  if have_tool asnmap; then
    (
      {
        echo "## ASN / CIDR ranges"
        capped "${ASNMAP_TIMEOUT:-120}" asnmap -d "$TARGET" -silent 2>/dev/null | sort -u
        echo
      } > "$f/10-asn.txt"
    ) & pids+=($!)
  fi

  # -- WHOIS registration -----------------------------------------------------
  if have_tool whois; then
    (
      {
        echo "## WHOIS (registration)"
        capped "${WHOIS_TIMEOUT:-30}" whois "$TARGET" 2>/dev/null | grep -iE \
          'registrar|creation|created|expir|updated|name server|organization|registrant' \
          | sed 's/^[[:space:]]*//' | sort -u
        echo
      } > "$f/20-whois.txt"
    ) & pids+=($!)
  fi

  # -- DNS records (MX/NS/TXT/SPF/DMARC) --------------------------------------
  if have_tool dnsx; then
    (
      {
        echo "## DNS records"
        printf '%s\n' "$TARGET" \
          | capped "${DNSX_TIMEOUT:-60}" dnsx -silent -a -aaaa -mx -ns -txt -cname -resp 2>/dev/null \
          | sort -u
        echo
      } > "$f/30-dns.txt"
    ) & pids+=($!)
  fi

  # -- DNS zone transfer (AXFR): a quick, high-value misconfiguration check ----
  if have_tool dig; then
    (
      local ns axfr="$f/35-axfr.txt"
      echo "## DNS zone transfer (AXFR)" > "$axfr"
      while read -r ns; do
        [[ -n "$ns" ]] || continue
        if capped 20 dig AXFR "$TARGET" "@$ns" +short 2>/dev/null | grep -qE '[A-Za-z0-9]'; then
          echo "  VULNERABLE: zone transfer allowed by $ns" >> "$axfr"
        fi
      done < <(capped 20 dig NS "$TARGET" +short 2>/dev/null | head -5)
      echo >> "$axfr"
    ) & pids+=($!)
  fi

  # -- Emails / hosts / names (capped: theHarvester can run very long) --------
  if have_tool theHarvester; then
    (
      capped "${HARVESTER_TIMEOUT:-180}" theHarvester -d "$TARGET" -b all \
        -f "$D_OSINT/harvester" >/dev/null 2>&1 || true
      {
        echo "## Emails"
        if [[ -f "$D_OSINT/harvester.json" ]] && have_tool jq; then
          jq -r '.emails[]?' "$D_OSINT/harvester.json" 2>/dev/null | sort -u
        fi
        echo
      } > "$f/40-emails.txt"
    ) & pids+=($!)
  fi

  # -- Favicon hash → pivot hint (mmh3) --------------------------------------
  if have_tool httpx; then
    (
      local fh
      fh=$(printf 'https://%s\n' "$TARGET" \
           | capped 30 httpx -silent -favicon -no-color 2>/dev/null \
           | grep -oE '\-?[0-9]{5,}' | head -1)
      {
        echo "## Favicon hash (mmh3 — pivot on Shodan/FOFA)"
        [[ -n "$fh" ]] && echo "  http.favicon.hash:$fh"
        echo
      } > "$f/50-favicon.txt"
    ) & pids+=($!)
  fi

  # Wait on each job by PID (never a bare `wait`, which would also block on the
  # tee log child). A capped tool that dies just leaves a short fragment.
  local p; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done

  # Assemble the fragments in a stable order into the single summary file.
  {
    echo "# OSINT summary for $TARGET"
    echo "# generated $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo
    cat "$f"/*.txt 2>/dev/null
  } > "$out"
  rm -rf "$f"

  log_ok "OSINT summary written: $out"
}
