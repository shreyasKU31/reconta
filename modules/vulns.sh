#!/usr/bin/env bash
#
# modules/vulns.sh — low-hanging vulnerability signals across the live surface.
# nuclei for templated CVEs/misconfigs/exposures; subzy for subdomain takeover.
# 'info' severity is excluded by default (see NUCLEI_SEVERITY) to cut noise.
#
# Inputs : $OUTDIR/hosts.txt, $OUTDIR/subdomains.txt, $OUTDIR/urls.txt
# Output : $OUTDIR/vulns.txt   (deduped findings, most actionable data of all)

module_vulns() {
  [[ "$ENABLE_VULNS" == 1 ]] || { log_info "vulns: disabled"; return 0; }
  log_step "Vulnerability signals (low-hanging fruit)"
  mkdir -p "$D_VULNS"
  local hosts="$OUTDIR/hosts.txt"
  local resolved="$OUTDIR/subdomains.txt"
  local out="$OUTDIR/vulns.txt"; touchf "$out"

  if [[ ! -s "$hosts" ]]; then log_warn "no live hosts to test"; return 0; fi

  # -- Technology stack inventory --------------------------------------------
  # Build a per-target technology list from httpx fingerprints. This drives the
  # stack-specific CVE scan below and gives you a clear "what is it running" view.
  local techstack="$OUTDIR/techstack.txt"
  if [[ -s "$D_SUBS/httpx.jsonl" ]] && have_tool jq; then
    jq -r '. as $r | (.tech // [])[]? | "\(.)\t\($r.url)"' "$D_SUBS/httpx.jsonl" 2>/dev/null \
      | sort -u > "$D_VULNS/tech-hosts.tsv" || true
    # Summarise: "technology  (N hosts)" so you see the stack at a glance.
    cut -f1 "$D_VULNS/tech-hosts.tsv" 2>/dev/null | sort | uniq -c | sort -rn \
      | awk '{c=$1; $1=""; sub(/^ /,""); printf "%-30s %s host(s)\n", $0, c}' \
      > "$techstack" || true
    [[ -s "$techstack" ]] && log_result "technologies fingerprinted: $(count "$techstack")"
  fi

  # -- Subdomain takeover -----------------------------------------------------
  if have_tool subzy && [[ -s "$resolved" ]]; then
    log_info "checking subdomain takeover (subzy)…"
    subzy run --targets "$resolved" --hide_fails --concurrency "$THREADS" \
      2>/dev/null | grep -iE 'VULNERABLE|takeover' \
      | anew -q "$out" >/dev/null 2>&1 || true
  fi

  # -- nuclei: the workhorse --------------------------------------------------
  if require_tool nuclei "vuln scan"; then
    log_info "running nuclei (${NUCLEI_SEVERITY})…"
    have_tool nuclei && nuclei -update-templates -silent >/dev/null 2>&1 || true

    local sev="$NUCLEI_SEVERITY"
    [[ "$PROFILE" == quick ]] && sev="critical,high"

    # Scan live hosts. Feed URLs too when we have them (better coverage).
    local scan_input="$hosts"
    if [[ -s "$OUTDIR/urls.txt" ]]; then
      cat "$hosts" "$OUTDIR/urls.txt" | sort -u > "$D_VULNS/targets.txt"
      scan_input="$D_VULNS/targets.txt"
    fi

    nuclei -l "$scan_input" \
           -severity "$sev" \
           -rate-limit "$NUCLEI_RATE" -c "$THREADS" \
           -silent -no-color -stats \
           -jsonl -o "$D_VULNS/nuclei.jsonl" >/dev/null 2>&1 || true

    # Flatten nuclei JSONL into readable "[severity] template — url" lines.
    if [[ -s "$D_VULNS/nuclei.jsonl" ]] && have_tool jq; then
      jq -r '"[\(.info.severity)] \(.["template-id"]) — \(.matched-at // .host)"' \
        "$D_VULNS/nuclei.jsonl" 2>/dev/null | anew -q "$out" >/dev/null || true
    fi

    # -- Tech-stack-driven CVE scan (normal/deep) ----------------------------
    # nuclei's automatic scan fingerprints each host's technologies and runs the
    # CVE/vuln templates that match that exact stack — this is how you surface
    # CVEs tied to the detected tech rather than a generic sweep.
    if [[ "$PROFILE" != quick ]]; then
      log_info "tech-stack CVE scan (nuclei automatic scan)…"
      capped 1200 nuclei -l "$hosts" -as \
             -rate-limit "$NUCLEI_RATE" -c "$THREADS" \
             -silent -no-color \
             -jsonl -o "$D_VULNS/nuclei-tech.jsonl" >/dev/null 2>&1 || true
      if [[ -s "$D_VULNS/nuclei-tech.jsonl" ]] && have_tool jq; then
        jq -r '"[\(.info.severity)] cve:\(.["template-id"]) — \(.matched-at // .host)"' \
          "$D_VULNS/nuclei-tech.jsonl" 2>/dev/null | anew -q "$out" >/dev/null || true
        log_result "stack-specific findings: $(count "$D_VULNS/nuclei-tech.jsonl")"
      fi
    fi
  fi

  uniq_sort "$out"
  # Sort findings by severity so the scariest lines float to the top.
  if [[ -s "$out" ]]; then
    { grep -i '\[critical\]' "$out"; grep -i '\[high\]' "$out";
      grep -i '\[medium\]' "$out"; grep -i '\[low\]' "$out";
      grep -viE '\[(critical|high|medium|low)\]' "$out"; } 2>/dev/null \
      | awk 'NF' > "$out.sorted" && mv "$out.sorted" "$out"
  fi

  local crit high
  crit=$(count_re '\[critical\]' "$out")
  high=$(count_re '\[high\]' "$out")
  log_ok "Vuln signals: $(count "$out")  (critical: $crit, high: $high)"
}
