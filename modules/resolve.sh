#!/usr/bin/env bash
#
# modules/resolve.sh — turn raw subdomain candidates into VERIFIED live hosts.
# This is the first big noise filter: DNS-dead and HTTP-dead names are dropped.
#
# Inputs : $D_SUBS/all.txt
# Outputs: $OUTDIR/subdomains.txt  (resolved, deduped — the canonical set)
#          $OUTDIR/hosts.txt       (live HTTP/S hosts, one URL per line)
#          $D_SUBS/httpx.jsonl     (full httpx records for the report/other modules)

module_resolve() {
  log_step "Resolution & liveness (noise filter)"
  local raw="$D_SUBS/all.txt"
  local resolved="$OUTDIR/subdomains.txt"; touchf "$resolved"
  local hosts="$OUTDIR/hosts.txt"; touchf "$hosts"
  local jsonl="$D_SUBS/httpx.jsonl"

  if [[ ! -s "$raw" ]]; then
    log_warn "no subdomain candidates to resolve"
    return 0
  fi

  # -- DNS resolution: drop names that don't resolve (wildcard-filtered) ------
  if require_tool dnsx "DNS resolution"; then
    local rflag=(); [[ -s "$RESOLVERS" ]] && rflag=(-r "$RESOLVERS")
    dnsx -l "$raw" "${rflag[@]}" -t "$RESOLVER_THREADS" -silent \
         -o "$resolved" >/dev/null 2>&1 || true
    log_result "$(count "$raw") candidates → $(count "$resolved") resolve in DNS"
  else
    # No dnsx: fall back to the raw list so the pipeline still proceeds.
    cp "$raw" "$resolved"
  fi
  uniq_sort "$resolved"

  # -- HTTP liveness + fingerprint: the actual attack surface -----------------
  if require_tool httpx "HTTP probing"; then
    httpx -l "$resolved" \
          -threads "$THREADS" -rate-limit "$RATE_LIMIT" -timeout "$HTTP_TIMEOUT" \
          -silent -no-color \
          -status-code -title -tech-detect -web-server -cdn -follow-redirects \
          -json -o "$jsonl" >/dev/null 2>&1 || true

    if [[ -s "$jsonl" ]] && have_tool jq; then
      jq -r '.url' "$jsonl" 2>/dev/null | sort -u > "$hosts"
    fi
    log_result "$(count "$resolved") resolved → $(count "$hosts") live HTTP hosts"
  else
    # Without httpx, assume https:// for every resolved name.
    sed 's#^#https://#' "$resolved" > "$hosts"
  fi
  uniq_sort "$hosts"

  log_ok "Live attack surface: $(count "$hosts") hosts"
}
