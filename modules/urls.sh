#!/usr/bin/env bash
#
# modules/urls.sh — URL & endpoint discovery, then aggressive de-noising.
# Passive archives (gau/waybackurls) + a live JS-aware crawl (katana) are
# merged, collapsed with uro (kills near-duplicate/parametric URLs), and
# probed with httpx so only URLs that still respond survive.
#
# Inputs : $OUTDIR/hosts.txt, $OUTDIR/subdomains.txt
# Outputs: $OUTDIR/urls.txt   (live, de-duplicated URLs — the useful set)
#          $D_URLS/params.txt (URLs that carry query parameters, for arjun etc.)

module_urls() {
  [[ "$ENABLE_URLS" == 1 ]] || { log_info "urls: disabled"; return 0; }
  log_step "URL & endpoint discovery"
  mkdir -p "$D_URLS"
  local hosts="$OUTDIR/hosts.txt"
  local resolved="$OUTDIR/subdomains.txt"
  local out="$OUTDIR/urls.txt"; touchf "$out"
  local pool="$D_URLS/pool.txt"; touchf "$pool"

  if [[ ! -s "$resolved" ]]; then log_warn "no hosts for URL discovery"; return 0; fi

  # -- Passive archives (fast, huge, noisy) -----------------------------------
  local upids=()
  (
    if have_tool gau; then
      gau --threads "$THREADS" --subs < "$resolved" 2>/dev/null > "$D_URLS/gau.txt"
    fi
  ) & upids+=($!)
  (
    if have_tool waybackurls; then
      waybackurls < "$resolved" 2>/dev/null > "$D_URLS/wayback.txt"
    fi
  ) & upids+=($!)
  wait "${upids[@]}" 2>/dev/null

  # -- Live crawl (JS-aware, catches what archives miss) ----------------------
  if [[ "$PROFILE" != quick ]] && have_tool katana && [[ -s "$hosts" ]]; then
    log_info "crawling live hosts (katana)…"
    local depth=2; [[ "$PROFILE" == deep ]] && depth=3
    capped 600 katana -list "$hosts" -d "$depth" -jc -kf all -silent \
      -rate-limit "$RATE_LIMIT" -o "$D_URLS/katana.txt" >/dev/null 2>&1 || true
  fi

  absorb "$pool" "$D_URLS/gau.txt" "$D_URLS/wayback.txt" "$D_URLS/katana.txt"
  local raw_n; raw_n=$(count "$pool")
  log_result "raw URLs collected: $raw_n"

  # -- THE noise filter: uro collapses parametric / near-duplicate URLs -------
  if have_tool uro; then
    uro -i "$pool" 2>/dev/null > "$out" || cp "$pool" "$out"
  else
    log_warn "'uro' not found — URLs will be noisier (dedup only)"
    cp "$pool" "$out"
  fi
  uniq_sort "$out"
  log_result "after uro collapse: $(count "$out")  (removed $(( raw_n - $(count "$out") )) noise URLs)"

  # -- Keep only URLs that still respond (drops dead archive links) -----------
  if [[ "$PROFILE" != quick ]] && have_tool httpx && [[ -s "$out" ]]; then
    log_info "verifying URLs are live (httpx)…"
    httpx -l "$out" -mc 200,201,202,204,301,302,307,401,403,405,500 \
          -threads "$THREADS" -rate-limit "$RATE_LIMIT" -timeout "$HTTP_TIMEOUT" \
          -silent -no-color -o "$D_URLS/live.txt" >/dev/null 2>&1 || true
    [[ -s "$D_URLS/live.txt" ]] && cp "$D_URLS/live.txt" "$out"
    uniq_sort "$out"
    log_result "live URLs: $(count "$out")"
  fi

  # -- Split out parameterised URLs for parameter-focused modules -------------
  grep -E '\?[^=]+=' "$out" 2>/dev/null | sort -u > "$D_URLS/params.txt" || true

  log_ok "Useful URLs: $(count "$out")  ($(count "$D_URLS/params.txt") with parameters)"
}
