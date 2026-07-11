#!/usr/bin/env bash
#
# modules/javascript.sh — pull JS files from the surface and mine them for
# endpoints and, most valuably, leaked secrets/keys.
#
# Inputs : $OUTDIR/urls.txt, $OUTDIR/hosts.txt
# Outputs: $OUTDIR/js.txt       (unique live .js URLs)
#          $OUTDIR/secrets.txt  (verified/high-signal secrets — HIGH VALUE)

module_javascript() {
  [[ "$ENABLE_JS" == 1 ]] || { log_info "javascript: disabled"; return 0; }
  log_step "JavaScript analysis & secret hunting"
  mkdir -p "$D_JS"
  local urls="$OUTDIR/urls.txt"
  local hosts="$OUTDIR/hosts.txt"
  local js="$OUTDIR/js.txt"; touchf "$js"
  local secrets="$OUTDIR/secrets.txt"; touchf "$secrets"

  # -- Collect JS URLs from the URL pool and by scraping live hosts -----------
  grep -iE '\.js(\?|$)' "$urls" 2>/dev/null | sort -u > "$js" || true
  if have_tool subjs && [[ -s "$hosts" ]]; then
    subjs < "$hosts" 2>/dev/null | anew -q "$js" >/dev/null 2>&1 || true
  fi

  # Keep only JS that actually loads.
  if [[ -s "$js" ]] && have_tool httpx; then
    httpx -l "$js" -mc 200 -threads "$THREADS" -silent -no-color \
      -o "$D_JS/live.txt" >/dev/null 2>&1 || true
    [[ -s "$D_JS/live.txt" ]] && cp "$D_JS/live.txt" "$js"
  fi
  uniq_sort "$js"
  log_result "$(count "$js") live JS files"

  [[ -s "$js" ]] || { log_ok "No JS files found"; return 0; }

  # -- Extract endpoints hidden inside JS -------------------------------------
  if have_tool katana; then
    # katana in passive/JS mode is an easy way to pull endpoints from JS.
    capped 300 katana -list "$js" -jc -silent 2>/dev/null \
      | anew -q "$OUTDIR/urls.txt" >/dev/null 2>&1 || true
  fi

  # -- Secret scanning — the highest-value output of this stage ---------------
  # trufflehog only reports VERIFIED secrets by default → very low false positive.
  if have_tool trufflehog; then
    log_info "scanning JS for secrets (trufflehog)…"
    while read -r u; do
      trufflehog --no-update filesystem <(curl -s --max-time 10 "$u") 2>/dev/null
    done < "$js" > "$D_JS/trufflehog.txt" 2>/dev/null || true
    # Pull the human-readable secret lines out of trufflehog output.
    grep -iE 'Found|Detector|Verified' "$D_JS/trufflehog.txt" 2>/dev/null \
      | anew -q "$secrets" >/dev/null 2>&1 || true
  fi

  if have_tool mantra; then
    log_info "scanning JS for secrets (mantra)…"
    mantra < "$js" 2>/dev/null | anew -q "$secrets" >/dev/null 2>&1 || true
  fi

  uniq_sort "$secrets"
  if [[ -s "$secrets" ]]; then
    log_ok "⚠ Potential secrets found: $(count "$secrets") — review $secrets"
  else
    log_ok "No secrets surfaced in JS"
  fi
}
