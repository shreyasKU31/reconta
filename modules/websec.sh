#!/usr/bin/env bash
#
# modules/websec.sh — fast web-security methodology checks.
#
# These are high-signal misconfigurations that a default nuclei run often filters
# out (they are frequently tagged info/low) but that lead to real bugs. Each
# check is capped and the checks run in parallel, so the stage is quick and can
# never hang. Findings are appended to vulns.txt (severity tagged) and flow into
# the chains, ranking, and report like everything else.
#
# Checks: GraphQL introspection, dangerous HTTP methods, null-origin CORS,
#         missing clickjacking protection.
#
# Inputs : $OUTDIR/hosts.txt, $OUTDIR/urls.txt
# Output : appended findings in $OUTDIR/vulns.txt

module_websec() {
  [[ "${ENABLE_WEBSEC:-1}" == 1 ]] || { log_info "websec: disabled"; return 0; }
  if [[ "$PROFILE" == quick ]]; then log_info "websec: skipped in quick profile"; return 0; fi
  log_step "Web-security methodology checks"
  have_tool curl || { log_warn "curl missing — skipping websec"; return 0; }
  mkdir -p "$D_WEBSEC"
  local hosts="$OUTDIR/hosts.txt"
  local out="$OUTDIR/vulns.txt"; touchf "$out"
  [[ -s "$hosts" ]] || { log_warn "no hosts for websec"; return 0; }

  # Cap the host sample so the sequential per-host checks stay time-bounded on
  # large scopes; each curl is also individually capped below.
  local subset="$D_WEBSEC/hosts.txt"
  local nmax=100; [[ "$PROFILE" == deep ]] && nmax=250
  head -n "$nmax" "$hosts" > "$subset"
  local pids=()

  # -- GraphQL introspection enabled (schema disclosure) ----------------------
  (
    local gq="$D_WEBSEC/graphql.txt"; : > "$gq"
    local base ep q='{"query":"{__schema{types{name}}}"}'
    while read -r base; do
      for ep in graphql graphql/console v1/graphql api/graphql; do
        if capped 12 curl -sk -m 10 -X POST -H 'Content-Type: application/json' \
             -d "$q" "${base%/}/$ep" 2>/dev/null | grep -qi '"__schema"'; then
          echo "[medium] graphql-introspection — ${base%/}/$ep" >> "$gq"
          break
        fi
      done
    done < "$subset"
    [[ -s "$gq" ]] && cat "$gq" >> "$out"
  ) & pids+=($!)

  # -- Dangerous HTTP methods (PUT/DELETE/TRACE enabled) ----------------------
  (
    local m="$D_WEBSEC/methods.txt"; : > "$m"
    local base allow
    while read -r base; do
      allow=$(capped 12 curl -sk -m 10 -X OPTIONS -i "$base" 2>/dev/null \
              | grep -i '^allow:' | tr -d '\r')
      if printf '%s' "$allow" | grep -qiE '\b(PUT|DELETE|TRACE|CONNECT)\b'; then
        echo "[medium] dangerous-http-methods — $base ($allow)" >> "$m"
      fi
    done < "$subset"
    [[ -s "$m" ]] && cat "$m" >> "$out"
  ) & pids+=($!)

  # -- null-origin CORS (complements the reflected-origin check in fuzz) ------
  (
    local c="$D_WEBSEC/cors-null.txt"; : > "$c"
    local base hdrs
    while read -r base; do
      hdrs=$(capped 12 curl -sk -m 10 -I -H 'Origin: null' "$base" 2>/dev/null)
      if printf '%s' "$hdrs" | grep -qi 'access-control-allow-origin: *null' \
         && printf '%s' "$hdrs" | grep -qi 'access-control-allow-credentials: *true'; then
        echo "[medium] cors-null-origin — $base" >> "$c"
      fi
    done < "$subset"
    [[ -s "$c" ]] && cat "$c" >> "$out"
  ) & pids+=($!)

  # -- Missing clickjacking protection (no X-Frame-Options / CSP frame-ancestors)
  (
    local cj="$D_WEBSEC/clickjacking.txt"; : > "$cj"
    local base hdrs
    while read -r base; do
      hdrs=$(capped 12 curl -sk -m 10 -I "$base" 2>/dev/null | tr -d '\r')
      if ! printf '%s' "$hdrs" | grep -qi 'x-frame-options' \
         && ! printf '%s' "$hdrs" | grep -qi 'content-security-policy:.*frame-ancestors'; then
        echo "[low] clickjacking-missing-xfo — $base" >> "$cj"
      fi
    done < <(head -n 40 "$subset")   # lower value → smaller sample
    [[ -s "$cj" ]] && cat "$cj" >> "$out"
  ) & pids+=($!)

  local p; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done

  # Keep vulns.txt severity-ordered after appending.
  if [[ -s "$out" ]]; then
    { grep -i '\[critical\]' "$out"; grep -i '\[high\]' "$out";
      grep -i '\[medium\]' "$out"; grep -i '\[low\]' "$out";
      grep -viE '\[(critical|high|medium|low)\]' "$out"; } 2>/dev/null \
      | awk '!seen[$0]++ && NF' > "$out.tmp" && mv "$out.tmp" "$out"
  fi

  log_ok "Web-security checks done — total findings: $(count "$out")"
}
