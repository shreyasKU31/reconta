#!/usr/bin/env bash
#
# modules/fuzz.sh — active vulnerability hunting.
#
# Recon tells you WHERE to look; this stage actually tests for bugs. It takes
# the parameterised URLs and live hosts Reconta already found and runs proven
# detection for the bug classes that pay out in the real world:
#
#   - nuclei DAST : fuzzes parameters for XSS, SQLi, SSTI, LFI, redirect, CRLF,
#                   with built-in out-of-band (interactsh) for blind/SSRF bugs
#   - dalfox      : reflected / DOM XSS
#   - open redirect : canary-based active check
#   - CORS        : reflected-origin + credentials misconfiguration
#   - crlfuzz     : CRLF / response splitting          (deep profile)
#   - sqlmap      : SQL injection confirmation          (deep profile)
#
# Every confirmed finding is written to $OUTDIR/vulns.txt with a [severity] tag,
# so it flows into ranking (interesting.txt), change detection, and the report.
#
# This stage sends payloads to the target. It only runs in normal/deep profiles
# and can be disabled with ENABLE_FUZZ=0 or --no-fuzz. Authorized targets only.
#
# Inputs : $OUTDIR/params.txt, $OUTDIR/urls.txt, $OUTDIR/hosts.txt
# Output : appended findings in $OUTDIR/vulns.txt

module_fuzz() {
  [[ "${ENABLE_FUZZ:-1}" == 1 ]] || { log_info "fuzz: disabled"; return 0; }
  if [[ "$PROFILE" == quick ]]; then
    log_info "fuzz: skipped in quick profile (passive only)"
    return 0
  fi
  log_step "Active vulnerability hunting"
  mkdir -p "$D_FUZZ"
  local out="$OUTDIR/vulns.txt"; touchf "$out"
  local hosts="$OUTDIR/hosts.txt"

  # -- Build a focused set of parameterised URLs to test ----------------------
  # Collapse to unique parameter patterns so we don't fuzz 5000 near-identical
  # URLs; cap the total so the stage stays time-bounded.
  local params="$D_FUZZ/params.txt"; : > "$params"
  {
    [[ -s "$OUTDIR/params.txt" ]] && cat "$OUTDIR/params.txt"
    grep -E '\?[^=]+=' "$OUTDIR/urls.txt" 2>/dev/null
  } | sort -u > "$D_FUZZ/params.raw"
  if have_tool uro; then
    uro -i "$D_FUZZ/params.raw" 2>/dev/null > "$params" || cp "$D_FUZZ/params.raw" "$params"
  else
    cp "$D_FUZZ/params.raw" "$params"
  fi
  # In normal profile cap tighter than deep to keep runtime reasonable.
  local cap=300; [[ "$PROFILE" == deep ]] && cap=1500
  head -n "$cap" "$params" > "$params.capped" && mv "$params.capped" "$params"
  local nparams; nparams=$(count "$params")
  log_result "$nparams parameterised URLs queued for testing"

  # -- 1. nuclei DAST: multi-class parameter fuzzing + OOB --------------------
  if have_tool nuclei && [[ "$nparams" -gt 0 ]]; then
    log_info "nuclei DAST fuzzing (XSS/SQLi/SSTI/LFI/redirect/CRLF + OOB)..."
    # -dast enables the fuzzing templates; interactsh is built in for blind bugs.
    capped 1200 nuclei -l "$params" -dast \
      -rate-limit "$NUCLEI_RATE" -c "$THREADS" \
      -silent -no-color -jsonl -o "$D_FUZZ/nuclei-dast.jsonl" >/dev/null 2>&1 || true
    if [[ -s "$D_FUZZ/nuclei-dast.jsonl" ]] && have_tool jq; then
      jq -r '"[\(.info.severity)] dast:\(.["template-id"]) — \(.matched-at // .host)"' \
        "$D_FUZZ/nuclei-dast.jsonl" 2>/dev/null | anew -q "$out" >/dev/null || true
      log_result "nuclei DAST findings: $(count "$D_FUZZ/nuclei-dast.jsonl")"
    fi
  fi

  # -- 2. dalfox: reflected / DOM XSS ----------------------------------------
  if have_tool dalfox && [[ "$nparams" -gt 0 ]]; then
    log_info "dalfox XSS scan..."
    capped 900 dalfox file "$params" --silence --no-spinner --skip-mining-dom \
      -w "$THREADS" -o "$D_FUZZ/dalfox.txt" >/dev/null 2>&1 || true
    # dalfox marks confirmed findings with [POC]; treat those as high severity.
    if [[ -s "$D_FUZZ/dalfox.txt" ]]; then
      grep -aoE 'https?://[^ ]+' "$D_FUZZ/dalfox.txt" 2>/dev/null | sort -u \
        | sed 's/^/[high] xss:dalfox — /' | anew -q "$out" >/dev/null || true
      log_result "dalfox XSS candidates: $(count "$D_FUZZ/dalfox.txt")"
    fi
  fi

  # -- 3. Open redirect: canary-based active check ---------------------------
  # Set redirect-style params to a canary and see if the server 3xx-es to it.
  if [[ "$nparams" -gt 0 ]] && have_tool curl; then
    log_info "open-redirect check..."
    local canary="https://reconta-oob.example"
    local redir="$D_FUZZ/redir.txt"; : > "$redir"
    grep -iE '[?&](url|uri|redirect|redir|next|dest|destination|return|returnurl|continue|goto|out|target|link|to|view|image_url|forward|redirect_uri)=' \
      "$params" 2>/dev/null | head -n 200 > "$D_FUZZ/redir-cand.txt" || true
    if [[ -s "$D_FUZZ/redir-cand.txt" ]]; then
      local u loc payloadurl
      while read -r u; do
        # Replace each candidate param value with the canary.
        if have_tool qsreplace; then
          payloadurl=$(printf '%s\n' "$u" | qsreplace "$canary" 2>/dev/null | head -1)
        else
          payloadurl=$(printf '%s\n' "$u" | sed -E "s#(=)[^&]*#\1${canary}#g")
        fi
        [[ -n "$payloadurl" ]] || continue
        loc=$(capped 10 curl -s -o /dev/null -m 8 -w '%{redirect_url}' "$payloadurl" 2>/dev/null)
        case "$loc" in
          "$canary"*|"http://reconta-oob.example"*)
            printf '[medium] open-redirect — %s\n' "$u" >> "$redir" ;;
        esac
      done < "$D_FUZZ/redir-cand.txt"
      [[ -s "$redir" ]] && sort -u "$redir" | anew -q "$out" >/dev/null || true
      log_result "open redirects confirmed: $(count "$redir")"
    fi
  fi

  # -- 4. CORS misconfiguration ----------------------------------------------
  # Reflected arbitrary Origin + credentials = account-data exposure risk.
  if [[ -s "$hosts" ]] && have_tool curl; then
    log_info "CORS misconfiguration check..."
    local cors="$D_FUZZ/cors.txt"; : > "$cors"
    local h hdrs
    while read -r h; do
      hdrs=$(capped 10 curl -s -I -m 8 -H 'Origin: https://evil.reconta.test' "$h" 2>/dev/null)
      if printf '%s' "$hdrs" | grep -qi 'access-control-allow-origin: *https\?://evil\.reconta\.test' \
         && printf '%s' "$hdrs" | grep -qi 'access-control-allow-credentials: *true'; then
        printf '[medium] cors-misconfig — %s\n' "$h" >> "$cors"
      fi
    done < <(head -n 200 "$hosts")
    [[ -s "$cors" ]] && sort -u "$cors" | anew -q "$out" >/dev/null || true
    log_result "CORS misconfigurations: $(count "$cors")"
  fi

  # -- 5. CRLF injection (deep) ----------------------------------------------
  if [[ "$PROFILE" == deep ]] && have_tool crlfuzz && [[ "$nparams" -gt 0 ]]; then
    log_info "CRLF injection scan (crlfuzz)..."
    capped 600 crlfuzz -l "$params" -s -c "$THREADS" -o "$D_FUZZ/crlf.txt" >/dev/null 2>&1 || true
    if [[ -s "$D_FUZZ/crlf.txt" ]]; then
      sed 's/^/[medium] crlf-injection — /' "$D_FUZZ/crlf.txt" | anew -q "$out" >/dev/null || true
      log_result "CRLF findings: $(count "$D_FUZZ/crlf.txt")"
    fi
  fi

  # -- 6. SQL injection confirmation (deep) ----------------------------------
  if [[ "$PROFILE" == deep ]] && have_tool sqlmap && [[ "$nparams" -gt 0 ]]; then
    log_info "SQL injection scan (sqlmap, top 100 URLs)..."
    head -n 100 "$params" > "$D_FUZZ/sqli-in.txt"
    capped 1800 sqlmap -m "$D_FUZZ/sqli-in.txt" --batch --smart --random-agent \
      --level 1 --risk 1 --output-dir="$D_FUZZ/sqlmap" >/dev/null 2>&1 || true
    # sqlmap logs confirmed injectable parameters in its output tree.
    if grep -rqiE "is vulnerable|sqlmap identified.*injection" "$D_FUZZ/sqlmap" 2>/dev/null; then
      grep -rhoiE "https?://[^ ']+" "$D_FUZZ/sqlmap"/*/log 2>/dev/null | sort -u \
        | sed 's/^/[critical] sqli:sqlmap — /' | anew -q "$out" >/dev/null || true
      log_result "SQL injection: confirmed (see .raw/fuzz/sqlmap)"
    fi
  fi

  # -- Re-sort findings by severity (worst first) and de-duplicate ------------
  if [[ -s "$out" ]]; then
    { grep -i '\[critical\]' "$out"; grep -i '\[high\]' "$out";
      grep -i '\[medium\]' "$out"; grep -i '\[low\]' "$out";
      grep -viE '\[(critical|high|medium|low)\]' "$out"; } 2>/dev/null \
      | awk '!seen[$0]++ && NF' > "$out.tmp" && mv "$out.tmp" "$out"
  fi

  local crit high
  crit=$(count_re '\[critical\]' "$out"); high=$(count_re '\[high\]' "$out")
  log_ok "Active hunting done — findings so far: $(count "$out") (critical: $crit, high: $high)"
}
