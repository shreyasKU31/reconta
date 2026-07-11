#!/usr/bin/env bash
#
# modules/analyze.sh — turn raw collected data into a PRIORITIZED work list.
#
# This is what makes Reconta more than a tool-runner. Every URL is scored
# against the signature knowledge base (config/signatures.txt), every live
# host is scored on status/tech/title/port, and confirmed vulns + secrets are
# folded in at the top. The result — interesting.txt — tells a hunter exactly
# where to look first instead of drowning them in tens of thousands of lines.
#
# Inputs : $OUTDIR/urls.txt, $D_SUBS/httpx.jsonl, vulns.txt, secrets.txt
# Output : $OUTDIR/interesting.txt  (ranked, human-readable — the star output)
#          $D_ANALYZE/ranked.tsv    (machine form: score \t tags \t asset)

module_analyze() {
  [[ "${ENABLE_ANALYZE:-1}" == 1 ]] || { log_info "analyze: disabled"; return 0; }
  log_step "Analysis — scoring & prioritizing (signal extraction)"
  mkdir -p "$D_ANALYZE"
  local urls="$OUTDIR/urls.txt"
  local jsonl="$D_SUBS/httpx.jsonl"
  local sigs="${SIGNATURES:-$RECONTA_HOME/config/signatures.txt}"
  local out="$OUTDIR/interesting.txt"
  local scored="$D_ANALYZE/scored.tsv"; : > "$scored"

  # -- 1. Score every URL against the signature knowledge base ---------------
  if [[ -s "$urls" && -f "$sigs" ]]; then
    awk '
      # First file: load signatures into parallel arrays.
      NR==FNR {
        if ($0 ~ /^[[:space:]]*#/ || NF < 3) next
        w[++n]=$1; c[n]=$2; r[n]=tolower($3); next
      }
      # Second file: score each URL, accumulating weight + tags on matches.
      {
        u=tolower($0); sc=0; tg=""
        for (i=1;i<=n;i++) if (u ~ r[i]) { sc+=w[i]; tg = tg (tg?",":"") c[i] }
        if (sc>0) printf "%d\t%s\t%s\n", sc, tg, $0
      }
    ' "$sigs" "$urls" >> "$scored"
    log_result "URL signatures matched: $(count "$scored") hits"
  fi

  # -- 2. Score live hosts from httpx metadata (status/tech/title/port) ------
  if [[ -s "$jsonl" ]] && have_tool jq; then
    jq -r '
      def dc(x): (x // "" | ascii_downcase);
      (dc(.title)) as $t |
      (dc((.tech // []) | join(","))) as $tech |
      (dc(.url)) as $url |
      [ (if ((.status_code|tostring)|test("^(401|403)$")) then {s:45,t:"auth-protected"} else empty end),
        (if ((.status_code|tostring)|test("^5")) then {s:35,t:"server-error"} else empty end),
        (if ($t|test("admin|login|dashboard|portal|console|manager")) then {s:55,t:"admin-title"} else empty end),
        (if ($tech|test("jenkins|grafana|kibana|gitlab|phpmyadmin|swagger|jira|elasticsearch|prometheus|tomcat|weblogic|jboss")) then {s:80,t:"sensitive-tech"} else empty end),
        (if ($t|test("dev|staging|test|internal|uat|qa|demo|beta")) or ($url|test("(//|\\.)(dev|staging|test|uat|qa|stage|internal|demo|beta)[.-]")) then {s:40,t:"non-prod"} else empty end),
        (if ((.port|tostring)|test("^(80|443|)$")|not) then {s:25,t:"odd-port"} else empty end)
      ] as $m |
      ($m|map(.s)|add // 0) as $s |
      if $s>0 then "\($s)\t\(($m|map(.t)|join(",")))\thost:\(.url)" else empty end
    ' "$jsonl" >> "$scored" 2>/dev/null || true
  fi

  # -- 3. Fold in confirmed vulns and secrets at the very top ----------------
  if [[ -s "$OUTDIR/vulns.txt" ]]; then
    awk '
      /\[critical\]/ {printf "1000\tvuln-critical\t%s\n",$0; next}
      /\[high\]/     {printf "600\tvuln-high\t%s\n",$0;     next}
      /\[medium\]/   {printf "250\tvuln-medium\t%s\n",$0;   next}
    ' "$OUTDIR/vulns.txt" >> "$scored"
  fi
  if [[ -s "$OUTDIR/secrets.txt" ]]; then
    awk 'NF{printf "900\tsecret-leak\t%s\n",$0}' "$OUTDIR/secrets.txt" >> "$scored"
  fi

  # -- 4. Dedup by asset (keep highest score), then rank -----------------------
  if [[ -s "$scored" ]]; then
    LC_ALL=C sort -t"$(printf '\t')" -k3,3 -k1,1nr "$scored" \
      | awk -F'\t' '!seen[$3]++' \
      | LC_ALL=C sort -t"$(printf '\t')" -k1,1nr > "$D_ANALYZE/ranked.tsv"
  else
    : > "$D_ANALYZE/ranked.tsv"
  fi

  # -- 5. Emit the human-readable prioritized list ----------------------------
  {
    echo "# Reconta — prioritized findings for $TARGET"
    echo "# Ranked by impact/interest. Start at the top. Format: [score] tags  asset"
    echo "#"
    echo "# Legend: vuln-*/secret-leak = act now · sensitive-file/exposed-* = high"
    echo "#         *-param = fuzz for that bug class · non-prod/admin = pivot points"
    echo
    awk -F'\t' 'NF>=3{ printf "[%4d] %-26s %s\n", $1, $2, $3 }' "$D_ANALYZE/ranked.tsv"
  } > "$out"

  local n; n=$(awk -F'\t' 'NF>=3{c++} END{print c+0}' "$D_ANALYZE/ranked.tsv" 2>/dev/null)
  n=${n:-0}
  export ANALYZE_COUNT="$n"
  if [[ "$n" -gt 0 ]]; then
    log_ok "Prioritized $n high-value items → interesting.txt"
    log_result "top: $(head -1 "$D_ANALYZE/ranked.tsv" | cut -f2-3 | tr '\t' ' ')"
  else
    log_ok "No high-value items surfaced by signatures"
  fi
}
