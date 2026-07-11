#!/usr/bin/env bash
#
# modules/report.sh — synthesize every module's filtered output into a single
# final report (Markdown + self-contained HTML). This is the deliverable.

# helper: safely grab the first N lines of a file, or a placeholder.
_head_or_none() {
  if [[ -s "$1" ]]; then head -n "${2:-20}" "$1"; else echo "(none)"; fi
}

module_report() {
  log_step "Final report"
  local md="$OUTDIR/report.md"
  local html="$OUTDIR/report.html"

  # -- Tally everything for the summary table ---------------------------------
  local n_subs n_hosts n_ports n_urls n_params n_js n_secrets n_vulns n_crit n_high
  local n_interesting n_new
  n_subs=$(count "$OUTDIR/subdomains.txt")
  n_hosts=$(count "$OUTDIR/hosts.txt")
  n_ports=$(count "$OUTDIR/ports.txt")
  n_urls=$(count "$OUTDIR/urls.txt")
  n_params=$(count "$OUTDIR/params.txt")
  n_js=$(count "$OUTDIR/js.txt")
  n_secrets=$(count "$OUTDIR/secrets.txt")
  n_vulns=$(count "$OUTDIR/vulns.txt")
  n_crit=$(count_re '\[critical\]' "$OUTDIR/vulns.txt")
  n_high=$(count_re '\[high\]' "$OUTDIR/vulns.txt")
  n_interesting=$(awk -F'\t' 'NF>=3{c++} END{print c+0}' "$D_ANALYZE/ranked.tsv" 2>/dev/null)
  n_interesting=${n_interesting:-0}
  n_new="${DIFF_TOTAL_NEW:-0}"
  local wl="$OUTDIR/wordlists" n_wl_dirs n_wl_users n_wl_pass n_wl_subs
  n_wl_dirs=$(count "$wl/directories.txt")
  n_wl_users=$(count "$wl/usernames.txt")
  n_wl_pass=$(count "$wl/passwords.txt")
  n_wl_subs=$(count "$wl/subdomains.txt")

  # Convenience: top prioritized findings as ready-to-read lines.
  _top_findings() { awk -F'\t' 'NF>=3{printf "[%d] %s  %s\n",$1,$2,$3}' \
                    "$D_ANALYZE/ranked.tsv" 2>/dev/null | head -n "${1:-15}"; }

  # -------------------------------------------------------------------------
  # Markdown report
  # -------------------------------------------------------------------------
  {
    echo "# Reconta report — \`$TARGET\`"
    echo
    echo "- **Scan date:** $(date -u +'%Y-%m-%d %H:%M UTC')"
    echo "- **Profile:** $PROFILE"
    echo "- **Duration:** $(elapsed "$RUN_START")"
    echo
    echo "## Summary"
    echo
    echo "| Asset | Count |"
    echo "|---|---:|"
    echo "| Resolved subdomains | $n_subs |"
    echo "| Live HTTP hosts | $n_hosts |"
    echo "| Open ports/services | $n_ports |"
    echo "| Useful URLs | $n_urls |"
    echo "| Parameterised URLs | $n_params |"
    echo "| JavaScript files | $n_js |"
    echo "| **Secrets (review!)** | $n_secrets |"
    echo "| **Vuln signals** | $n_vulns (crit: $n_crit, high: $n_high) |"
    echo "| **Prioritized findings** | $n_interesting |"
    echo "| **New since last run** | $n_new |"
    echo

    # The headline: where to actually start.
    if [[ "$n_interesting" -gt 0 ]]; then
      echo "## Start here - top prioritized findings"
      echo
      echo "Ranked from \`interesting.txt\`. Highest impact/interest first."
      echo
      echo '```'
      _top_findings 20
      echo '```'
      echo
    fi

    # What changed since last time — the fresh, un-picked-over surface.
    if [[ "${DIFF_HAD_PRIOR:-0}" == 1 && "$n_new" -gt 0 ]]; then
      echo "## New since last run ($n_new)"
      echo
      echo '```'
      grep -vE '^[[:space:]]*#' "$OUTDIR/new.txt" 2>/dev/null | awk 'NF' | head -n 40
      echo '```'
      echo
    fi

    echo "## Live hosts (top 40)"
    echo '```'; _head_or_none "$OUTDIR/hosts.txt" 40; echo '```'; echo
    echo "## Open ports/services"
    echo '```'; _head_or_none "$OUTDIR/ports.txt" 40; echo '```'; echo
    echo "## Vulnerability signals"
    echo '```'; _head_or_none "$OUTDIR/vulns.txt" 40; echo '```'; echo
    echo "## OSINT"
    echo '```'; _head_or_none "$OUTDIR/osint.txt" 40; echo '```'; echo

    if [[ "$((n_wl_dirs + n_wl_users + n_wl_pass + n_wl_subs))" -gt 0 ]]; then
      echo "## Custom wordlists"
      echo
      echo "Built from this target's own data (see \`wordlists/USAGE.txt\` for commands)."
      echo
      echo "| Wordlist | Words | Used with |"
      echo "|---|---:|---|"
      echo "| directories.txt | $n_wl_dirs | ffuf, gobuster |"
      echo "| usernames.txt | $n_wl_users | hydra, Burp Intruder |"
      echo "| passwords.txt | $n_wl_pass | hydra, hashcat, john |"
      echo "| subdomains.txt | $n_wl_subs | alterx, puredns |"
      echo
    fi

    echo "## Full data files"
    echo
    echo "All results live under \`$OUTDIR/\`:"
    echo
    for f in interesting new subdomains hosts ports urls params js secrets osint vulns; do
      [[ -f "$OUTDIR/$f.txt" ]] && echo "- \`$f.txt\` — $(count "$OUTDIR/$f.txt") lines"
    done
    [[ -f "$OUTDIR/report.json" ]] && echo "- \`report.json\` — machine-readable summary"
  } > "$md"

  # -------------------------------------------------------------------------
  # HTML report — self-contained, no external assets.
  # -------------------------------------------------------------------------
  _card() { # label value [danger]
    local cls="card"; [[ "${3:-}" == danger && "$2" -gt 0 ]] && cls="card danger"
    printf '<div class="%s"><div class="n">%s</div><div class="l">%s</div></div>\n' "$cls" "$2" "$1"
  }
  _section() { # title file
    printf '<h2>%s</h2><pre>%s</pre>\n' "$1" \
      "$( [[ -s "$2" ]] && head -n 60 "$2" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' || echo '(none)' )"
  }

  {
    cat <<HTMLHEAD
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reconta — $TARGET</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--danger:#f85149;--ok:#3fb950}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
.wrap{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{font-size:26px;margin:0 0 4px}h1 span{color:var(--accent)}
.meta{color:var(--muted);margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:28px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--muted);font-size:13px;margin-top:2px}
.card.danger{border-color:var(--danger)}.card.danger .n{color:var(--danger)}
h2{font-size:16px;border-bottom:1px solid var(--border);padding-bottom:6px;margin-top:32px}
pre{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px;overflow-x:auto;font:13px/1.5 ui-monospace,Consolas,monospace;color:var(--fg)}
footer{color:var(--muted);font-size:12px;margin-top:40px;border-top:1px solid var(--border);padding-top:16px}
</style></head><body><div class="wrap">
<h1>Reconta — <span>$TARGET</span></h1>
<div class="meta">$(date -u +'%Y-%m-%d %H:%M UTC') · profile: $PROFILE · duration: $(elapsed "$RUN_START")</div>
<div class="grid">
HTMLHEAD
    _card "Prioritized" "$n_interesting" danger
    _card "New this run" "$n_new" danger
    _card "Subdomains" "$n_subs"
    _card "Live hosts" "$n_hosts"
    _card "Open ports" "$n_ports"
    _card "URLs" "$n_urls"
    _card "Parameters" "$n_params"
    _card "JS files" "$n_js"
    _card "Secrets" "$n_secrets" danger
    _card "Vuln signals" "$n_vulns" danger
    _card "Wordlist words" "$((n_wl_dirs + n_wl_users + n_wl_pass + n_wl_subs))"
    echo '</div>'
    # Headline sections first: where to start, and what's new.
    printf '<h2>Start here - top prioritized findings</h2><pre>%s</pre>\n' \
      "$( _top_findings 25 | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' | awk 'NF' || echo '(none)')"
    if [[ "${DIFF_HAD_PRIOR:-0}" == 1 ]]; then
      _section "New since last run" "$OUTDIR/new.txt"
    fi
    _section "Vulnerability signals" "$OUTDIR/vulns.txt"
    _section "Secrets (review manually)" "$OUTDIR/secrets.txt"
    _section "Live hosts" "$OUTDIR/hosts.txt"
    _section "Open ports / services" "$OUTDIR/ports.txt"
    _section "OSINT" "$OUTDIR/osint.txt"
    if [[ "$((n_wl_dirs + n_wl_users + n_wl_pass + n_wl_subs))" -gt 0 ]]; then
      printf '<h2>Custom wordlists</h2><pre>%s</pre>\n' \
"directories.txt   ${n_wl_dirs} words   (ffuf, gobuster)
usernames.txt     ${n_wl_users} words   (hydra, Burp Intruder)
passwords.txt     ${n_wl_pass} words   (hydra, hashcat, john)
subdomains.txt    ${n_wl_subs} words   (alterx, puredns)

Built from this target's own data. See wordlists/USAGE.txt for ready-to-run commands."
    fi
    echo "<footer>Generated by Reconta — Recon + Data. Use only against targets you are authorized to test.</footer>"
    echo '</div></body></html>'
  } > "$html"

  # -------------------------------------------------------------------------
  # report.json — machine-readable summary for piping into other tooling.
  # -------------------------------------------------------------------------
  if [[ "${ENABLE_JSON:-1}" == 1 ]] && have_tool jq; then
    local top_json
    top_json=$(awk -F'\t' 'NF>=3{print $1"\t"$2"\t"$3}' "$D_ANALYZE/ranked.tsv" 2>/dev/null \
      | head -n 50 \
      | jq -R -s 'split("\n")|map(select(length>0)|split("\t")
                 |{score:(.[0]|tonumber),tags:(.[1]|split(",")),asset:.[2]})')
    [[ -n "$top_json" ]] || top_json='[]'

    jq -n \
      --arg target "$TARGET" \
      --arg profile "$PROFILE" \
      --arg date "$(date -u +%FT%TZ)" \
      --arg duration "$(elapsed "$RUN_START")" \
      --argjson counts "{
        \"subdomains\":$n_subs,\"hosts\":$n_hosts,\"ports\":$n_ports,
        \"urls\":$n_urls,\"params\":$n_params,\"js\":$n_js,
        \"secrets\":$n_secrets,\"vulns\":$n_vulns,
        \"vulns_critical\":$n_crit,\"vulns_high\":$n_high,
        \"prioritized\":$n_interesting,\"new\":$n_new,
        \"wordlist_directories\":$n_wl_dirs,\"wordlist_usernames\":$n_wl_users,
        \"wordlist_passwords\":$n_wl_pass,\"wordlist_subdomains\":$n_wl_subs
      }" \
      --argjson top "$top_json" \
      '{target:$target, profile:$profile, generated:$date, duration:$duration,
        counts:$counts, top_findings:$top}' > "$OUTDIR/report.json" 2>/dev/null \
      && log_ok "Report: $OUTDIR/report.json" \
      || log_warn "report.json generation failed (bad data?)"
  fi

  log_ok "Report: $md"
  log_ok "Report: $html"

  # Optional push notification with the headline numbers.
  if [[ "$NOTIFY" == 1 ]] && have_tool notify; then
    printf 'Reconta %s done: %s hosts · %s prioritized · %s new · %s vulns (%s crit/%s high) · %s secrets\n' \
      "$TARGET" "$n_hosts" "$n_interesting" "$n_new" "$n_vulns" "$n_crit" "$n_high" "$n_secrets" \
      | notify -silent >/dev/null 2>&1 || true
  fi
}
