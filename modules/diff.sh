#!/usr/bin/env bash
#
# modules/diff.sh — change detection across runs (continuous-recon primitive).
#
# The single most valuable recon signal is "what appeared since last time":
# a new subdomain, a freshly deployed host, a new endpoint or JS bundle, a new
# vuln. Reconta snapshots each run per-target and, on subsequent runs, surfaces
# ONLY the deltas — the assets nobody else has looked at yet.
#
# State: ~/.config/reconta/state/<target>/*.txt   (previous run's canonical files)
# Output: $OUTDIR/new.txt   (grouped list of everything new since last run)

module_diff() {
  [[ "${ENABLE_DIFF:-1}" == 1 ]] || { log_info "diff: disabled"; return 0; }
  log_step "Change detection (diff vs previous run)"

  local state="${STATE_DIR:-$HOME/.config/reconta/state}/$TARGET"
  local newf="$OUTDIR/new.txt"
  mkdir -p "$state"

  # Canonical asset files worth tracking for change (stable content, no scores).
  local files=(subdomains hosts ports urls js secrets vulns)
  local had_prior=0 total_new=0

  {
    echo "# New / changed assets since the previous Reconta run — $TARGET"
    echo "# $(date -u +%FT%TZ)"
    echo
  } > "$newf"

  local f cur prev delta n
  for f in "${files[@]}"; do
    cur="$OUTDIR/$f.txt"
    prev="$state/$f.txt"
    [[ -f "$cur" ]] || continue

    if [[ -f "$prev" ]]; then
      had_prior=1
      # Lines present now but not in the previous snapshot.
      if [[ -s "$prev" ]]; then
        delta=$(grep -Fxvf "$prev" "$cur" 2>/dev/null | grep -vE '^[[:space:]]*$' || true)
      else
        delta=$(grep -vE '^[[:space:]]*$' "$cur" 2>/dev/null || true)
      fi
      if [[ -n "$delta" ]]; then
        n=$(printf '%s\n' "$delta" | grep -c .)
        total_new=$((total_new + n))
        { echo "## +$n new in ${f}"; printf '%s\n' "$delta"; echo; } >> "$newf"
      fi
    fi

    # Update the snapshot for next time.
    cp "$cur" "$prev" 2>/dev/null || true
  done

  export DIFF_HAD_PRIOR="$had_prior" DIFF_TOTAL_NEW="$total_new"

  if [[ "$had_prior" == 0 ]]; then
    echo "(Baseline established — first tracked run for this target." >> "$newf"
    echo " Future runs will list only what changed.)" >> "$newf"
    log_ok "Baseline snapshot saved — no previous run to diff against"
  elif [[ "$total_new" -gt 0 ]]; then
    log_ok "⚡ $total_new NEW item(s) since last run → new.txt"
    # Push an alert when monitoring is on and something actually changed.
    if [[ "${MONITOR:-0}" == 1 || "${NOTIFY:-0}" == 1 ]] && have_tool notify; then
      { echo "⚡ Reconta: $total_new new assets on $TARGET";
        head -n 20 "$newf" | grep -E '^(##|[a-z0-9])'; } \
        | notify -silent >/dev/null 2>&1 || true
    fi
  else
    echo "(No changes since the previous run.)" >> "$newf"
    log_ok "No changes since last run"
  fi
}
