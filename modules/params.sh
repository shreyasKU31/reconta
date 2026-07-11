#!/usr/bin/env bash
#
# modules/params.sh — discover hidden / interesting parameters worth fuzzing.
# Combines archive-mined params (paramspider) with active brute force (arjun).
#
# Inputs : $OUTDIR/hosts.txt, $D_URLS/params.txt
# Output : $OUTDIR/params.txt   (URLs with discovered parameters)

module_params() {
  [[ "$ENABLE_PARAMS" == 1 ]] || { log_info "params: disabled"; return 0; }
  log_step "Parameter discovery"
  mkdir -p "$D_PARAMS"
  local hosts="$OUTDIR/hosts.txt"
  local out="$OUTDIR/params.txt"; touchf "$out"

  # Seed with parameterised URLs already discovered during URL collection.
  [[ -s "$D_URLS/params.txt" ]] && cp "$D_URLS/params.txt" "$out"

  if [[ ! -s "$hosts" ]]; then log_warn "no hosts for param discovery"; return 0; fi

  # -- paramspider: parameters straight from archive data (fast, passive) -----
  if have_tool paramspider; then
    log_info "mining archived parameters (paramspider)…"
    paramspider -d "$TARGET" --level high -q 2>/dev/null \
      | anew -q "$out" >/dev/null 2>&1 || true
  fi

  # -- arjun: brute-force hidden params on live hosts (active, deeper) ---------
  # Only in normal/deep — this touches the target directly.
  if [[ "$PROFILE" != quick ]] && have_tool arjun; then
    log_info "brute-forcing hidden parameters (arjun)…"
    # Limit arjun to a manageable slice of hosts to keep runtime sane.
    head -n 50 "$hosts" > "$D_PARAMS/targets.txt"
    capped 600 arjun -i "$D_PARAMS/targets.txt" -t "$THREADS" -q \
      -oT "$D_PARAMS/arjun.txt" >/dev/null 2>&1 || true
    [[ -s "$D_PARAMS/arjun.txt" ]] && anew -q "$out" < "$D_PARAMS/arjun.txt" >/dev/null 2>&1 || true
  fi

  uniq_sort "$out"
  log_ok "Parameters discovered: $(count "$out")"
}
