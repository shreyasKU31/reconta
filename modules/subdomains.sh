#!/usr/bin/env bash
#
# modules/subdomains.sh — passive + active subdomain enumeration.
# Output: $D_SUBS/all.txt  (raw, deduped — resolution happens in resolve.sh)

module_subdomains() {
  log_step "Subdomain enumeration"
  local raw="$D_SUBS/all.txt"; touchf "$raw"
  local tmp="$D_SUBS/.tmp"; mkdir -p "$tmp"

  # -- Passive sources, fanned out in parallel --------------------------------
  if [[ "$ENABLE_PASSIVE_SUBS" == 1 ]]; then
    log_info "passive sources (parallel)…"
    # Collect job PIDs and wait on those explicitly — a bare `wait` would also
    # block on the tee child from the run-log redirect and never return.
    local pids=()
    (
      require_tool subfinder "subfinder" &&
        subfinder -d "$TARGET" -all -silent -o "$tmp/subfinder.txt" >/dev/null 2>&1
    ) & pids+=($!)
    (
      require_tool assetfinder "assetfinder" &&
        assetfinder --subs-only "$TARGET" > "$tmp/assetfinder.txt" 2>/dev/null
    ) & pids+=($!)
    (
      # amass passive — deepest, slowest; capped so it can't stall the run.
      require_tool amass "amass" &&
        capped 300 amass enum -passive -d "$TARGET" -silent > "$tmp/amass.txt" 2>/dev/null
    ) & pids+=($!)
    (
      # crt.sh via certificate transparency — no binary needed, just curl+jq.
      if have_tool curl && have_tool jq; then
        curl -s --max-time 30 "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
          | jq -r '.[].name_value' 2>/dev/null \
          | sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' > "$tmp/crtsh.txt"
      fi
    ) & pids+=($!)
    (
      # findomain if present (another fast passive source)
      have_tool findomain &&
        findomain -t "$TARGET" -q > "$tmp/findomain.txt" 2>/dev/null
    ) & pids+=($!)
    wait "${pids[@]}" 2>/dev/null
    absorb "$raw" "$tmp"/*.txt
    log_result "passive → $(count "$raw") unique subdomains"
  fi

  # -- Active: permutations + brute force, resolved to kill fakes -------------
  if [[ "$ENABLE_ACTIVE_SUBS" == 1 && "$PROFILE" != quick ]]; then
    # Permutations from what we already found (dev-, staging-, api-, …)
    if have_tool alterx; then
      log_info "generating permutations (alterx)…"
      alterx -l "$raw" -silent 2>/dev/null | anew -q "$tmp/perms.txt" >/dev/null 2>&1 || true
    elif have_tool dnsgen; then
      log_info "generating permutations (dnsgen)…"
      dnsgen "$raw" 2>/dev/null > "$tmp/perms.txt" || true
    fi

    # Brute force with a wordlist, wildcard-filtered via puredns.
    if [[ "$PROFILE" == deep ]] && require_tool puredns "brute-force" \
       && [[ -s "$DNS_WORDLIST" ]]; then
      log_info "brute-forcing with $(basename "$DNS_WORDLIST")…"
      local resolver_flag=()
      [[ -s "$RESOLVERS" ]] && resolver_flag=(-r "$RESOLVERS")
      puredns bruteforce "$DNS_WORDLIST" "$TARGET" "${resolver_flag[@]}" \
        --wildcard-batch 100000 -q 2>/dev/null | anew -q "$tmp/brute.txt" >/dev/null || true
    fi

    absorb "$raw" "$tmp/perms.txt" "$tmp/brute.txt"
    log_result "after active enum → $(count "$raw") candidates"
  fi

  rm -rf "$tmp"

  # Keep only in-scope names (endswith target) — strips junk from CT logs etc.
  if [[ -s "$raw" ]]; then
    grep -E "(^|\.)$(printf '%s' "$TARGET" | sed 's/\./\\./g')\$" "$raw" \
      | sort -u -o "$raw" || true
  fi

  log_ok "Subdomains collected: $(count "$raw")"
}
