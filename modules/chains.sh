#!/usr/bin/env bash
#
# modules/chains.sh — correlate findings into high-impact attack chains.
#
# A lone bug is often low value. The same bug combined with another is a critical
# report. This stage reads everything Reconta found and looks for combinations
# that add up to real impact — account takeover, cloud-credential theft, data
# disclosure — the kind of chained reasoning that separates a $50 report from a
# $5,000 one and that scanners miss because they test bugs in isolation.
#
# It is pure correlation and reporting. It does not send traffic or exploit
# anything; each chain lists the evidence, the impact, and the manual steps to
# confirm it. You verify and submit.
#
# Inputs : vulns.txt, secrets.txt, interesting.txt, urls.txt, osint.txt, techstack.txt
# Output : $OUTDIR/chains.txt   (ranked attack-chain narratives)

module_chains() {
  [[ "${ENABLE_CHAINS:-1}" == 1 ]] || { log_info "chains: disabled"; return 0; }
  log_step "Attack-chain correlation"
  local V="$OUTDIR/vulns.txt" U="$OUTDIR/urls.txt" I="$OUTDIR/interesting.txt"
  local S="$OUTDIR/secrets.txt" O="$OUTDIR/osint.txt"
  local out="$OUTDIR/chains.txt"; : > "$out"
  local n=0

  # --- small predicates / evidence helpers (grep-based, read-only) -----------
  _cv()  { grep -qiE "$1" "$V" 2>/dev/null; }             # vuln present?
  _cu()  { grep -qiE "$1" "$U" 2>/dev/null; }             # url present?
  _ci()  { grep -qiE "$1" "$I" 2>/dev/null; }             # interesting tag present?
  _co()  { grep -qiE "$1" "$O" 2>/dev/null; }             # osint match?
  _evv() { grep -iE "$1" "$V" 2>/dev/null | head -1; }
  _evu() { grep -iE "$1" "$U" 2>/dev/null | head -1; }
  _evi() { grep -iE "$1" "$I" 2>/dev/null | head -1; }

  # emit <severity> <name> <impact> <verify> ; components passed via $CHAIN_EV
  _chain() {
    n=$((n+1))
    {
      printf '## [%s] CHAIN %d: %s\n' "$1" "$n" "$2"
      printf 'Components:\n%s\n' "$CHAIN_EV"
      printf 'Impact : %s\n' "$3"
      printf 'Verify : %s\n\n' "$4"
    } >> "$out"
    CHAIN_EV=""
  }

  {
    echo "# Reconta attack chains for $TARGET"
    echo "# Generated $(date -u +%FT%TZ)"
    echo "# Combinations of findings that add up to real impact. Correlation only —"
    echo "# confirm each chain manually and stay within the program scope."
    echo
  } >> "$out"

  # --- Chain 1: open redirect on an OAuth/SSO flow -> account takeover -------
  if _cv 'open-redirect' && _cu '(oauth|/authorize|/sso|/saml|redirect_uri|/callback|openid)'; then
    CHAIN_EV="  - open redirect: $(_evv 'open-redirect' | sed 's/.*— //')
  - auth flow endpoint: $(_evu '(oauth|/authorize|/sso|/saml|redirect_uri|/callback|openid)')"
    _chain critical "OAuth token theft via open redirect" \
      "Redirect on the OAuth/SSO flow can leak the auth code/token to an attacker host, leading to account takeover." \
      "Set the redirect/redirect_uri param to your host in the auth flow and check whether the code/token is delivered to it."
  fi

  # --- Chain 2: reflected-origin CORS on an authenticated API -> data theft --
  if _cv 'cors-misconfig' && _cu '(/api/|/me\b|/account|/user|/profile|/graphql)'; then
    CHAIN_EV="  - CORS misconfig: $(_evv 'cors-misconfig' | sed 's/.*— //')
  - authenticated endpoint: $(_evu '(/api/|/me\b|/account|/user|/profile|/graphql)')"
    _chain high "Cross-origin theft of authenticated data" \
      "A malicious origin can read authenticated responses (personal data, tokens) via the reflected-origin CORS policy." \
      "From a page on an arbitrary origin, fetch the endpoint with credentials and confirm the response is readable."
  fi

  # --- Chain 3: leaked secret + API surface -> authenticated access ----------
  if [[ -s "$S" ]] && { _cu '(/api/|/graphql|/v[0-9]+/)' || _ci 'api-endpoint'; }; then
    CHAIN_EV="  - leaked secret/key: $(head -1 "$S")
  - API surface: $(_evu '(/api/|/graphql|/v[0-9]+/)')"
    _chain high "Leaked key unlocks the API" \
      "A leaked key/token used against the discovered API can grant authenticated access to data or actions." \
      "Validate the key read-only against the vendor's token-info endpoint; do NOT access target data on a bounty."
  fi

  # --- Chain 4: SSRF + cloud hosting -> metadata/credential theft ------------
  if _cv '(ssrf|dast.*ssrf)' && { _co '(amazonaws|aws|google|gcp|azure|digitalocean|cloud)' || _ci 'cloud-storage'; }; then
    CHAIN_EV="  - SSRF: $(_evv '(ssrf|dast.*ssrf)' | sed 's/.*— //')
  - cloud hosting: $(_evi 'cloud-storage' || echo 'cloud provider in osint.txt')"
    _chain critical "SSRF to cloud metadata credentials" \
      "SSRF on cloud infrastructure can reach the metadata service (169.254.169.254) and expose IAM credentials." \
      "Point the SSRF at the metadata endpoint via your interactsh/OOB host and confirm a callback; do not use any creds returned."
  fi

  # --- Chain 5: source/secret exposure (.git/.env) -> credential access ------
  if _ci '(sensitive-file|vcs-exposed)'; then
    CHAIN_EV="  - exposed source/config: $(_evi '(sensitive-file|vcs-exposed)')"
    _chain high "Source/config disclosure -> credentials" \
      "Exposed .git/.env/backup files often contain DB strings, API keys, and internal endpoints that unlock deeper access." \
      "Download the exposed file read-only and review it for credentials and internal hosts; report without using the creds."
  fi

  # --- Chain 6: XSS + auth surface -> session/account takeover ---------------
  if _cv '(\bxss\b|xss:)' && { _cu '(/login|/admin|/account|/dashboard)' || _ci 'admin-auth'; }; then
    CHAIN_EV="  - XSS: $(_evv '(\bxss\b|xss:)' | sed 's/.*— //')
  - auth surface: $(_evu '(/login|/admin|/account|/dashboard)' || _evi 'admin-auth')"
    _chain high "XSS to session/account takeover" \
      "XSS on an authenticated area can steal session cookies or perform actions as the victim (including admins)." \
      "Confirm the payload executes in an authenticated context and can read document.cookie or trigger a state change."
  fi

  # --- Chain 7: subdomain takeover -> cookie/phishing on the parent brand ----
  if _cv 'takeover'; then
    CHAIN_EV="  - subdomain takeover: $(_evv 'takeover' | sed 's/.*— //; s/.*VULNERABLE//I')"
    _chain high "Subdomain takeover -> trusted phishing / cookie scope" \
      "Controlling a subdomain lets you serve content on the target's brand and, if cookies are scoped to the parent domain, capture sessions." \
      "Claim the dangling resource per the provider, host a proof page, and check for parent-domain cookie scope."
  fi

  # --- Chain 8: SQLi -> data access / auth bypass ----------------------------
  if _cv '(sqli|sql.injection)'; then
    CHAIN_EV="  - SQL injection: $(_evv '(sqli|sql.injection)' | sed 's/.*— //')"
    _chain critical "SQL injection -> data access / auth bypass" \
      "Injection can read database contents or bypass authentication." \
      "Prove with a boolean/time-based check only (e.g. AND 1=1 vs 1=2). Do NOT dump data on a bounty."
  fi

  # --- Chain 9: exposed admin panel + default-login finding -> admin access --
  if { _ci 'admin-auth' || _cu '/admin'; } && _cv '(default-login|default.credential|weak.password)'; then
    CHAIN_EV="  - admin panel: $(_evi 'admin-auth' || _evu '/admin')
  - default/weak login: $(_evv '(default-login|default.credential|weak.password)' | sed 's/.*— //')"
    _chain critical "Admin panel with default credentials" \
      "An exposed admin interface accepting default credentials gives full administrative control." \
      "Log in once to confirm access, capture a screenshot as proof, and stop — do not change anything."
  fi

  # --- rank by severity, keep worst first ------------------------------------
  if [[ "$n" -gt 0 ]]; then
    # Re-order the chain blocks by severity using a temp split on the header.
    awk 'BEGIN{RS="\n\n"; ORS="\n\n"} /^## \[critical\]/' "$out" >  "$out.s"
    awk 'BEGIN{RS="\n\n"; ORS="\n\n"} /^## \[high\]/'     "$out" >> "$out.s"
    awk 'BEGIN{RS="\n\n"; ORS="\n\n"} /^## \[medium\]/'   "$out" >> "$out.s"
    # Preserve the intro comment block (lines starting "# ", not the "## " chain
    # headers) at the very top, then the severity-sorted chain blocks.
    { grep '^# ' "$out"; echo; cat "$out.s"; } > "$out.final" 2>/dev/null
    mv "$out.final" "$out"; rm -f "$out.s"
  fi

  export CHAINS_COUNT="$n"
  if [[ "$n" -gt 0 ]]; then
    log_ok "Attack chains identified: $n -> chains.txt"
  else
    log_ok "No multi-finding chains detected this run"
  fi
}
