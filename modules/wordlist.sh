#!/usr/bin/env bash
#
# modules/wordlist.sh — build target-specific wordlists from collected data.
#
# This implements the OSINT -> extract -> generate -> clean -> use methodology.
# Generic wordlists (e.g. SecLists) are the same for every target; these are
# built from THIS target's own words, so they hit paths, usernames, and
# passwords that generic lists miss.
#
#   [1] OSINT gathering     already done by earlier stages (urls, tech, emails)
#   [2] Extract data        website words (CeWL), URL path tokens, PDF text,
#                           emails, technology and product names
#   [3] Generate wordlists  directories, usernames, passwords, subdomain words
#   [4] Clean & normalize    lowercase, drop junk, filter short, de-duplicate
#   [5] Use wordlists        optional ffuf discovery + a ready-to-run USAGE guide
#   [6] Discover resources   ffuf hits are merged back into urls.txt
#
# Inputs : $OUTDIR/{hosts,urls,subdomains,osint}.txt, $D_SUBS/httpx.jsonl
# Output : $OUTDIR/wordlists/{keywords,directories,usernames,passwords,
#                             subdomains,USAGE}.txt

# --- helpers ---------------------------------------------------------------

# clean_words <minlen> : stdin -> stdout, lowercased word-like tokens, junk and
# short/very-long tokens dropped, pure numbers removed, sorted unique.
_clean_words() {
  local minlen="${1:-3}"
  LC_ALL=C tr '[:upper:]' '[:lower:]' \
    | grep -oE '[a-z0-9][a-z0-9._-]{1,32}' \
    | awk -v m="$minlen" 'length($0)>=m && length($0)<=32' \
    | grep -vE '^[0-9._-]+$' \
    | LC_ALL=C sort -u
}

# _gen_usernames : stdin lines like "john doe" / "john.doe" / "jdoe" -> candidates
_gen_usernames() {
  awk '{
    line=tolower($0); gsub(/[._+-]/," ",line);
    n=split(line,a," ");
    f=a[1]; l=a[2];
    if(f!="") print f;
    if(l!="") print l;
    if(f!="" && l!=""){
      print f"."l; print f l; print substr(f,1,1) l; print f substr(l,1,1);
      print substr(f,1,1)"."l; print l"."f; print l f; print f"_"l;
    }
  }'
}

# _gen_passwords : stdin base words -> common human password patterns
_gen_passwords() {
  local years="$1"; local w cap y
  while IFS= read -r w; do
    [[ -n "$w" ]] || continue
    cap="$(tr '[:lower:]' '[:upper:]' <<<"${w:0:1}")${w:1}"
    printf '%s\n%s\n%s123\n%s@123\n%s!\n' "$w" "$cap" "$cap" "$cap" "$cap"
    for y in $years; do
      printf '%s%s\n%s%s!\n%s@%s\n' "$cap" "$y" "$cap" "$y" "$cap" "$y"
    done
  done
}

module_wordlist() {
  [[ "${ENABLE_WORDLIST:-1}" == 1 ]] || { log_info "wordlist: disabled"; return 0; }
  log_step "Custom wordlists (OSINT-driven)"

  local wl="$OUTDIR/wordlists"; mkdir -p "$wl" "$D_WORDLIST"
  local hosts="$OUTDIR/hosts.txt" urls="$OUTDIR/urls.txt"
  local jsonl="$D_SUBS/httpx.jsonl" osint="$OUTDIR/osint.txt"
  local pool="$D_WORDLIST/pool.txt"; : > "$pool"
  local minlen="${WORDLIST_MINLEN:-3}"
  local years="${WORDLIST_YEARS:-2023 2024 2025 2026}"

  # ---- [2] Extract data --------------------------------------------------

  # Company / product seed: the apex label (e.g. "example" from example.com).
  local brand="${TARGET%%.*}"
  printf '%s\n' "$brand" >> "$pool"

  # Website words via CeWL (spiders the site and pulls its vocabulary).
  if have_tool cewl && [[ -s "$hosts" ]]; then
    log_info "harvesting site vocabulary (CeWL)..."
    local h
    while read -r h; do
      capped 120 cewl -d "${CEWL_DEPTH:-2}" -m "${CEWL_MIN:-4}" --lowercase \
        "$h" 2>/dev/null >> "$D_WORDLIST/cewl.txt" || true
    done < <(head -n 3 "$hosts")
    [[ -s "$D_WORDLIST/cewl.txt" ]] && cat "$D_WORDLIST/cewl.txt" >> "$pool"
    log_result "CeWL words: $(count "$D_WORDLIST/cewl.txt")"
  else
    have_tool cewl || log_warn "'cewl' not found - skipping site vocabulary"
  fi

  # Real path tokens from discovered URLs: these ARE directories the site uses.
  if [[ -s "$urls" ]]; then
    sed -E 's#^https?://[^/]+/?##; s#[?#].*$##' "$urls" \
      | tr '/._-' '\n' | _clean_words "$minlen" > "$D_WORDLIST/paths.txt"
    cat "$D_WORDLIST/paths.txt" >> "$pool"
    log_result "URL path tokens: $(count "$D_WORDLIST/paths.txt")"
  fi

  # Technology / product names from httpx fingerprints.
  if [[ -s "$jsonl" ]] && have_tool jq; then
    jq -r '(.tech // [])[]?, (.webserver // empty)' "$jsonl" 2>/dev/null \
      | _clean_words "$minlen" > "$D_WORDLIST/tech.txt"
    cat "$D_WORDLIST/tech.txt" >> "$pool"
  fi

  # PDF/document text: fetch a few public docs and extract their words.
  if [[ -s "$urls" ]]; then
    grep -iE '\.pdf(\?|$)' "$urls" 2>/dev/null | head -n 10 > "$D_WORDLIST/pdfs.txt" || true
    if [[ -s "$D_WORDLIST/pdfs.txt" ]] && have_tool curl; then
      log_info "extracting words from $(count "$D_WORDLIST/pdfs.txt") document(s)..."
      local u i=0
      while read -r u; do
        i=$((i+1))
        capped 30 curl -s -L --max-time 25 "$u" -o "$D_WORDLIST/doc$i.pdf" 2>/dev/null || continue
        if have_tool pdftotext; then
          pdftotext -q "$D_WORDLIST/doc$i.pdf" - 2>/dev/null
        else
          strings "$D_WORDLIST/doc$i.pdf" 2>/dev/null
        fi
      done < "$D_WORDLIST/pdfs.txt" | _clean_words "$minlen" > "$D_WORDLIST/pdfwords.txt"
      cat "$D_WORDLIST/pdfwords.txt" >> "$pool"
      rm -f "$D_WORDLIST"/doc*.pdf
      log_result "document words: $(count "$D_WORDLIST/pdfwords.txt")"
    fi
  fi

  # Subdomain labels are good keywords too (api, portal, vpn ...).
  if [[ -s "$OUTDIR/subdomains.txt" ]]; then
    sed -E "s#\.?${TARGET//./\\.}\$##" "$OUTDIR/subdomains.txt" \
      | tr '.' '\n' | _clean_words "$minlen" >> "$pool"
  fi

  # ---- [3+4] Generate + clean the keyword pool ---------------------------
  local keywords="$wl/keywords.txt"
  _clean_words "$minlen" < "$pool" > "$keywords"
  log_result "keyword pool: $(count "$keywords") words"

  # Directories: real path tokens + keywords + tech, cleaned & merged.
  local dirs="$wl/directories.txt"
  cat "$D_WORDLIST/paths.txt" "$keywords" "$D_WORDLIST/tech.txt" 2>/dev/null \
    | _clean_words "$minlen" > "$dirs"

  # Usernames: from email local-parts + any operator-supplied name seeds.
  local usernames="$wl/usernames.txt"
  {
    # emails found during OSINT -> local parts
    grep -hoE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$osint" 2>/dev/null \
      | cut -d@ -f1
    # optional seed file of "First Last" names the operator gathered manually
    local seed="${STATE_DIR:-$HOME/.config/reconta/state}/$TARGET/names.txt"
    [[ -s "$seed" ]] && cat "$seed"
  } | _gen_usernames | _clean_words 2 > "$usernames"

  # Passwords: brand/product + top keywords, expanded into common patterns.
  local passwords="$wl/passwords.txt"
  { printf '%s\n' "$brand"; head -n 150 "$keywords"; } \
    | _gen_passwords "$years" | awk 'length>=4 && length<=24' \
    | LC_ALL=C sort -u > "$passwords"

  # Subdomain words: keywords + common environment prefixes (for permutation).
  local subwords="$wl/subdomains.txt"
  { cat "$keywords"
    printf '%s\n' dev develop development staging stage stg test testing qa uat \
      preprod sandbox demo internal intranet corp api api-dev admin portal vpn \
      mail smtp webmail git gitlab jenkins jira grafana kibana status beta alpha \
      app apps auth sso login dashboard cdn static assets img media files backup \
      old legacy new mobile m ws service services gateway proxy
  } | _clean_words "$minlen" > "$subwords"

  # ---- [5] Optional ffuf discovery with the custom directory list --------
  if [[ "${WORDLIST_FFUF:-0}" == 1 || "$PROFILE" == deep ]] \
     && have_tool ffuf && [[ -s "$dirs" && -s "$hosts" ]]; then
    log_info "probing hidden resources with ffuf (custom list)..."
    local h found="$D_WORDLIST/ffuf.txt"; : > "$found"
    while read -r h; do
      capped 180 ffuf -u "${h%/}/FUZZ" -w "$dirs" \
        -mc 200,201,204,301,302,307,401,403 -ac -t "$THREADS" \
        -rate "$RATE_LIMIT" -s 2>/dev/null \
        | sed "s#^#${h%/}/#" >> "$found" || true
    done < <(head -n 10 "$hosts")
    if [[ -s "$found" ]]; then
      sort -u "$found" | anew -q "$OUTDIR/urls.txt" >/dev/null 2>&1 || true
      log_result "hidden resources found: $(count "$found") (merged into urls.txt)"
    fi
  fi

  # ---- [5] Ready-to-run usage guide --------------------------------------
  _write_wordlist_usage "$wl"

  local nd nu np ns
  nd=$(count "$dirs"); nu=$(count "$usernames"); np=$(count "$passwords"); ns=$(count "$subwords")
  export WL_DIRS="$nd" WL_USERS="$nu" WL_PASS="$np" WL_SUBS="$ns"
  log_ok "Wordlists: $nd dirs, $nu usernames, $np passwords, $ns subdomain words"
  log_result "usage examples: $wl/USAGE.txt"
}

# Write a target-specific cheat sheet showing how to use each wordlist.
_write_wordlist_usage() {
  local wl="$1"
  local host; host="$(head -n1 "$OUTDIR/hosts.txt" 2>/dev/null)"; host="${host:-https://$TARGET}"
  cat > "$wl/USAGE.txt" <<EOF
Reconta custom wordlists for $TARGET
Generated $(date -u +%FT%TZ)

These lists are built from the target's own data, so keep them alongside (not
instead of) generic lists like SecLists. Only use them against systems you are
authorized to test.

Files:
  keywords.txt      raw cleaned keyword pool (source for the others)
  directories.txt   content/endpoint discovery
  usernames.txt     login/user enumeration
  passwords.txt     password guessing (patterns from the target's own words)
  subdomains.txt    prefixes for subdomain permutation

--- Content discovery (directories.txt) ---
  ffuf -u $host/FUZZ -w directories.txt -mc 200,301,302,401,403 -ac
  gobuster dir -u $host -w directories.txt -k

--- Subdomain permutation (subdomains.txt) ---
  alterx -l subdomains.txt | dnsx -silent
  # or feed as a brute-force list:
  puredns bruteforce subdomains.txt $TARGET

--- Login / credential testing (usernames.txt + passwords.txt) ---
  # Only with explicit authorization. Example against an SSH service:
  hydra -L usernames.txt -P passwords.txt <target-ip> ssh
  # HTTP POST login form (adjust the failure string):
  hydra -L usernames.txt -P passwords.txt $TARGET http-post-form \\
    "/login:user=^USER^&pass=^PASS^:Invalid"
  # Burp Intruder: load usernames.txt and passwords.txt as payload sets.

--- Offline password cracking (passwords.txt) ---
  hashcat -a 0 -m <hash-mode> hashes.txt passwords.txt -r rules/best64.rule
  john --wordlist=passwords.txt --rules hashes.txt
EOF
}
