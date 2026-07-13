#!/usr/bin/env bash
#
# modules/verify.sh — turn confirmed findings into report-ready proof.
#
# For every finding in vulns.txt, this builds a SAFE, non-destructive
# reproduction: the exact payload/command that demonstrates the bug, a one-line
# impact statement, and a reminder to confirm before you submit. This is the
# real time-saver — it removes the manual triage and report-writing step so you
# can move on to the next target.
#
# It deliberately stops at proof-of-concept. It does not weaponize anything, does
# not gain access, and does not exfiltrate data — that is both what bug-bounty
# rules require and where responsible testing ends. Reproductions are read-only
# checks (reflection, headers, boolean PoC) that a human runs and verifies.
#
# Inputs : $OUTDIR/vulns.txt   (severity-tagged findings from vulns + fuzz)
# Output : $OUTDIR/poc.txt      (per-finding reproduction, report-ready)
#          $OUTDIR/exploitation-notes.txt  (optional, informational, opt-in)

module_verify() {
  [[ "${ENABLE_POC:-1}" == 1 ]] || { log_info "verify: disabled"; return 0; }
  log_step "Proof-of-concept & reproduction"
  local vulns="$OUTDIR/vulns.txt"
  local poc="$OUTDIR/poc.txt"; : > "$poc"

  if [[ ! -s "$vulns" ]]; then
    log_ok "No findings to reproduce yet"
    return 0
  fi

  {
    echo "# Reconta reproduction guide for $TARGET"
    echo "# Generated $(date -u +%FT%TZ)"
    echo "#"
    echo "# Each entry is a SAFE, non-destructive check that demonstrates the bug."
    echo "# Always run it yourself to confirm before submitting a report, and stay"
    echo "# within the program's scope and rules. Do not escalate beyond PoC."
    echo
  } >> "$poc"

  local line sev rest cat target repro impact n=0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    # Parse "[severity] category — target"
    case "$line" in
      \[*\]*) : ;;
      *) continue ;;
    esac
    sev="${line%%]*}"; sev="${sev#[}"
    rest="${line#*] }"
    cat="${rest%% — *}"
    target="${rest##* — }"
    n=$((n+1))

    case "$cat" in
      *xss*)
        impact="Executes attacker JS in a victim's session (session theft, actions as the user)."
        repro="curl -sk \"$target\"    # observe the injected payload reflected unescaped in the response" ;;
      open-redirect*)
        impact="Redirects users to an attacker site; aids phishing and OAuth token theft."
        repro="curl -skI \"$target\" | grep -i '^location:'    # Location should point to the injected host" ;;
      cors*)
        impact="A malicious origin can read authenticated responses (account-data disclosure)."
        repro="curl -skI -H 'Origin: https://evil.example' \"$target\" | grep -i 'access-control-'    # ACAO must NOT reflect evil.example with credentials:true" ;;
      *sqli*|*sql*)
        impact="Database access. Prove with a boolean/time check only — never dump data on a bounty."
        repro="sqlmap -u \"$target\" --batch --technique=B --flush-session    # boolean PoC only; do NOT use --dump / --os-shell on bug bounty" ;;
      *crlf*)
        impact="Header injection; can enable cache poisoning or response splitting."
        repro="curl -skiv \"$target\"    # confirm the injected CRLF (%0d%0a) reaches a response header" ;;
      dast:*|*dast*)
        impact="See the nuclei template name in vulns.txt for the exact class and matcher."
        repro="nuclei -u \"$target\" -id <template-id-from-vulns.txt>    # re-run the exact template to reproduce" ;;
      *takeover*)
        impact="Claim the dangling resource to serve content on the target's subdomain."
        repro="dig +short \"$target\" ; # then verify the dangling CNAME/service fingerprint and claim it manually per the provider" ;;
      *secret*)
        impact="Leaked credential/key. Validate scope/expiry read-only; never use it to access data."
        repro="# review the secret in secrets.txt; confirm it is live via the vendor's read-only token-info endpoint" ;;
      *)
        impact="Review the matched URL and the template/category in vulns.txt."
        repro="curl -sk \"$target\"" ;;
    esac

    {
      printf '## [%s] %s\n' "$sev" "$cat"
      printf 'Target : %s\n' "$target"
      printf 'Impact : %s\n' "$impact"
      printf 'Repro  : %s\n\n' "$repro"
    } >> "$poc"
  done < "$vulns"

  export POC_COUNT="$n"
  log_ok "Reproductions written for $n finding(s) -> poc.txt"

  # -- Optional, opt-in, INFORMATIONAL exploitation notes ---------------------
  # Off by default. This does NOT run anything. It maps detected CVEs/services to
  # things to review by hand in an authorized engagement — never auto-exploits.
  if [[ "${ENABLE_MSF_NOTES:-0}" == 1 ]]; then
    _write_exploitation_notes
  fi
}

# Informational only: suggests where to look manually. No execution, no payloads.
_write_exploitation_notes() {
  local notes="$OUTDIR/exploitation-notes.txt"
  {
    echo "# Manual exploitation notes for $TARGET (INFORMATIONAL)"
    echo "#"
    echo "# This file does NOT run anything. It lists detected CVEs and services so"
    echo "# you can research and, ONLY within an authorized engagement, verify them"
    echo "# by hand. Do not run exploits against bug-bounty targets — stop at PoC."
    echo
    if grep -oiE 'CVE-[0-9]{4}-[0-9]+' "$OUTDIR/vulns.txt" 2>/dev/null | sort -u | head -n1 >/dev/null; then
      echo "## Detected CVEs (research these)"
      grep -oiE 'CVE-[0-9]{4}-[0-9]+' "$OUTDIR/vulns.txt" 2>/dev/null | sort -u \
        | while read -r cve; do
            echo "  $cve   -> read the advisory; in an authorized lab you can 'search cve:$cve' in msfconsole"
          done
      echo
    fi
    if [[ -s "$OUTDIR/ports.txt" ]]; then
      echo "## Open services (map to the right advisory/version manually)"
      head -n 40 "$OUTDIR/ports.txt"
    fi
  } > "$notes"
  log_result "informational notes -> exploitation-notes.txt (review manually)"
}
