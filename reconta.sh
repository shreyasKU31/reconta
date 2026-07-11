#!/usr/bin/env bash
#
# reconta.sh — Reconta = Recon + Data
# One command, full passive+active recon & OSINT, aggressively de-noised,
# ending in a single consolidated report.
#
#   ./reconta.sh example.com
#   ./reconta.sh example.com -p deep -o ~/loot
#
# Reconta chains best-in-class tools and, at every hop, discards what doesn't
# resolve / isn't live / is a near-duplicate, so the final files hold signal.
#
# License: MIT.  Use ONLY against targets you are authorized to test.

set -uo pipefail   # note: NOT -e — recon tools legitimately return non-zero.

# --- Locate ourselves so it works from any CWD ------------------------------
RECONTA_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RECONTA_HOME
RECONTA_VERSION="1.0.0"

# --- Defaults (overridden by config, then flags) ----------------------------
TARGET=""
OUTBASE="$RECONTA_HOME/output"
CONFIG="$RECONTA_HOME/config/reconta.conf"
PROFILE_OVERRIDE=""

usage() {
  cat <<EOF
${C_BOLD:-}Reconta${C_RESET:-} — Recon + Data

Usage: reconta.sh <target-domain> [options]

Options:
  -o, --output DIR    Output base directory        (default: ./output)
  -p, --profile P     quick | normal | deep         (default: from config)
  -c, --config FILE   Config file                   (default: config/reconta.conf)
      --no-vulns      Skip the nuclei/takeover stage
      --no-ports      Skip port scanning
      --no-diff       Skip change detection vs previous run
  -m, --monitor       Notify (via 'notify') when new assets appear vs last run
      --list-tools    Show which tools are installed / missing, then exit
  -v, --version       Print version and exit
  -h, --help          This help

Profiles:
  quick   passive only — subs, live hosts, urls, critical/high nuclei. Fastest.
  normal  passive + light active, top-100 ports, standard nuclei. (recommended)
  deep    brute force, full port scan, deeper crawl/fuzz, all severities.

Example:
  ./reconta.sh example.com -p normal
EOF
}

# --- Source library + config so logging/colors exist for arg parsing --------
# shellcheck source=lib/common.sh
source "$RECONTA_HOME/lib/common.sh"

# --- Parse arguments --------------------------------------------------------
POS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)  OUTBASE="$2"; shift 2 ;;
    -p|--profile) PROFILE_OVERRIDE="$2"; shift 2 ;;
    -c|--config)  CONFIG="$2"; shift 2 ;;
    --no-vulns)   NO_VULNS=1; shift ;;
    --no-ports)   NO_PORTS=1; shift ;;
    --no-diff)    NO_DIFF=1; shift ;;
    -m|--monitor) MONITOR=1; shift ;;
    --list-tools) LIST_TOOLS=1; shift ;;
    -v|--version) echo "Reconta v$RECONTA_VERSION"; exit 0 ;;
    -h|--help)    usage; exit 0 ;;
    -*)           log_err "unknown option: $1"; usage; exit 1 ;;
    *)            POS+=("$1"); shift ;;
  esac
done
[[ ${#POS[@]} -gt 0 ]] && TARGET="${POS[0]}"

# --- Load config ------------------------------------------------------------
if [[ -f "$CONFIG" ]]; then
  # shellcheck source=config/reconta.conf
  source "$CONFIG"
else
  log_warn "config not found at $CONFIG — using built-in defaults"
fi
[[ -n "$PROFILE_OVERRIDE" ]] && PROFILE="$PROFILE_OVERRIDE"
[[ "${NO_VULNS:-0}" == 1 ]] && ENABLE_VULNS=0
[[ "${NO_PORTS:-0}" == 1 ]] && ENABLE_PORTS=0
[[ "${NO_DIFF:-0}" == 1 ]] && ENABLE_DIFF=0
[[ "${MONITOR:-0}" == 1 ]] && NOTIFY=1   # monitoring implies notify on new

# --- --list-tools mode ------------------------------------------------------
CORE_TOOLS=(subfinder assetfinder amass dnsx httpx naabu nmap gau waybackurls
            katana uro anew jq arjun paramspider asnmap theHarvester whois
            nuclei subzy trufflehog subjs curl)
if [[ "${LIST_TOOLS:-0}" == 1 ]]; then
  printf '%sReconta tool status%s\n\n' "$C_BOLD" "$C_RESET"
  for t in "${CORE_TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      printf '  %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$t"
    else
      printf '  %s✗%s %s\n' "$C_RED" "$C_RESET" "$t"
    fi
  done
  echo; echo "Install missing tools with: ./install.sh"
  exit 0
fi

# --- Validate target --------------------------------------------------------
if [[ -z "$TARGET" ]]; then
  log_err "no target supplied."
  usage; exit 1
fi
if ! [[ "$TARGET" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
  log_err "'$TARGET' doesn't look like a domain. Reconta takes a root/apex domain."
  exit 1
fi

# --- Banner -----------------------------------------------------------------
cat <<BANNER
${C_CYAN}${C_BOLD}
   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗████████╗ █████╗
   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗
   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║   ██║   ███████║
   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██║
   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝${C_RESET}
        ${C_DIM}Recon + Data — signal, not noise · v$RECONTA_VERSION${C_RESET}

  target : ${C_BOLD}$TARGET${C_RESET}
  profile: $PROFILE
BANNER

# --- Set up output layout ---------------------------------------------------
export TARGET PROFILE THREADS RESOLVER_THREADS RATE_LIMIT HTTP_TIMEOUT
export ENABLE_PASSIVE_SUBS ENABLE_ACTIVE_SUBS ENABLE_PORTS ENABLE_URLS \
       ENABLE_JS ENABLE_PARAMS ENABLE_OSINT ENABLE_VULNS ENABLE_SCREENSHOTS \
       ENABLE_ANALYZE ENABLE_DIFF ENABLE_JSON
export NAABU_TOP_PORTS NUCLEI_SEVERITY NUCLEI_RATE NOTIFY MONITOR
export DNS_WORDLIST RESOLVERS PERM_WORDLIST SIGNATURES STATE_DIR

OUTDIR="$OUTBASE/$TARGET"
export OUTDIR
mkdir -p "$OUTDIR"

# Working sub-directories for intermediate/raw data (kept out of the top level
# so the top level stays "broad topic files" only, as required).
export D_RAW="$OUTDIR/.raw"
export D_SUBS="$D_RAW/subdomains"  D_PORTS="$D_RAW/ports"  D_URLS="$D_RAW/urls"
export D_JS="$D_RAW/js"  D_PARAMS="$D_RAW/params"  D_OSINT="$D_RAW/osint"
export D_VULNS="$D_RAW/vulns"  D_ANALYZE="$D_RAW/analyze"
mkdir -p "$D_SUBS" "$D_PORTS" "$D_URLS" "$D_JS" "$D_PARAMS" "$D_OSINT" \
         "$D_VULNS" "$D_ANALYZE"

RUN_START=$(date +%s); export RUN_START

# Mirror all console output into a run log.
exec > >(tee -a "$OUTDIR/reconta.log") 2>&1

# --- Load modules -----------------------------------------------------------
for m in subdomains resolve osint ports urls javascript params vulns \
         analyze diff report; do
  # shellcheck source=/dev/null
  source "$RECONTA_HOME/modules/$m.sh"
done

# --- Pipeline ---------------------------------------------------------------
# Order matters: each stage consumes the filtered output of earlier stages.
#
#   subdomains ─▶ resolve (DNS+HTTP filter) ─┬─▶ ports
#                                            ├─▶ urls ─▶ javascript ─▶ params
#                                            └─▶ osint
#                                                 ▼
#                                               vulns ─▶ report
#
module_subdomains
module_resolve

# osint is independent of the live surface; run it in the background while the
# surface-dependent stages proceed, then wait before the report.
if [[ "$ENABLE_OSINT" == 1 ]]; then module_osint & OSINT_PID=$!; fi

# ports and urls both only need the resolved/live sets → run concurrently.
if [[ "$ENABLE_PORTS" == 1 ]]; then module_ports & PORTS_PID=$!; fi
module_urls          # runs in foreground; JS/params chain off its output
module_javascript
module_params

# Reconverge before vuln scanning + report.
[[ -n "${PORTS_PID:-}" ]] && wait "$PORTS_PID" 2>/dev/null || true
[[ -n "${OSINT_PID:-}" ]] && wait "$OSINT_PID" 2>/dev/null || true

module_vulns

# Post-processing: extract signal, detect change, then report.
module_analyze   # score & rank everything → interesting.txt
module_diff      # compare against previous run → new.txt
module_report

# --- Wrap up ----------------------------------------------------------------
log_step "Done in $(elapsed "$RUN_START")"
if [[ ${#_MISSING_TOOLS[@]} -gt 0 ]]; then
  log_warn "some tools were missing (results reduced): ${!_MISSING_TOOLS[*]}"
  log_warn "run ./install.sh to get full coverage."
fi
printf '\n%s  Open your report:%s %s\n' "$C_GREEN$C_BOLD" "$C_RESET" "$OUTDIR/report.html"
printf '%s  Start hunting at:%s %s\n\n' "$C_GREEN$C_BOLD" "$C_RESET" "$OUTDIR/interesting.txt"
