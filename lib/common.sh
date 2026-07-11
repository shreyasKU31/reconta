#!/usr/bin/env bash
#
# lib/common.sh — shared helpers, logging, tool detection.
# Sourced by reconta.sh and every module. Not meant to run standalone.

# ---------------------------------------------------------------------------
# Colors (disabled automatically when output is not a TTY or NO_COLOR is set)
# ---------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""
  C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_ts() { date +"%H:%M:%S"; }

log_info()  { printf "%s[%s]%s %s\n"  "$C_DIM" "$(_ts)" "$C_RESET" "$*"; }
log_step()  { printf "\n%s[%s] ▸ %s%s\n" "$C_CYAN$C_BOLD" "$(_ts)" "$*" "$C_RESET"; }
log_ok()    { printf "%s[%s] ✓%s %s\n"  "$C_GREEN" "$(_ts)" "$C_RESET" "$*"; }
log_warn()  { printf "%s[%s] !%s %s\n"  "$C_YELLOW" "$(_ts)" "$C_RESET" "$*" >&2; }
log_err()   { printf "%s[%s] ✗%s %s\n"  "$C_RED" "$(_ts)" "$C_RESET" "$*" >&2; }
log_result(){ printf "%s      └─ %s%s\n" "$C_DIM" "$*" "$C_RESET"; }

# ---------------------------------------------------------------------------
# Tool detection — modules call have_tool to skip gracefully when a binary
# is missing instead of crashing the whole run.
# ---------------------------------------------------------------------------
declare -A _MISSING_TOOLS=()

have_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    return 0
  fi
  _MISSING_TOOLS["$1"]=1
  return 1
}

# require_tool <bin> <stage-name> : returns 1 and warns if the tool is absent.
require_tool() {
  if have_tool "$1"; then
    return 0
  fi
  log_warn "'$1' not found — skipping ${2:-this step}. (run install.sh)"
  return 1
}

# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------
# count <file> : number of non-empty lines, 0 if the file is absent.
count() {
  [[ -s "$1" ]] && grep -cve '^[[:space:]]*$' "$1" || echo 0
}

# count_re <regex> <file> : lines matching regex, 0 if none/absent.
# (grep -c prints 0 AND exits 1 on no match, so `|| echo 0` would double up —
# capturing into a var and defaulting avoids that.)
count_re() {
  local n; n=$(grep -ciE "$1" "$2" 2>/dev/null)
  echo "${n:-0}"
}

# ensure a file exists so downstream `< file` reads never explode.
touchf() { : > "$1"; }

# sort -u only the lines that are actually present; keep files tidy & unique.
uniq_sort() {
  [[ -s "$1" ]] || return 0
  LC_ALL=C sort -u "$1" -o "$1"
}

# Merge extra sources into a canonical file, deduped, using anew when present.
# usage: absorb <dest> <src...>
absorb() {
  local dest="$1"; shift
  local src
  for src in "$@"; do
    [[ -s "$src" ]] || continue
    if have_tool anew; then
      anew -q "$dest" < "$src"
    else
      cat "$src" >> "$dest"
    fi
  done
  uniq_sort "$dest"
}

# Run a command with a wall-clock timeout when `timeout` is available so a
# single hung tool can never stall the pipeline. Falls back to plain exec.
capped() {
  local secs="$1"; shift
  if have_tool timeout; then
    timeout --preserve-status "${secs}s" "$@"
  else
    "$@"
  fi
}

# elapsed <start_epoch> : human-readable duration since a recorded start.
elapsed() {
  local d=$(( $(date +%s) - $1 ))
  printf '%dm%02ds' $((d/60)) $((d%60))
}
