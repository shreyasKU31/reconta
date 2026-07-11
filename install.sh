#!/usr/bin/env bash
#
# install.sh — install every tool Reconta orchestrates.
# Targets Debian/Ubuntu/Kali + WSL. Installs Go tools via `go install`,
# Python tools via pipx, and a few system packages via apt.
#
#   ./install.sh              # install everything
#   ./install.sh --go-only    # only the Go-based tools
#
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

GO_ONLY=0
[[ "${1:-}" == "--go-only" ]] && GO_ONLY=1

# --- Prereqs ----------------------------------------------------------------
log_step "Checking prerequisites"
if ! have_tool go; then
  log_err "Go is required. Install from https://go.dev/dl/ then re-run."
  log_info "  (Debian/Kali quick path: sudo apt install -y golang-go)"
  exit 1
fi
export PATH="$PATH:$(go env GOPATH)/bin"
log_ok "Go found: $(go version | awk '{print $3}')"

# --- System packages --------------------------------------------------------
if [[ "$GO_ONLY" == 0 ]] && have_tool apt-get; then
  log_step "Installing system packages (sudo)"

  # Run apt fully non-interactively. On Kali, upgrading libc6 pulls in the
  # 'needrestart' prompt ("restart services?"), which hangs forever when apt
  # output is hidden. These env vars auto-answer it so the install never stalls.
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1

  # If a previous run was interrupted, dpkg can be left half-configured and
  # every later install fails. Repair that state before doing anything else.
  log_info "checking for and repairing any interrupted package state…"
  sudo dpkg --configure -a 2>/dev/null || true

  log_info "updating apt package lists…"
  if ! sudo apt-get update -o Acquire::Retries=3; then
    log_warn "apt-get update failed — check your network/mirrors, then re-run"
  fi

  # Install one package at a time. This way a single unavailable or broken
  # package can't stop the others, and you can see exactly which one failed.
  apt_pkgs="jq curl whois nmap masscan python3-pip pipx git libpcap-dev cewl poppler-utils"
  apt_failed=""
  for p in $apt_pkgs; do
    printf '  %-16s ' "$p"
    if dpkg -s "$p" >/dev/null 2>&1; then
      echo "${C_DIM}already installed${C_RESET}"
      continue
    fi
    if apt_out=$(sudo apt-get install -y --no-install-recommends "$p" 2>&1); then
      echo "${C_GREEN}ok${C_RESET}"
    else
      echo "${C_RED}failed${C_RESET}"
      echo "$apt_out" | tail -3 | sed 's/^/      /'
      apt_failed="$apt_failed $p"
    fi
  done
  if [[ -n "$apt_failed" ]]; then
    log_warn "apt packages that failed:$apt_failed"
    log_warn "if it says 'held by process' — kill that apt/dpkg PID, then re-run"
    log_warn "if it says 'unmet dependencies' — finish the system upgrade first:"
    log_warn "    sudo apt-get update && sudo apt-get full-upgrade -y"
    log_warn "then:  sudo apt-get install -y$apt_failed"
  else
    log_ok "system packages installed"
  fi
  pipx ensurepath >/dev/null 2>&1 || true
fi

# --- Go tools (ProjectDiscovery + tomnomnom + others) -----------------------
log_step "Installing Go tools"
declare -A GO_TOOLS=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [asnmap]="github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  [notify]="github.com/projectdiscovery/notify/cmd/notify@latest"
  [alterx]="github.com/projectdiscovery/alterx/cmd/alterx@latest"
  [assetfinder]="github.com/tomnomnom/assetfinder@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls@latest"
  [anew]="github.com/tomnomnom/anew@latest"
  [gau]="github.com/lc/gau/v2/cmd/gau@latest"
  [subjs]="github.com/lc/subjs@latest"
  [amass]="github.com/owasp-amass/amass/v4/...@master"
  [puredns]="github.com/d3mondev/puredns/v2@latest"
  [subzy]="github.com/PentestPad/subzy@latest"
  [gowitness]="github.com/sensepost/gowitness@latest"
  [ffuf]="github.com/ffuf/ffuf/v2@latest"
  [gobuster]="github.com/OJ/gobuster/v3@latest"
)
for bin in "${!GO_TOOLS[@]}"; do
  if command -v "$bin" >/dev/null 2>&1; then
    log_info "already installed: $bin"
  else
    printf '  installing %-14s… ' "$bin"
    if go install -v "${GO_TOOLS[$bin]}" >/dev/null 2>&1; then
      echo "${C_GREEN}ok${C_RESET}"
    else
      echo "${C_RED}failed${C_RESET}"
    fi
  fi
done

# --- Python tools -----------------------------------------------------------
if [[ "$GO_ONLY" == 0 ]]; then
  log_step "Installing Python tools (pipx)"
  # name -> pipx install spec. paramspider is git-only (not on PyPI), so it
  # needs the full VCS URL; installing the bare name would fail.
  declare -A PY_TOOLS=(
    [uro]="uro"
    [arjun]="arjun"
    [paramspider]="git+https://github.com/devanshbatham/paramspider.git"
    [theHarvester]="theHarvester"
  )
  for name in uro arjun paramspider theHarvester; do
    if command -v "$name" >/dev/null 2>&1; then
      log_info "already installed: $name"
      continue
    fi
    printf '  installing %-14s… ' "$name"
    if py_out=$(pipx install "${PY_TOOLS[$name]}" 2>&1); then
      echo "${C_GREEN}ok${C_RESET}"
    else
      echo "${C_RED}failed${C_RESET}"
      echo "$py_out" | tail -2 | sed 's/^/      /'
    fi
  done

  # trufflehog via official script
  if ! have_tool trufflehog; then
    log_info "installing trufflehog…"
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
      | sh -s -- -b "$(go env GOPATH)/bin" >/dev/null 2>&1 \
      && log_ok "trufflehog installed" || log_warn "trufflehog manual install needed"
  fi
fi

# --- Resolvers list ---------------------------------------------------------
log_step "Setting up resolvers"
mkdir -p "$HOME/.config/reconta"
if [[ ! -s "$HOME/.config/reconta/resolvers.txt" ]]; then
  curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    -o "$HOME/.config/reconta/resolvers.txt" 2>/dev/null \
    && log_ok "resolvers saved to ~/.config/reconta/resolvers.txt" \
    || log_warn "couldn't fetch resolvers — set RESOLVERS in config manually"
fi

log_step "Install complete"
log_info "Verify with:  ./reconta.sh --list-tools"
log_info "Add PATH line to your shell rc if tools aren't found:"
echo '    export PATH="$PATH:$(go env GOPATH)/bin"'
