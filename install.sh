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
  sudo apt-get update -qq
  sudo apt-get install -y -qq \
    jq curl whois nmap masscan python3-pip pipx git libpcap-dev \
    cewl poppler-utils >/dev/null \
    && log_ok "system packages installed" \
    || log_warn "some apt packages failed — continuing"
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
  for spec in "uro" "arjun" "paramspider@git+https://github.com/devanshbatham/paramspider" \
              "theHarvester"; do
    name="${spec%@*}"
    if command -v "$name" >/dev/null 2>&1; then
      log_info "already installed: $name"
    else
      printf '  installing %-14s… ' "$name"
      if pipx install "${spec/@git/ git}" >/dev/null 2>&1 || pipx install "$name" >/dev/null 2>&1; then
        echo "${C_GREEN}ok${C_RESET}"
      else
        echo "${C_YELLOW}skip (install manually)${C_RESET}"
      fi
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
