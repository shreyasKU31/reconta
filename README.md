<h1 align="center">Reconta</h1>
<p align="center"><b>Recon + Data</b> — one command, full recon &amp; OSINT, aggressively de-noised.</p>

<p align="center">
  <img alt="CI" src="https://github.com/<you>/reconta/actions/workflows/ci.yml/badge.svg">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-blue">
  <img alt="shell" src="https://img.shields.io/badge/bash-5%2B-green">
  <img alt="platform" src="https://img.shields.io/badge/platform-Kali%20%7C%20Linux%20%7C%20WSL%20%7C%20macOS-lightgrey">
  <img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen">
</p>

---

Reconta chains the best passive & active reconnaissance tools into a single
pipeline and — this is the point — **throws away the noise at every hop**. Dead
DNS names, unreachable hosts, near-duplicate URLs, unverified secrets: gone. What
lands in your output directory is the stuff actually worth looking at, plus one
consolidated report.

```bash
./reconta.sh example.com
```

That's it. Reconta discovers subdomains, resolves and probes them, maps ports and
services, harvests URLs and JavaScript, mines parameters and secrets, gathers
infrastructure OSINT, scans for low-hanging vulnerabilities, and writes an
HTML + Markdown report.

## What makes Reconta different

Most recon frameworks are tool-runners: they fire off 30 tools and hand you a
directory of giant text files. The hard part — *which of these 10,000 URLs
matter, and what's new since last week* — is left to you. Reconta does that part.

- **🎯 It prioritizes for you.** Every URL is scored against a curated
  [signature knowledge base](config/signatures.txt) and every live host is
  scored on status/tech/title/port. The output — **`interesting.txt`** — is a
  ranked "start here" list: `.git/config` and staging Swagger at the top, static
  images filtered out. You stop triaging and start hunting.

  ```
  [ 185] sensitive-file,vcs-exposed   https://target.com/.git/config
  [ 137] api-docs,non-prod-host       https://staging.target.com/swagger-ui.html
  [ 120] admin-auth,non-prod-host     https://dev.target.com/admin/login
  [  85] secret-param                 https://cdn.target.com/app.js?apikey=AKIA…
  [  72] redirect-ssrf-param          https://target.com/go?redirect=…
  ```

- **⚡ It detects change.** Reconta snapshots every run per target. On the next
  run it shows **only what's new** — `new.txt` lists the fresh subdomains, hosts,
  endpoints, and vulns nobody has looked at yet. Run it on a cron with
  `--monitor` and get pinged the moment a target ships a new asset. *That* is
  where bounties are won.

- **🔌 It's pipeline-ready.** `report.json` gives every count and the top ranked
  findings in machine-readable form, so Reconta drops into your own automation.

- **🧠 The knowledge base is the product.** `config/signatures.txt` is an open,
  weighted, extensible pattern DB (secret params, SSRF/redirect params, LFI,
  exposed panels, VCS leaks, non-prod hosts…). Tune weights to your targets; add
  your own patterns. Everyone's recon gets smarter.

## Also

- **Signal, not noise.** Every stage feeds the *filtered* output of the previous
  one forward. `dnsx` drops names that don't resolve, `httpx` drops hosts that
  aren't live, `uro` collapses parametric duplicate URLs, `trufflehog` reports
  only *verified* secrets, and `nuclei` skips `info` severity by default.
- **Broad-topic output only.** No sprawl of a hundred tiny files — one file per
  topic at the top level; everything raw is tucked into `.raw/`.
- **Fast by design.** Independent stages (OSINT, ports, URLs) run concurrently;
  every external tool is wall-clock-capped so one hang can't stall the run.
- **Graceful degradation.** Missing a tool? Reconta warns and skips that step
  instead of dying. Run what you have; install the rest later.
- **Three profiles.** `quick` (passive, seconds–minutes), `normal` (recommended),
  `deep` (brute force + full port scan + deep crawl).

## The pipeline

```
 subdomains ─▶ resolve (DNS + HTTP liveness = noise filter) ─┬─▶ ports (naabu → nmap)
                                                             ├─▶ urls (gau/wayback/katana → uro → httpx)
                                                             │      └─▶ javascript (secrets) ─▶ params
                                                             └─▶ osint (asnmap/whois/theHarvester)
                                                                    ▼
                                                        vulns (nuclei + subzy)
                                                                    ▼
                          analyze (score & rank → interesting.txt) ─▶ diff (change → new.txt) ─▶ report
```

## Output layout

```
output/example.com/
├── interesting.txt  # ★ ranked "start here" findings — read this first
├── new.txt          # ⚡ what's new vs the previous run
├── subdomains.txt   # resolved, in-scope subdomains
├── hosts.txt        # live HTTP/S hosts (URLs)
├── ports.txt        # open host:port → service/version
├── urls.txt         # de-noised, live URLs
├── params.txt       # URLs / endpoints carrying parameters
├── js.txt           # live JavaScript files
├── secrets.txt      # ⚠ potential leaked secrets/keys
├── osint.txt        # ASN, WHOIS, DNS, emails, favicon hash
├── vulns.txt        # nuclei + takeover findings (severity-sorted)
├── report.html      # ← open this (dashboard + priority findings)
├── report.md
├── report.json      # machine-readable summary for automation
└── .raw/            # every intermediate artifact, per stage
```

## Install

### Kali Linux (recommended) — quick start

Kali already ships `nmap`, `whois`, `jq`, and Go. From a terminal:

```bash
# 1. Get the code
git clone https://github.com/<you>/reconta.git
cd reconta

# 2. Install the toolchain (Go + Python + system deps) and a resolvers list
chmod +x reconta.sh install.sh
./install.sh

# 3. Make sure Go's tool bin is on your PATH (once)
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc && source ~/.zshrc

# 4. Verify, then run
./reconta.sh --list-tools
./reconta.sh example.com -p quick
```

> On Kali the default shell is **zsh** (use `~/.zshrc`). On Ubuntu/WSL it's
> **bash** (use `~/.bashrc`). If Go isn't installed: `sudo apt install -y golang-go`.

### Install globally (run `reconta` from anywhere)

```bash
sudo make install          # copies to /opt/reconta, links /usr/local/bin/reconta
reconta example.com -p normal
```

### Docker (zero host setup)

```bash
make docker-build
docker run --rm -v "$PWD/loot:/opt/reconta/output" reconta example.com -p normal
# results appear in ./loot
```

Requires **Go 1.21+** for the native install (plus Python 3 + apt for the full
tool set). Reconta runs with whatever subset of tools you have — missing ones
are skipped with a warning.

### Tools orchestrated

`subfinder` · `amass` · `assetfinder` · `crt.sh` · `findomain` · `puredns` ·
`alterx` · `dnsx` · `httpx` · `naabu` · `nmap` · `gau` · `waybackurls` ·
`katana` · `uro` · `subjs` · `trufflehog` · `mantra` · `arjun` · `paramspider` ·
`asnmap` · `theHarvester` · `whois` · `nuclei` · `subzy` · `anew` · `jq` ·
`notify` · `gowitness`

Reconta uses whatever subset you have installed.

## Usage

```bash
./reconta.sh example.com                 # normal profile
./reconta.sh example.com -p quick        # fast, passive only
./reconta.sh example.com -p deep -o ~/loot
./reconta.sh example.com --no-ports --no-vulns
./reconta.sh --list-tools
```

| Flag | Meaning |
|---|---|
| `-o, --output DIR` | output base directory (default `./output`) |
| `-p, --profile P`  | `quick` \| `normal` \| `deep` |
| `-c, --config FILE`| alternate config file |
| `--no-ports`       | skip port scanning |
| `--no-vulns`       | skip nuclei / takeover stage |
| `--no-diff`        | skip change detection vs previous run |
| `-m, --monitor`    | push a `notify` alert when new assets appear |
| `--list-tools`     | show installed vs missing tools |

### Continuous monitoring

Because Reconta tracks state per target, running it on a schedule turns it into a
change-monitoring system — get alerted the moment a target exposes something new:

```bash
# cron: every day at 03:00, alert on anything new
0 3 * * *  /path/to/reconta.sh example.com -p quick --monitor
```

## Configuration

Everything lives in [`config/reconta.conf`](config/reconta.conf): thread counts,
rate limits, stage toggles, profile, wordlists, resolvers, and notifications.
API keys are **never** stored here — configure them in each tool's own config
(e.g. `~/.config/subfinder/provider-config.yaml`) or your environment.

Optional Telegram/Discord/Slack push of the final summary: set `NOTIFY=1` and
configure [`notify`](https://github.com/projectdiscovery/notify).

## Responsible use

> Reconta is for **authorized** security testing only — bug-bounty targets within
> scope, systems you own, or engagements you have written permission for. Active
> stages (brute force, port scans, crawling, nuclei) touch the target directly.
> You are responsible for staying within scope and within the law. The authors
> accept no liability for misuse.

Passive-only recon with `-p quick` is the least intrusive starting point.

## Contributing

Contributions are very welcome — especially new **signatures**, which make
everyone's triage sharper. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the dev
setup, coding standards, and how to add a signature, module, or tool.

- 🐛 Found a bug? [Open an issue](../../issues/new/choose).
- 💡 Have an idea? [Request a feature](../../issues/new/choose).
- 🔐 Security issue? See **[SECURITY.md](SECURITY.md)** (report privately).
- 🤝 Please read our [Code of Conduct](CODE_OF_CONDUCT.md).

Good first contributions: add a signature to `config/signatures.txt`, integrate a
new passive source, or improve the HTML report. Run `make test` before you push.

## Roadmap

- [ ] `report.json` diffing for CI-driven monitoring dashboards
- [ ] Optional `gowitness` screenshots embedded in the HTML report
- [ ] Per-program scope files (in/out-of-scope regex) applied across all stages
- [ ] Pluggable notifiers beyond `notify` (native Discord/Slack webhooks)
- [ ] Community signature packs (per-CMS, per-cloud)

## License

MIT — see [LICENSE](LICENSE). By contributing you agree your work is licensed
under the same terms.
