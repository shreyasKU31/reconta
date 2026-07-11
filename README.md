<h1 align="center">Reconta</h1>
<p align="center">Recon + Data. One command runs a full reconnaissance and OSINT sweep, removes the noise, and hands you a ranked list of what to look at.</p>

<p align="center">
  <img alt="CI" src="https://github.com/shreyasKU31/reconta/actions/workflows/ci.yml/badge.svg">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-blue">
  <img alt="shell" src="https://img.shields.io/badge/bash-5%2B-green">
  <img alt="platform" src="https://img.shields.io/badge/platform-Kali%20%7C%20Linux%20%7C%20WSL%20%7C%20macOS-lightgrey">
  <img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen">
</p>

---

Reconta connects the best passive and active reconnaissance tools into one
pipeline. At each step it drops the results that do not matter: names that do not
resolve, hosts that are not live, duplicate URLs, and unverified secrets. What
you are left with is a clean dataset and a single report.

```bash
./reconta.sh example.com
```

From that one command, Reconta finds subdomains, checks which ones are live,
scans ports and services, collects URLs and JavaScript, looks for secrets and
parameters, gathers OSINT about the target's infrastructure, checks for common
vulnerabilities, and writes a report in HTML, Markdown, and JSON.

## Why Reconta is different

Most recon frameworks run a lot of tools and leave you with a folder full of huge
text files. The hard part is still yours: deciding which of ten thousand URLs are
worth your time, and noticing what has changed since last week. Reconta does that
part for you.

**It ranks the results.** Every URL is checked against a list of known-interesting
patterns, and every live host is scored on its status code, technology, title,
and port. The output, `interesting.txt`, is a sorted "start here" list. Exposed
`.git` folders and staging panels rise to the top; static images and plain pages
are filtered out.

```
[ 185] sensitive-file,vcs-exposed   https://target.com/.git/config
[ 137] api-docs,non-prod-host       https://staging.target.com/swagger-ui.html
[ 120] admin-auth,non-prod-host     https://dev.target.com/admin/login
[  85] secret-param                 https://cdn.target.com/app.js?apikey=AKIA...
[  72] redirect-ssrf-param          https://target.com/go?redirect=...
```

**It tracks changes.** Reconta saves a snapshot after every run. The next time you
scan the same target, `new.txt` lists only what is new: fresh subdomains, hosts,
endpoints, and findings. Run it on a schedule with `--monitor` and it will alert
you when a target puts something new online. New assets are often the ones nobody
else has looked at yet.

**It fits into automation.** `report.json` holds every count and the top-ranked
findings in a machine-readable form, so you can feed Reconta's output into your
own scripts and dashboards.

**The pattern list is open and editable.** `config/signatures.txt` is a plain,
weighted list of patterns for secrets, risky parameters, exposed services, and
non-production hosts. You can adjust the weights or add your own patterns, and
your changes improve every future scan.

## How it works

Each stage uses the cleaned output of the stage before it, so noise is removed as
early as possible.

```
subdomains -> resolve (keep only names that resolve and hosts that are live)
                |-> ports    (naabu, then nmap for service and version detail)
                |-> urls     (gau, waybackurls, katana; uro removes duplicates; httpx keeps live URLs)
                |     |-> javascript (find JS files and scan them for secrets) -> params
                |-> osint    (asnmap, whois, theHarvester)
                            |
                    wordlist (build target-specific lists from the data above)
                            |
                          vulns (nuclei, subzy)
                            |
             analyze (score and rank) -> diff (find what is new) -> report
```

## Output files

Reconta keeps the top level simple: one file per topic. All the raw, intermediate
data is stored under `.raw/`.

```
output/example.com/
  interesting.txt   Ranked findings. Read this first.
  new.txt           What is new compared to the previous run.
  subdomains.txt    Subdomains that resolve.
  hosts.txt         Live web hosts.
  ports.txt         Open ports and detected services.
  urls.txt          Cleaned, de-duplicated URLs.
  params.txt        URLs and endpoints that take parameters.
  js.txt            Live JavaScript files.
  secrets.txt       Possible leaked secrets and keys. Review by hand.
  osint.txt         ASN, WHOIS, DNS records, emails, favicon hash.
  vulns.txt         Findings from nuclei and takeover checks.
  report.html       A dashboard you can open in a browser.
  report.md         The same report in Markdown.
  report.json       A machine-readable summary.
  wordlists/        Target-specific wordlists (see below).
  .raw/             Every intermediate file, grouped by stage.
```

## Custom wordlists

Generic wordlists like SecLists are the same for every target. Reconta also
builds wordlists from the target's own data, so they contain words that generic
lists miss. This follows a simple flow: gather OSINT, extract the words, generate
lists, clean them, and hand them to your tools.

- **Extract.** Reconta pulls words from the site's own pages (CeWL), the real
  path names in the URLs it found, the technologies it fingerprinted, any public
  PDF documents, and the email addresses from OSINT.
- **Generate.** From those words it builds four lists: `directories.txt` for
  content discovery, `usernames.txt` from email names and employee names,
  `passwords.txt` from the target's words expanded into common patterns, and
  `subdomains.txt` for permutation.
- **Clean.** Everything is lowercased, stripped of junk, filtered by length, and
  de-duplicated.
- **Use.** Each run writes `wordlists/USAGE.txt` with ready-to-run commands for
  ffuf, gobuster, hydra, hashcat, and john. In the `deep` profile (or with
  `WORDLIST_FFUF=1`), Reconta also runs ffuf with the directory list and merges
  any hidden resources it finds back into `urls.txt`.

```
output/example.com/wordlists/
  keywords.txt      the cleaned word pool everything else is built from
  directories.txt   content and endpoint discovery (ffuf, gobuster)
  usernames.txt     login and user enumeration (hydra, Burp Intruder)
  passwords.txt     password guessing (hydra, hashcat, john)
  subdomains.txt    prefixes for subdomain permutation (alterx, puredns)
  USAGE.txt         ready-to-run commands for each list
```

To add employee names you gathered by hand (for example from LinkedIn), put one
`First Last` per line in `~/.config/reconta/state/<target>/names.txt` before the
run. Reconta will fold them into `usernames.txt`. Reconta does not scrape social
networks itself, because that usually breaks their terms of service.

The username and password lists are for authorized credential testing only.

## Installation

### Kali Linux

Kali already includes `nmap`, `whois`, `jq`, and Go, so setup is short.

```bash
# 1. Download the code
git clone https://github.com/shreyasKU31/reconta.git
cd reconta

# 2. Install the tools and a DNS resolver list
chmod +x reconta.sh install.sh
./install.sh

# 3. Add Go's tool directory to your PATH (only needed once)
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc
source ~/.zshrc

# 4. Check what installed, then run your first scan
./reconta.sh --list-tools
./reconta.sh example.com -p quick
```

Kali uses the zsh shell by default, so the example writes to `~/.zshrc`. On Ubuntu
or WSL the default is bash, so use `~/.bashrc` instead. If Go is not installed,
run `sudo apt install -y golang-go` first.

### Run it from anywhere

```bash
sudo make install
reconta example.com -p normal
```

This copies Reconta to `/opt/reconta` and links the `reconta` command into your
PATH.

### Docker

If you would rather not install the tools on your system, use the container. It
comes with everything included.

```bash
make docker-build
docker run --rm -v "$PWD/loot:/opt/reconta/output" reconta example.com -p normal
```

Your results appear in the `loot` folder.

Reconta needs Go 1.21 or newer for a normal install, plus Python 3 and apt for the
full set of tools. You do not need every tool. If one is missing, Reconta prints a
warning, skips that step, and continues.

### Tools Reconta uses

subfinder, amass, assetfinder, crt.sh, findomain, puredns, alterx, dnsx, httpx,
naabu, nmap, gau, waybackurls, katana, uro, subjs, trufflehog, mantra, arjun,
paramspider, asnmap, theHarvester, whois, nuclei, subzy, anew, jq, notify,
gowitness, cewl, ffuf, gobuster, pdftotext (poppler-utils).

## Usage

```bash
./reconta.sh example.com                 # normal profile (the default)
./reconta.sh example.com -p quick        # fast, passive only
./reconta.sh example.com -p deep -o ~/loot
./reconta.sh example.com --no-ports --no-vulns
./reconta.sh --list-tools
```

| Option | What it does |
|---|---|
| `-o, --output DIR` | Output directory (default: `./output`) |
| `-p, --profile P`  | `quick`, `normal`, or `deep` |
| `-c, --config FILE`| Use a different config file |
| `--no-ports`       | Skip port scanning |
| `--no-vulns`       | Skip the nuclei and takeover checks |
| `--no-diff`        | Skip change detection |
| `-m, --monitor`    | Send an alert (through `notify`) when new assets appear |
| `--list-tools`     | Show which tools are installed |
| `-v, --version`    | Print the version |

### Profiles

- **quick** runs passive sources only. No brute force, no port scan. Fastest, and
  the least intrusive way to start.
- **normal** is the recommended default. Passive sources plus light active checks,
  the top 100 ports, and a standard nuclei scan.
- **deep** does the most: subdomain brute force, a full port scan, deeper
  crawling, and all severity levels.

### Continuous monitoring

Because Reconta remembers each target between runs, you can put it on a schedule
and be told when something changes.

```bash
# Every day at 03:00, scan and alert on anything new
0 3 * * *  /path/to/reconta.sh example.com -p quick --monitor
```

## Configuration

All settings live in [config/reconta.conf](config/reconta.conf): thread counts,
rate limits, which stages to run, the profile, wordlists, resolvers, and
notifications.

API keys are never stored in this file. Set them in each tool's own config, for
example `~/.config/subfinder/provider-config.yaml`, or in your environment.

To get a notification with the final summary, set `NOTIFY=1` and configure
[notify](https://github.com/projectdiscovery/notify).

## Responsible use

Reconta is meant for authorized security testing only. That means bug bounty
targets that are in scope, systems you own, or engagements where you have written
permission.

The active stages, such as brute forcing, port scanning, crawling, and the nuclei
scan, send traffic straight to the target. You are responsible for staying in
scope and following the law. The authors take no responsibility for misuse.

The `quick` profile is passive and is the safest way to begin.

## Contributing

Contributions are welcome. New signatures are especially valuable, because they
make everyone's results better. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, the coding standards, and step-by-step guides for adding a
signature, a module, or a tool.

- Found a bug? Open an issue.
- Have an idea? Request a feature.
- Found a security problem in Reconta itself? See [SECURITY.md](SECURITY.md) and
  report it privately.
- Please read the [Code of Conduct](CODE_OF_CONDUCT.md).

Good first contributions include adding a pattern to `config/signatures.txt`,
integrating a new passive source, or improving the HTML report. Run `make test`
before you push.

## Roadmap

- Compare `report.json` between runs for monitoring dashboards.
- Optionally embed `gowitness` screenshots in the HTML report.
- Per-program scope files (in-scope and out-of-scope patterns) applied to every
  stage.
- More notification options beyond `notify`, such as native Discord and Slack
  webhooks.
- Community signature packs for specific platforms and cloud providers.

## License

MIT. See [LICENSE](LICENSE). By contributing, you agree that your work is licensed
under the same terms.
