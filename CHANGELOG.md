# Changelog

All notable changes to Reconta are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Active vulnerability hunting stage (`modules/fuzz.sh`): tests the collected
  parameterised URLs and hosts for real bugs and appends confirmed findings to
  `vulns.txt` (severity-tagged, so they also top `interesting.txt`). Covers XSS
  (dalfox + nuclei DAST), SQL injection (nuclei DAST, plus sqlmap in deep),
  SSRF/blind bugs via out-of-band interactsh, open redirect and CORS
  misconfiguration (built-in canary checks), CRLF injection (crlfuzz, deep), and
  SSTI/LFI/path traversal via nuclei fuzzing templates. Runs only in the normal
  and deep profiles; disable with `--no-fuzz`. Adds `dalfox`, `crlfuzz`,
  `sqlmap`, `qsreplace`, and `interactsh-client` to the installer and Docker.
- Custom wordlist engine (`modules/wordlist.sh`): builds target-specific
  `directories`, `usernames`, `passwords`, and `subdomains` wordlists from the
  target's own data (CeWL site vocabulary, URL path tokens, technology names,
  public PDF text, and OSINT emails), cleans and de-duplicates them, and writes
  a `wordlists/USAGE.txt` cheat sheet with ready-to-run ffuf, gobuster, hydra,
  hashcat, and john commands. In the `deep` profile it also runs ffuf with the
  custom directory list and merges discovered resources into `urls.txt`.
- `ffuf`, `gobuster`, `cewl`, and `poppler-utils` added to the installer and
  Docker image; wordlist counts added to the report and `report.json`.

## [1.0.0] - 2026-07-11

### Added
- Initial public release.
- Orchestrated recon pipeline: passive + active subdomain enumeration,
  DNS/HTTP liveness filtering, port & service discovery, URL/endpoint
  discovery with `uro` de-noising, JavaScript & secret hunting, parameter
  discovery, infrastructure/exposure OSINT, and templated vulnerability
  signals (`nuclei`, `subzy`).
- **Prioritization engine** (`modules/analyze.sh`): scores every URL against a
  curated signature knowledge base (`config/signatures.txt`) and every live
  host on status/tech/title/port, producing a ranked `interesting.txt`.
- **Change detection** (`modules/diff.sh`): per-target snapshots surface only
  what is new since the previous run in `new.txt`; `--monitor` alerts via
  `notify`.
- Consolidated reporting: `report.html` (dashboard), `report.md`, and
  machine-readable `report.json`.
- Three scan profiles: `quick`, `normal`, `deep`.
- Graceful degradation when tools are missing; `--list-tools` status view.
- `install.sh` for Go/Python/system dependencies on Debian/Ubuntu/Kali/WSL.

[Unreleased]: https://github.com/shreyasKU31/reconta/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/shreyasKU31/reconta/releases/tag/v1.0.0
