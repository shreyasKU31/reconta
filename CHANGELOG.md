# Changelog

All notable changes to Reconta are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/<you>/reconta/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/<you>/reconta/releases/tag/v1.0.0
