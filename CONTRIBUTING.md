# Contributing to Reconta

First off — thank you. Reconta gets better every time someone adds a signature,
wires in a tool, or fixes an edge case. This guide gets you productive fast.

## Ways to contribute

- **Add or tune signatures** — the highest-leverage contribution. `config/signatures.txt`
  is what turns noise into a ranked findings list. New leak patterns, param
  classes, or exposed-service fingerprints help everyone. See
  [Adding a signature](#adding-a-signature).
- **Add a tool / source** — a new passive source, a better crawler, another
  secret scanner. See [Adding a module or tool](#adding-a-module-or-tool).
- **Fix bugs / improve reliability** — edge cases in parsing, portability, speed.
- **Docs** — clarify install steps, add usage recipes, improve the README.

No contribution is too small. Typo fixes are welcome.

## Development setup

```bash
git clone https://github.com/<you>/reconta.git
cd reconta
./install.sh            # or: ./install.sh --go-only
./reconta.sh --list-tools
sudo apt install shellcheck   # for linting (see below)
```

Reconta is pure Bash + external CLIs. No build step. Edit, run, done.

## Project layout

```
reconta.sh            # orchestrator: args, config, pipeline order
lib/common.sh         # shared logging, tool detection, file helpers
config/reconta.conf   # user-tunable settings & stage toggles
config/signatures.txt # the prioritization knowledge base
modules/*.sh          # one file per stage, each defines module_<name>()
```

Each module is a function `module_<name>` sourced by `reconta.sh`. Modules read
the canonical files under `$OUTDIR` and write their own broad-topic file back.

## Coding standards

- **Target Bash 5+** (Kali/Ubuntu default). POSIX where easy, but Bashisms are fine.
- **Lint clean:** `make lint` (runs ShellCheck) must pass. CI enforces this.
- **Log through the helpers** in `lib/common.sh` (`log_step`, `log_ok`, `log_warn`,
  `log_result`) — never raw `echo` for status. Keeps output consistent.
- **Degrade gracefully:** every external tool must be guarded with
  `require_tool <bin> "<stage>"` or `have_tool <bin>`. A missing tool warns and
  skips — it never crashes the run.
- **Cap long tools** with `capped <seconds> <cmd…>` so one hang can't stall a scan.
- **Filter, don't dump.** New data must be de-noised (resolve/dedupe/collapse)
  before it lands in a top-level output file. Raw artifacts go under `.raw/`.
- **Keep the top level to broad-topic files only.** Don't add a new top-level
  output file without discussion — fold into an existing one or use `.raw/`.
- Indent with **2 spaces**, no tabs (see `.editorconfig`).

## Adding a signature

Edit `config/signatures.txt`. One rule per line, three whitespace-separated fields:

```
WEIGHT  CATEGORY  REGEX
```

- `WEIGHT` — integer priority. Roughly: 90+ direct exposure, 70–85 high-impact
  params / exposed interfaces, 40–65 interesting endpoints, <40 low signal.
- `CATEGORY` — short tag, **no spaces** (e.g. `redirect-ssrf-param`).
- `REGEX` — POSIX ERE, **no spaces**, matched case-insensitively against the URL.

Example — flag exposed Prometheus metrics:

```
80 exposed-metrics (/metrics$|/prometheus|/actuator/prometheus)
```

Test it before opening a PR:

```bash
printf 'https://x.com/metrics\nhttps://x.com/home\n' \
  | SIGNATURES=config/signatures.txt awk -f /dev/stdin config/signatures.txt -
# or just run a scan and inspect output/<target>/interesting.txt
```

Keep regexes tight — a noisy signature that fires on everything is worse than none.

## Adding a module or tool

1. Create `modules/<name>.sh` defining `module_<name>()`. Copy the header/shape
   of an existing module (e.g. `modules/urls.sh`).
2. Guard every binary with `require_tool`. Read inputs from `$OUTDIR/*.txt`;
   write one de-noised broad-topic file back to `$OUTDIR`.
3. Register it: add `<name>` to the `for m in …` source loop **and** call
   `module_<name>` at the right point in the pipeline in `reconta.sh`.
4. Add the binary to `install.sh` (Go tool → `GO_TOOLS`, Python → the pipx loop).
5. Add it to the `CORE_TOOLS` list so `--list-tools` reports it.
6. Update the README tool list and pipeline diagram.

## Commit & PR process

- Branch from `main`: `git checkout -b feat/<short-name>` or `fix/<short-name>`.
- Use clear, imperative commit messages. [Conventional Commits](https://www.conventionalcommits.org/)
  are encouraged: `feat: add prometheus metrics signature`.
- Run `make lint` and a smoke scan (`./reconta.sh example.com -p quick`) before pushing.
- Open a PR against `main`, fill in the template, and describe what you tested.
- One logical change per PR keeps review fast.

## Reporting bugs & requesting features

Use the issue templates. For bugs, include your OS, `./reconta.sh --list-tools`
output, the exact command, and the relevant lines from `output/<target>/reconta.log`.

## Legal & ethics

Reconta is for **authorized** testing only. Do not contribute features whose
primary purpose is evading detection, attacking out-of-scope systems, or
mass-exploitation. See [SECURITY.md](SECURITY.md). By contributing you agree your
work is licensed under the project's [MIT License](LICENSE).
