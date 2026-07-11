# Contributing to Reconta

Thank you for taking the time to contribute. Reconta improves every time someone
adds a pattern, connects a new tool, or fixes a rough edge. This guide will help
you get started quickly.

## Ways to help

- **Add or improve signatures.** This is the most useful thing you can do.
  `config/signatures.txt` is what turns raw output into a ranked list of findings.
  New patterns for leaks, risky parameters, or exposed services help every user.
  See [Adding a signature](#adding-a-signature).
- **Add a tool or source.** A new passive source, a better crawler, or another
  secret scanner. See [Adding a module or tool](#adding-a-module-or-tool).
- **Fix bugs.** Parsing edge cases, portability problems, or speed improvements.
- **Improve the docs.** Clearer install steps, more usage examples, a better
  README.

No contribution is too small. Typo fixes are welcome.

## Setting up for development

```bash
git clone https://github.com/<you>/reconta.git
cd reconta
./install.sh                 # or: ./install.sh --go-only
./reconta.sh --list-tools
sudo apt install shellcheck  # used for linting, see below
```

Reconta is written in Bash and calls external command-line tools. There is no
build step. You edit a file and run it.

## Project layout

```
reconta.sh             The main script: arguments, config, and the pipeline order.
lib/common.sh          Shared logging, tool detection, and file helpers.
config/reconta.conf    Settings and stage on/off switches.
config/signatures.txt  The list of patterns used to rank findings.
modules/*.sh           One file per stage. Each defines a module_<name> function.
```

Every module is a function named `module_<name>` that `reconta.sh` loads. A module
reads the shared files in the output directory and writes its own topic file back.

## Coding standards

- **Target Bash 5 or newer**, which is the default on Kali and Ubuntu.
- **Keep it lint-clean.** Run `make lint` (which runs ShellCheck). The CI checks
  this on every pull request.
- **Use the logging helpers** in `lib/common.sh` (`log_step`, `log_ok`,
  `log_warn`, `log_result`) instead of plain `echo` for status messages. This
  keeps the output consistent.
- **Fail gracefully.** Guard every external tool with
  `require_tool <name> "<stage>"` or `have_tool <name>`. If a tool is missing,
  Reconta should warn and skip that step, never crash.
- **Cap slow tools** with `capped <seconds> <command>` so one stuck tool cannot
  freeze the whole scan.
- **Clean the data before you save it.** New results should be resolved,
  de-duplicated, or collapsed before they reach a top-level output file. Raw
  output goes under `.raw/`.
- **Keep the top level to one file per topic.** Please do not add a new top-level
  output file without discussing it first. Fold the data into an existing file or
  put it under `.raw/`.
- **Indent with two spaces.** No tabs. See `.editorconfig`.

## Adding a signature

Open `config/signatures.txt`. Each rule is one line with three fields separated by
spaces:

```
WEIGHT  CATEGORY  REGEX
```

- **WEIGHT** is a whole number for priority. As a rough guide: 90 and above for
  direct exposures, 70 to 85 for high-impact parameters and exposed interfaces,
  40 to 65 for interesting endpoints, and below 40 for weak signals.
- **CATEGORY** is a short tag with no spaces, for example `redirect-ssrf-param`.
- **REGEX** is a POSIX extended regular expression with no spaces. It is matched
  against the URL, ignoring case.

Here is an example that flags an exposed Prometheus metrics endpoint:

```
80 exposed-metrics (/metrics$|/prometheus|/actuator/prometheus)
```

Test your rule before opening a pull request. The simplest way is to run a scan
and look at `output/<target>/interesting.txt`. Keep the pattern tight. A rule that
matches almost everything is worse than no rule.

## Adding a module or tool

1. Create `modules/<name>.sh` with a `module_<name>` function. Copy the shape of
   an existing module, such as `modules/urls.sh`.
2. Guard every tool with `require_tool`. Read your input from the shared files in
   the output directory, and write one cleaned topic file back.
3. Register it in `reconta.sh`: add `<name>` to the list of modules that get
   loaded, and call `module_<name>` at the right point in the pipeline.
4. Add the tool to `install.sh` (Go tools go in the `GO_TOOLS` list, Python tools
   in the pipx section).
5. Add the tool to the `CORE_TOOLS` list so `--list-tools` reports it.
6. Update the tool list and the pipeline diagram in the README.

## Commits and pull requests

- Create a branch from `main`, for example `feat/new-source` or `fix/url-parsing`.
- Write clear commit messages in the imperative mood. The
  [Conventional Commits](https://www.conventionalcommits.org/) style is
  encouraged, for example `feat: add prometheus metrics signature`.
- Run `make lint` and a quick scan (`./reconta.sh example.com -p quick`) before
  you push.
- Open a pull request against `main`, fill in the template, and describe what you
  tested.
- Keep each pull request focused on one change. This makes review faster.

## Reporting bugs and requesting features

Please use the issue templates. For bug reports, include your operating system,
the output of `./reconta.sh --list-tools`, the exact command you ran, and the
relevant lines from `output/<target>/reconta.log`.

## Legal and ethics

Reconta is for authorized testing only. Please do not contribute features whose
main purpose is evading detection, attacking systems that are out of scope, or
mass exploitation. See [SECURITY.md](SECURITY.md). By contributing, you agree that
your work is licensed under the project's [MIT License](LICENSE).
