# Security Policy

## Responsible use

Reconta is a reconnaissance framework intended **exclusively** for authorized
security work: bug-bounty targets that are in scope, systems you own, or
engagements for which you hold explicit written permission.

Reconta's active stages (subdomain brute force, port scanning, crawling,
parameter fuzzing, and `nuclei` scanning) send traffic directly to the target.
Running them against systems you are not authorized to test may be illegal in
your jurisdiction and violates the license and this policy.

- Start with the least-intrusive profile: `./reconta.sh <target> -p quick`.
- Stay within the scope defined by the program or engagement.
- Respect `robots.txt`, rate limits, and program-specific rules.
- You are solely responsible for how you use this tool. The authors and
  contributors accept no liability for misuse or damage.

## Reporting a vulnerability in Reconta

If you find a security issue in Reconta itself (e.g. a command-injection path
through a crafted target/response, or unsafe handling of tool output), please
report it privately rather than opening a public issue:

- Use GitHub's **Private vulnerability reporting** (Security → Report a
  vulnerability) on this repository, **or**
- Email the maintainers at the address listed on the project's GitHub profile.

Please include:

- A description of the issue and its impact
- Steps to reproduce (a minimal command / input)
- The version/commit (`./reconta.sh --version`) and your OS

We aim to acknowledge reports within **72 hours** and to provide a remediation
timeline after triage. Please give us a reasonable window to fix the issue
before any public disclosure. We're happy to credit reporters who wish to be
named.

## Supported versions

Reconta is released from `main`. Security fixes land on `main` and in the next
tagged release. Please run a recent version before reporting.
