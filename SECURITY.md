# Security Policy

agentaudit is a security tool, so we hold ourselves to the standard we ask of
others.

## Reporting a vulnerability

Please report security issues privately to **security@mujinlabs.com**.

- Include a description, affected version, and reproduction steps.
- We aim to acknowledge within 72 hours and to ship a fix or mitigation as
  quickly as the severity warrants.
- Please give us a reasonable window to address the issue before public
  disclosure. We're happy to credit you.

## Scope

agentaudit runs **locally and offline** — it reads files and prints results,
and never uploads what it scans. Reports we especially care about:

- A way to make agentaudit execute code from the artifact it is auditing.
- A path traversal or write outside the intended output.
- A detection bypass that lets a known-malicious pattern score clean.

## Detection false positives / false negatives

These are *not* security vulnerabilities — please open a normal GitHub issue or
PR against [`rules.py`](src/agentaudit/rules.py). Improving the rules in the
open is the whole point.

— Mujin Labs
