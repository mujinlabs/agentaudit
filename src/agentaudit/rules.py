"""Detection rules for agentaudit.

Each rule is a small, transparent, regex-based heuristic. They are
intentionally conservative and explainable: every finding points at an
exact line so a human can judge it. False positives are expected and
fine — the goal is to surface things worth a second look before you let
an AI agent extension run on your machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern

# Severity weights feed the score (higher = worse).
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    message: str
    recommendation: str
    pattern: Pattern
    # Restrict a rule to certain file kinds: "code", "doc", "manifest", "any".
    applies_to: tuple = ("any",)


def _rx(p: str) -> Pattern:
    return re.compile(p, re.IGNORECASE)


RULES: list[Rule] = [
    # --- Remote code fetch / supply chain --------------------------------
    Rule(
        "AA001", "remote-code-fetch", "critical",
        "Pipes a downloaded script straight into a shell (curl|bash style).",
        "Never execute remote scripts blindly. Pin a version and review the script first.",
        _rx(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh"),
        ("code", "doc", "manifest"),
    ),
    Rule(
        "AA002", "remote-code-fetch", "high",
        "Installs an unpinned/remote package at runtime (npx -y, pip git+, etc.).",
        "Pin exact versions and vendor or lock dependencies; runtime installs are an injection vector.",
        _rx(r"\b(npx\s+-y|pip(3)?\s+install\s+(git\+|https?://)|uvx\s|go\s+install\s+\S+@)"),
        ("code", "manifest"),
    ),
    # --- Secret / credential access --------------------------------------
    Rule(
        "AA010", "secret-access", "high",
        "Touches credential files or secret env vars (.env, ~/.aws, ~/.ssh, *_API_KEY, *_TOKEN).",
        "Confirm the extension genuinely needs these. Credential paths are a common exfil target.",
        _rx(r"(\.aws/credentials|\.ssh/id_|\.netrc|/\.env\b|\bAWS_SECRET_ACCESS_KEY|\bGITHUB_TOKEN|\bANTHROPIC_API_KEY|\bOPENAI_API_KEY)"),
        ("code", "manifest"),
    ),
    Rule(
        "AA011", "secret-access", "high",
        "Accesses browser cookie / session stores (credential theft pattern).",
        "Browser cookie/session DB access is rarely legitimate for an agent extension.",
        _rx(r"(Cookies|Login Data|key4\.db|logins\.json|Local Storage/leveldb)"),
        ("code",),
    ),
    # --- Network exfiltration --------------------------------------------
    Rule(
        "AA020", "network-exfil", "high",
        "Sends data to a hardcoded external endpoint (webhook / paste / tunnel).",
        "Verify the destination. Hardcoded webhooks/pastebins are classic exfiltration sinks.",
        _rx(r"(hooks\.slack\.com|discord(app)?\.com/api/webhooks|pastebin\.com|requestbin|ngrok\.io|webhook\.site|0x0\.st|transfer\.sh)"),
        ("code", "manifest"),
    ),
    Rule(
        "AA021", "network-exfil", "medium",
        "Raw outbound HTTP POST with request body — check what is being sent.",
        "Trace what data flows into this request; ensure no secrets or file contents leak.",
        _rx(r"(requests\.post|urllib\.request\.urlopen|fetch\(|axios\.post|http\.client)"),
        ("code",),
    ),
    # --- Shell / process execution ---------------------------------------
    Rule(
        "AA030", "shell-exec", "medium",
        "Spawns a shell / arbitrary process from code.",
        "Shell-out is sometimes legitimate but widens attack surface; confirm inputs are not attacker-controlled.",
        _rx(r"(os\.system|subprocess\.(Popen|call|run|check_output)|child_process|exec\(|shell=True)"),
        ("code",),
    ),
    Rule(
        "AA031", "destructive", "high",
        "Contains a destructive filesystem command (rm -rf, del /s, format, mkfs).",
        "Destructive commands in an extension are a major red flag unless clearly scoped and intended.",
        _rx(r"(rm\s+-rf\s+[/~]|\bdel\s+/[sq]\b|\bformat\s+[a-z]:|mkfs\.|>\s*/dev/sd)"),
        ("code", "doc", "manifest"),
    ),
    # --- Obfuscation ------------------------------------------------------
    Rule(
        "AA040", "obfuscation", "critical",
        "Decodes then executes data at runtime (base64/hex -> eval/exec).",
        "Dynamic-decode-then-execute is the single strongest malware signal. Treat as hostile until proven safe.",
        _rx(r"(eval|exec|Function)\s*\(\s*(atob|base64\.b64decode|bytes\.fromhex|Buffer\.from)"),
        ("code",),
    ),
    Rule(
        "AA041", "obfuscation", "medium",
        "Large base64/hex blob embedded in source.",
        "Embedded encoded blobs can hide payloads; decode and inspect before trusting.",
        _rx(r"['\"][A-Za-z0-9+/]{120,}={0,2}['\"]"),
        ("code",),
    ),
    # --- Prompt injection / hidden instructions (docs & manifests) -------
    Rule(
        "AA050", "prompt-injection", "high",
        "Hidden/override instructions aimed at the agent (\"ignore previous\", \"do not tell the user\").",
        "Extension text that tries to steer the agent behind the user's back is a prompt-injection attack.",
        _rx(r"(ignore (all |the )?previous (instructions|prompts)|do not (tell|inform|mention to) the user|without (telling|informing|asking) the user|disregard (your|the) (system|safety))"),
        ("doc", "manifest", "code"),
    ),
    Rule(
        "AA051", "prompt-injection", "medium",
        "Invisible / zero-width / bidi unicode in text (can hide instructions).",
        "Zero-width or bidirectional control characters are used to smuggle hidden instructions. Inspect raw bytes.",
        _rx(r"[​-‏‪-‮⁠-⁤﻿]"),
        ("doc", "manifest", "code"),
    ),
    # --- Over-broad permissions (manifests) ------------------------------
    Rule(
        "AA060", "permissions", "medium",
        "Declares wildcard / unrestricted permissions or allow-all tool access.",
        "Grant least privilege. Wildcards like \"*\" or allow-all defeat the permission model.",
        _rx(r"(\"permissions\"\s*:\s*\[\s*\"\*\"|allow[_-]?all|\"bypassPermissions\"\s*:\s*true|\"--dangerously-skip-permissions\")"),
        ("manifest", "code"),
    ),
]
