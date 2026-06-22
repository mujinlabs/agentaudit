"""SARIF 2.1.0 output for agentaudit.

Renders a scan Report as SARIF so findings show up natively in GitHub's
"Code scanning" tab / PR annotations (and any SARIF-aware platform). Pure
serializer over the existing Report/Finding model — no engine changes, stdlib
only, so the zero-dependency promise holds.
"""

from __future__ import annotations

import hashlib

from . import __version__
from .rules import RULES
from .scanner import Finding, Report

SARIF_VERSION = "2.1.0"
SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
          "Schemata/sarif-schema-2.1.0.json")
INFO_URI = "https://github.com/mujinlabs/agentaudit"

# SARIF `level` has only error/warning/note — collapse our 5 severities.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}
# `security-severity` (string 0.0–10.0) preserves GitHub's 5-level badge that
# `level` alone would lose.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0",
                      "low": "3.0", "info": "0.0"}


def _level(severity: str) -> str:
    return _LEVEL.get(severity, "warning")


def _camel(category: str) -> str:
    parts = category.replace("_", "-").split("-")
    return parts[0] + "".join(p.title() for p in parts[1:])


def _uri(path: str) -> str:
    # SARIF wants forward-slash, repo-relative URIs (scanner already emits
    # paths relative to the scan root).
    return path.replace("\\", "/")


def _rule_descriptor(rule) -> dict:
    return {
        "id": rule.id,
        "name": _camel(rule.category),
        "shortDescription": {"text": rule.message},
        "fullDescription": {"text": f"{rule.message} {rule.recommendation}"},
        "helpUri": f"{INFO_URI}#{rule.id.lower()}",
        "defaultConfiguration": {"level": _level(rule.severity)},
        "properties": {
            "category": rule.category,
            "security-severity": _SECURITY_SEVERITY.get(rule.severity, "0.0"),
        },
    }


def _fingerprint(f: Finding) -> str:
    # Stable across commits so a moved line is not re-reported as a new alert.
    return hashlib.sha256(
        f"{f.rule_id}:{f.file}:{f.excerpt}".encode("utf-8")
    ).hexdigest()[:16]


def _result(f: Finding) -> dict:
    return {
        "ruleId": f.rule_id,
        "level": _level(f.severity),
        "message": {"text": f"{f.message}\n{f.recommendation}"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(f.file), "uriBaseId": "SRCROOT"},
                "region": {
                    "startLine": max(1, f.line),
                    "snippet": {"text": f.excerpt},
                },
            }
        }],
        "partialFingerprints": {"agentauditV1": _fingerprint(f)},
    }


def to_sarif(report: Report) -> dict:
    """Convert a scan Report into a SARIF 2.1.0 document (a plain dict)."""
    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "agentaudit",
                "version": __version__,
                "informationUri": INFO_URI,
                "rules": [_rule_descriptor(r) for r in RULES],
            }},
            "results": [_result(f) for f in report.findings],
            "properties": {
                "agentaudit.score": report.score,
                "agentaudit.grade": report.grade,
                "agentaudit.counts": report.counts(),
            },
        }],
    }
