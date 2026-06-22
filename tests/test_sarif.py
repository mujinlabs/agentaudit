"""Tests for SARIF 2.1.0 output."""

from pathlib import Path

from agentaudit.scanner import scan, Finding
from agentaudit.sarif import to_sarif, _level, _fingerprint

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_sarif_shape_on_malicious():
    s = to_sarif(scan(str(EXAMPLES / "malicious-skill")))
    assert s["version"] == "2.1.0"
    assert s["$schema"].endswith("sarif-schema-2.1.0.json")
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "agentaudit"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert run["results"], "malicious example must produce results"
    for res in run["results"]:
        # every result's ruleId must be in the driver catalog (GitHub requires it)
        assert res["ruleId"] in rule_ids
        assert res["level"] in {"error", "warning", "note"}
        region = res["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
    assert run["properties"]["agentaudit.grade"] == "F"
    assert run["properties"]["agentaudit.score"] == 0


def test_level_mapping():
    assert _level("critical") == "error"
    assert _level("high") == "error"
    assert _level("medium") == "warning"
    assert _level("low") == "note"
    assert _level("info") == "note"


def test_empty_report_is_valid_sarif():
    s = to_sarif(scan(str(EXAMPLES / "benign-skill")))
    run = s["runs"][0]
    assert run["results"] == []                       # valid: empty results
    assert run["properties"]["agentaudit.grade"] == "A"
    assert len(run["tool"]["driver"]["rules"]) > 0     # catalog still present


def test_fingerprint_is_stable_and_line_independent():
    f = Finding("AA001", "remote-code-fetch", "critical", "m", "r", "SKILL.md", 3, "curl | bash")
    assert _fingerprint(f) == _fingerprint(f)
    moved = Finding("AA001", "remote-code-fetch", "critical", "m", "r", "SKILL.md", 99, "curl | bash")
    assert _fingerprint(f) == _fingerprint(moved)      # moved line != new alert
    other = Finding("AA002", "remote-code-fetch", "high", "m", "r", "SKILL.md", 3, "curl | bash")
    assert _fingerprint(f) != _fingerprint(other)


def test_security_severity_and_level_kept_distinct():
    s = to_sarif(scan(str(EXAMPLES / "malicious-skill")))
    by_id = {r["id"]: r for r in s["runs"][0]["tool"]["driver"]["rules"]}
    # AA001 is critical → level error, security-severity 9.5 (keeps GitHub badge fidelity)
    assert by_id["AA001"]["defaultConfiguration"]["level"] == "error"
    assert by_id["AA001"]["properties"]["security-severity"] == "9.5"


def test_uris_are_forward_slash():
    s = to_sarif(scan(str(EXAMPLES / "malicious-skill")))
    for res in s["runs"][0]["results"]:
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri
