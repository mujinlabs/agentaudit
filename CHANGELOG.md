# Changelog

## 0.2.0 — 2026-06-22
### Added
- `--format {text,json,sarif}` output selector.
- **`--format sarif`** emits SARIF 2.1.0 so findings render in GitHub's
  Code scanning tab / PR annotations (and any SARIF-aware platform). Severity
  maps to SARIF `level` plus `security-severity` (keeps GitHub's 5-level badge),
  and each finding carries a stable `partialFingerprint` so a moved line is not
  re-reported as a new alert. Pure serializer — still zero dependencies.
- README: GitHub code-scanning workflow example.

### Changed
- `--json` is now a deprecated alias for `--format json` (still works).

## 0.1.0 — 2026-06-21
- Initial release: local, dependency-free auditor for AI-agent extensions
  (Claude Code skills, MCP servers, plugins). 13 rules across 7 categories;
  text/JSON output; score + grade; `--fail-on` CI gating.
