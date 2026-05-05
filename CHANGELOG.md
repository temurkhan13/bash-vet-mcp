# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-05-05

### Changed — README refresh from Pass 7 sweep

- Added a hero-section verbatim quote from a working engineer ([@chiefofautism, 158↑ / 135 RTs / 11.5K views](https://x.com/chiefofautism/status/2023151450503753972)) — the strongest one-line statement of the threat model the server defends against. Cross-linked to `openclaw-output-vetter-mcp` for the "while telling you he cleaned up the project structure" half of the failure mode.
- No code or detection-rule changes. Patch bump only.

## [1.0.0] — 2026-05-05

Initial release.

### Added
- 24 destructive-pattern detection rules across 8 families (DESTRUCTIVE, PACKAGE, PRIVILEGED, SHUTDOWN, EXFIL, DATABASE, GIT, SUSPICIOUS).
- 3 MCP tools: `vet_command`, `vet_command_chain`, `list_detection_rules`.
- 3 demo resources: `bash-vet://demo/clean`, `bash-vet://demo/dangerous`, `bash-vet://demo/sneaky`.
- 2 prompts: `vet-this-command(chain?)`, `audit-script`.
- `bashlex` AST parsing with graceful regex-only fallback for unusual syntax.
- Chain-mode severity escalation (LOW→MEDIUM, MEDIUM→HIGH) for chained / multi-statement commands.
- Severity ladder (INFO=0 / LOW=1 / MEDIUM=5 / HIGH=15 / CRITICAL=40), risk_score capped at 100.
- Verdict ladder (CLEAN / CAUTION / REVIEW / BLOCK / UNVERIFIED).
- 50+ test cases covering rule-by-rule detection, chain-mode escalation, risk-score ladder, and MCP protocol wiring.
- GitHub Actions CI + release workflow with PyPI Trusted Publishing via OIDC.
- MCP Registry submission via `mcp-publisher`.

[1.0.0]: https://github.com/temurkhan13/bash-vet-mcp/releases/tag/v1.0.0
