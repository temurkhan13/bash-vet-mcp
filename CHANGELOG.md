# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.5] — 2026-05-08

### Added — `bash-vet-mcp-demo` console script (V1 of cross-product UX retrofit)

A new console script that runs against 6 hand-curated representative shell commands and prints verdict + risk score + first finding for each — in ~30 seconds, without configuring an MCP client.

The 6 commands exercise each rule family:

- `rm -rf $UNSET_VAR/*` — the classic xornullvoid wipeout (variable empty → `rm -rf /*`)
- `apt remove '*nvidia*'` — package-manager glob removal that cascades
- `curl ... | bash` — network-exfil-by-installer
- `dd if=/dev/zero of=/dev/sda` — filesystem destruction
- `chmod 777 -R /etc` — privilege blast on system path
- `ls + cat` — clean baseline

For each, the demo prints the verdict (CLEAN/CAUTION/REVIEW/BLOCK), risk_score (0-100), and the first finding's rule_id + pattern_kind + description. Designed for the first-30-seconds-after-install moment.

**Usage:**

```
$ pip install bash-vet-mcp
$ bash-vet-mcp-demo
bash-vet-mcp v1.0.5 · synthetic demo
    vets LLM-emitted shell commands BEFORE execution · 26 rules / 8 families

  🛑  Package-manager glob removal
     command: sudo apt remove '*nvidia*' && sudo reboot
     verdict: BLOCK · risk_score: 20/100 · findings: 2
     PACKAGE.APT_REMOVE_GLOB: package-glob-remove — apt removing packages by glob pattern
  ...
Result: 4 BLOCK · 1 REVIEW · 1 CLEAN  out of 6 inputs.
```

**No external I/O.** Demo runs vet_command against the bundled hardcoded commands; no network, no API keys, no filesystem access. Safe to run anywhere.

Adds a second console-script entry (`bash-vet-mcp-demo`) alongside the existing `bash-vet-mcp` (the MCP server entry).

## [1.0.4] — 2026-05-08

### Added — first-run startup banner (visibility-after-install fix, V2 of cross-product UX retrofit)

When the server starts via `python -m bash_vet_mcp` or the console script, the first stderr line is now a one-line value-prove receipt:

```
bash-vet-mcp v1.0.4 ready · vets LLM-emitted shell commands BEFORE execution · 26 rules across 8 families · sub-second, local, free
```

Before v1.0.4 the server started silently — operators who'd just `pip install`ed had no immediate signal of what the server actually does. The banner is the first-30-seconds value moment that was previously missing.

**Suppressible:** set `BASH_VET_QUIET=1` (or `true` / `yes`) to skip the banner. Useful when piping stderr to a log file in production.

**No protocol behavior changed.** Banner is stderr-only; stdout (the MCP JSON-RPC channel) is untouched. Pure observability addition.

## [1.0.3] — 2026-05-06

### Added — 2 new rules + 2 regex extensions (real-input validation gap closures)

Discovered during a real-input validation pass with adversarial commands not from the test fixtures: 5 of 12 representative destructive patterns slipped through v1.0.2's catalog. This release closes 4 of those 5 (the 5th, `rm -rf ./extracted/*`, is intentionally not flagged because relative-path cleanup is plausibly benign — name a specific subdir if you want explicit scope).

**New rules:**

- **`DESTRUCTIVE.RM_CURRENT_DIR`** (HIGH) — catches `rm -rf .`, `rm -rf ./`, `rm -rf ./*`. The chiefofautism threat-model quote in the README ("it can rm -rf your repo") was previously not actually detected — the existing `RM_RECURSIVE_ROOT` rule only matched root system paths (`/`, `/etc`, `~/`). Named subdirs (`rm -rf ./build`, `rm -rf ./node_modules`) are deliberately NOT flagged because they are typically intentional cleanup.
- **`DESTRUCTIVE.FIND_EXEC_RM`** (HIGH) — catches `find ... -exec rm` patterns. If `-name` is broad or the start path is large, this is mass deletion in disguise. `find -delete` is a separate pattern (not flagged by this rule; could become its own future rule).
- **`EXFIL.BASE64_PIPE_SHELL`** (HIGH) — catches `base64 -d | bash`, `base64 --decode | sh`, `base64 -D | zsh`. Obfuscation evasion technique — the decoded payload is invisible until execution.

**Extended rules:**

- **`PACKAGE.APT_REMOVE_GLOB`** — now catches `apt-get remove --purge -y python3-*` (trailing-glob form with `--purge` flag) in addition to the existing leading-glob form (`apt remove '*nvidia*'`).
- **`EXFIL.WGET_PIPE_BASH`** — now catches `wget ... -O - | sh` (space variant) and `wget --output-document=- ... | bash` (long-flag form), in addition to the existing `wget -O- ... | bash` (no-space form).

**Test coverage:** +23 new tests across positive cases per rule + intentional-clean cases to verify no false positives. Total 111 tests passing (was 88). ruff + mypy strict clean.

**Catalog count:** 24 rules → 26 rules. README pyproject description + server.json description updated to reflect the new count.

**Validation gap that drove this release:** documented in `C:/Users/hp/_mcp-validation-2026-05-06/REPORT.md` (PHASE 2 functional tests with real adversarial inputs).

## [1.0.2] — 2026-05-06

### Added — server-protocol coverage tests (overnight Phase 1A)

- Coverage gap-fillers committed as [`f206f5d`](https://github.com/temurkhan13/bash-vet-mcp/commit/f206f5d). No production-code changes — purely tests exercising the MCP-protocol surface (handler registration, tool / resource / prompt routing) that previously had only end-user-API coverage. Patch bump republishes to PyPI so the test-count badge in README stays consistent across PyPI mirrors.

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

[Unreleased]: https://github.com/temurkhan13/bash-vet-mcp/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/temurkhan13/bash-vet-mcp/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/temurkhan13/bash-vet-mcp/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/temurkhan13/bash-vet-mcp/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/temurkhan13/bash-vet-mcp/releases/tag/v1.0.0
