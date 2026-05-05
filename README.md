# bash-vet-mcp

<!-- mcp-name: io.github.temurkhan13/bash-vet-mcp -->

> **MCP server that vets LLM-emitted shell commands BEFORE execution** — detects `rm -rf` nested deep in chains, package-manager glob removal (`apt remove '*nvidia*'`), `dd`/`mkfs`/`wipefs` filesystem destruction, `chmod 777` / `chown -R` privilege blast, network-exfil via `curl | bash`, chained `shutdown`/`reboot`, and `git` destructive ops. **Sub-second, local, free, MCP-native** — designed to be called inline by Claude Code / Cursor / Cline / OpenClaw before approving any agent-proposed command. Defensive complement to MCP shell-execution servers (MCPShell, mcp-shell, mcp-bash).

[![Status: v1.0.0](https://img.shields.io/badge/status-v1.0.0-brightgreen)](https://github.com/temurkhan13/bash-vet-mcp) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](./LICENSE) [![MCP](https://img.shields.io/badge/protocol-MCP-purple)](https://modelcontextprotocol.io/) [![PyPI](https://img.shields.io/pypi/v/bash-vet-mcp)](https://pypi.org/project/bash-vet-mcp/)

---

## What it does

Production AI agents have a quiet failure mode in shell-command execution: the agent emits a chained command, the operator pattern-matches the start of the line, and a destructive fragment nested deep in the chain (`&&`, `;`, `|`) gets executed by accident.

A working engineer ([@chiefofautism, 158↑ / 135 RTs / 11.5K views](https://x.com/chiefofautism/status/2023151450503753972)) puts it more bluntly:

> *"claude code runs shell commands with YOUR permissions. it can rm -rf your repo. it can force push to main. it can drop your database. and it will do it confidently while telling you that he cleaned up the project structure"*

The danger isn't just the destructive command — it's the **confident misreport** that follows. bash-vet attacks the first half of that pair (the "rm -rf / force-push / drop database" part); pair it with [openclaw-output-vetter-mcp](https://github.com/temurkhan13/openclaw-output-vetter-mcp) for the second half (the "while telling you he cleaned up the project structure" part).

- **Buried `rm -rf`.** [r/LocalLLaMA "One bash permission slipped" (1,512↑)](https://old.reddit.com/r/LocalLLaMA/) — operator approved a long chained command after recognizing the lede; the chain ended with `rm -rf $UNSET_VAR/*` which expanded to `rm -rf /*` because the variable was empty. The classic xornullvoid wipeout was `apt remove '*nvidia*595*'` cascading into critical-package removal.
- **CVSS 10.0 in agent harnesses.** [r/devops "AI coding tools are now a CVSS 10.0 supply-chain risk" (130↑)](https://old.reddit.com/r/devops/) cites Cursor CVE-2026-26268 and Gemini CLI CVSS 10.0 — both featuring `--yolo` modes that ignore allowlists entirely and execute LLM-emitted commands without operator review.
- **Network-exfil via curl-pipe-bash.** Agents trained on installer documentation pattern-match `curl https://x.com/install.sh | bash` as legitimate. Once the agent is the one fetching the URL, the operator has no way to inspect the script before it runs.

This MCP server runs the vetting **inline before the command executes** — no API key, no LLM-as-judge cost, sub-second:

```
> claude: vet this command before I run it: sudo apt remove '*nvidia*' && reboot
[MCP tool: vet_command_chain]

verdict: BLOCK
risk_score: 30
finding_count: 2
findings:
  [HIGH] PACKAGE.APT_REMOVE_GLOB
    snippet: sudo apt remove '*nvidia*'
    description: apt removing packages by glob pattern — likely cascades into
      critical-dependency removal
    recommendation: Use exact package names. xornullvoid's nvidia-driver
      wipeout was apt remove '*nvidia*595*'.

  [HIGH] SHUTDOWN.CHAINED_REBOOT
    snippet: && reboot
    description: Chained reboot/shutdown after another command — cuts off the
      operator's ability to react if anything went wrong (escalated MEDIUM→HIGH
      because chain mode)
    recommendation: Run shutdown/reboot as a separate command after manual
      review.

summary: BLOCK — 2 finding(s); worst is HIGH (PACKAGE.APT_REMOVE_GLOB):
apt removing packages by glob pattern — likely cascades into critical-dependency
removal
```

---

## Why `bash-vet-mcp`

Three things existing MCP shell-execution servers don't do:

1. **Defensive complement, not yet-another-shell-executor.** [MCPShell](https://github.com/inercia/MCPShell), [mcp-shell](https://github.com/sonirico/mcp-shell), [mcp-bash](https://github.com/dvelasquezr/mcp-bash) all give the agent a `run_command` tool. **bash-vet-mcp is the opposite shape: vet before execute.** Pair it with one of those servers (or with Claude Code's built-in Bash tool) — the agent calls `vet_command` *before* asking the operator to approve the run. If the verdict is BLOCK, the operator sees the destructive fragment surfaced before they pattern-match-approve.

2. **Sub-second + local + free.** Pure-Python: `bashlex` AST parse + regex pattern bank. No LLM-as-judge call, no API key, no per-call cost. Runs in CI, runs offline, runs at every agent turn without budget pressure.

3. **24 detection rules across 8 families, each with stable rule_id + severity + recommendation.** Not "is this dangerous?" — *exactly which rule fired, what severity, what the operator should do.* This makes the response actionable at the agent loop level (block + retry with a different command) and at the human-review level (audit trail for compliance).

Built for the **production AI operator** who's already using Claude Code / Cursor / Cline / OpenClaw with shell access enabled, who's seen the failure mode at least once, and who wants the agent to vet its own emitted commands before asking for approval.

---

## Tool surface

| Tool | What it returns |
|------|-----------------|
| `vet_command(command)` | Verdict (CLEAN / CAUTION / REVIEW / BLOCK / UNVERIFIED) + risk_score (0–100) + per-finding rule_id + severity + snippet + description + recommendation |
| `vet_command_chain(command)` | Same as `vet_command`, but escalates LOW→MEDIUM and MEDIUM→HIGH because nested destructive fragments in chains are easier to overlook on quick read |
| `list_detection_rules()` | Catalog of every rule the scanner applies — for coverage audits, compliance documentation, custom allowlist construction |

Resources:
- `bash-vet://demo/clean` — sample CLEAN verdict (`ls -la /home/user/projects && cat README.md`)
- `bash-vet://demo/dangerous` — sample BLOCK verdict (apt-glob + chained reboot + curl|bash)
- `bash-vet://demo/sneaky` — sample SNEAKY chain mimicking the r/LocalLLaMA failure mode

Prompts:
- `vet-this-command(chain?)` — diagnostic walkthrough; agent calls `vet_command` (or chain variant) on the most recent command + explains each finding
- `audit-script` — line-by-line vet of a multi-line shell script + per-line verdict + overall script verdict

---

## Detection rules (24 across 8 families)

| Family | Rules | Severity range |
|--------|-------|----------------|
| `DESTRUCTIVE.*` | `RM_RECURSIVE_ROOT`, `RM_RECURSIVE_VAR`, `RM_NO_PRESERVE`, `DD_TO_DEVICE`, `MKFS`, `WIPEFS`, `SHRED`, `REDIRECT_TO_DEVICE` | MEDIUM → CRITICAL |
| `PACKAGE.*` | `APT_REMOVE_GLOB`, `YUM_REMOVE_GLOB`, `PACMAN_RNS_GLOB`, `BREW_UNINSTALL_FORCE` | MEDIUM → HIGH |
| `PRIVILEGED.*` | `CHMOD_777_ROOT`, `CHOWN_ROOT_ROOT`, `SUDO_GLOB_REMOVE` | HIGH |
| `SHUTDOWN.*` | `CHAINED_REBOOT` | MEDIUM |
| `EXFIL.*` | `CURL_PIPE_BASH`, `WGET_PIPE_BASH` | HIGH |
| `DATABASE.*` | `DROP_DATABASE`, `DROP_TABLE`, `TRUNCATE` | MEDIUM → HIGH |
| `GIT.*` | `PUSH_FORCE`, `RESET_HARD`, `CLEAN_FDX`, `FILTER_BRANCH` | MEDIUM |
| `SUSPICIOUS.*` | `FORK_BOMB`, `YES_PIPE_INSTALL` | LOW → CRITICAL |

Each rule has a stable `rule_id` (e.g., `DESTRUCTIVE.RM_RECURSIVE_ROOT`) + severity + pattern-kind tag + plain-English description + concrete recommendation. Call `list_detection_rules` to retrieve the full catalog.

---

## Quickstart

### Install

```bash
pip install bash-vet-mcp
```

### Configure for Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "bash-vet": {
      "command": "python",
      "args": ["-m", "bash_vet_mcp"]
    }
  }
}
```

Restart Claude Desktop. Test:

> Resource `bash-vet://demo/dangerous` — read it back to me.

The demo resource returns a sample CommandVetReport so you can verify the protocol wiring without authoring inputs.

### Use it inline

```
> me: cd /tmp/build && make clean && rm -rf $BUILD_DIR/cache && git reset --hard HEAD~3
> claude: let me vet this before running.
[MCP tool: vet_command_chain]
verdict: BLOCK
findings:
  [HIGH] DESTRUCTIVE.RM_RECURSIVE_VAR
    snippet: rm -rf $BUILD_DIR/cache
    description: rm -rf with environment variable — if the variable is empty
      or unset, this becomes `rm -rf /cache` (or `rm -rf /` depending on glob).
    recommendation: Replace with absolute path; or guard with [[ -n "$VAR" ]]
      check before the rm. (escalated MEDIUM→HIGH because chain mode.)
  [HIGH] GIT.RESET_HARD
    snippet: git reset --hard HEAD~3
    description: git reset --hard discards uncommitted local changes irreversibly.
    recommendation: Confirm there are no uncommitted changes you want to keep.
      (escalated MEDIUM→HIGH because chain mode.)

I'd recommend not running this as-is. Suggested rewrite:
  cd /tmp/build && make clean
  [[ -n "$BUILD_DIR" ]] && rm -rf "$BUILD_DIR/cache"
  # commit/stash any work, THEN: git reset --hard HEAD~3
```

---

## Roadmap

| Version | Scope | Status |
|---------|-------|--------|
| v1.0 | 24 rules across 8 families, bashlex AST + regex fallback, 3 tools / 3 demo resources / 2 prompts, GitHub Actions CI, PyPI Trusted Publishing, MCP Registry submission, 50+ tests | ✅ |
| v1.1 | Optional shellcheck-as-backend mode for users who want the higher-quality static analysis on top of the destructive-pattern detection; per-rule severity overrides via config; allowlist mode (specific commands always pass) | ⏳ |
| v1.2 | Sandboxed dry-run via [`maximumdust`](https://maximumdust.com/) container backend for ambiguous cases; provider-call sandbox to verify network endpoints before `curl | bash` is even attempted | ⏳ |
| v1.x | Webhook emit on BLOCK verdict; CI integration to gate AI-generated commit-stage hooks that contain destructive patterns | ⏳ |

---

## Need this adapted to your stack?

If your AI deployment uses a different shell harness, custom allowlists, language other than bash (PowerShell / fish / nushell), or specific compliance / auditing requirements — that's a **Custom MCP Build** engagement.

| Tier | Scope | Investment | Timeline |
|------|-------|------------|----------|
| Simple | Custom rule set + tuned severity for your domain (e.g., extra DB-specific patterns) | **$8,000–$10,000** | 1–2 weeks |
| Standard | Multi-shell support (PowerShell / fish / nushell parsers + rule packs) + allowlist persistence | **$15,000–$25,000** | 2–4 weeks |
| Complex | Sandboxed dry-run backend (container-isolated execution to validate ambiguous cases) + audit-trail + CI integration | **$30,000–$45,000** | 4–8 weeks |

**To engage:**
1. Email **temur@pixelette.tech** with subject `Custom MCP Build inquiry — bash-vet`
2. Include: 1-paragraph description of your stack + which tier
3. Reply within 2 business days with a 30-min discovery call slot

This server is part of a **production-AI infrastructure MCP suite** — companion to [silentwatch-mcp](https://github.com/temurkhan13/silentwatch-mcp) (cron silent-failure detection), [openclaw-health-mcp](https://github.com/temurkhan13/openclaw-health-mcp) (deployment health), [openclaw-cost-tracker-mcp](https://github.com/temurkhan13/openclaw-cost-tracker-mcp) (token-cost telemetry + 429 prediction), [openclaw-skill-vetter-mcp](https://github.com/temurkhan13/openclaw-skill-vetter-mcp) (skill security vetting), [openclaw-upgrade-orchestrator-mcp](https://github.com/temurkhan13/openclaw-upgrade-orchestrator-mcp) (upgrade safety), and [openclaw-output-vetter-mcp](https://github.com/temurkhan13/openclaw-output-vetter-mcp) (response grounding + swallowed-exception detection). Install all seven for full operational visibility.

---

## How this fits in the agent-shell-execution ecosystem

| Layer | Examples | Role |
|-------|----------|------|
| **Shell executor (existing MCP servers)** | [MCPShell](https://github.com/inercia/MCPShell), [mcp-shell](https://github.com/sonirico/mcp-shell), [mcp-bash](https://github.com/dvelasquezr/mcp-bash), Claude Code's built-in `Bash` tool | Run the command. Surface stdout/stderr to the agent. |
| **Vetter (this server)** | bash-vet-mcp | Vet the command **before** the executor runs it. Surface destructive patterns to the operator. |
| **Static analyzer (host-side)** | [shellcheck](https://www.shellcheck.net/) | Catch shell scripting bugs (unquoted variables, etc.). Different scope from destructive-pattern detection. |
| **Sandboxed dry-run (host-side)** | [Cisco DefenseClaw](https://www.cisco.com/), [Snyk Agent Scan](https://snyk.io/) | Container-isolate suspect commands; observe behavior before allowing live execution. Heavier, slower, optional. |

**Each layer is complementary.** A command can pass shellcheck (no scripting bugs), pass bash-vet-mcp (no destructive patterns), and still need sandboxing if the agent's intent is unclear. We're aiming at the failure mode that's the most pattern-matchable and the most preventable: agent emits a chain with a destructive fragment buried in it, and the operator approves the chain because the lede looks fine.

---

## Production AI audits

If you're running production AI and want an outside practitioner to score readiness, find the failure patterns already present (LLM-emitted shell commands being pattern P5.x in the catalog), and write the corrective-action plan:

| Tier | Scope | Investment | Timeline |
|------|-------|------------|----------|
| Audit Lite | One system, top-5 findings, written report | **$1,500** | 1 week |
| Audit Standard | Full audit, all 14 patterns, 5 Cs findings, 90-day follow-up | **$3,000** | 2–3 weeks |
| Audit + Workshop | Standard audit + 2-day team workshop + first monthly audit included | **$7,500** | 3–4 weeks |

Same email channel: **temur@pixelette.tech** with subject `AI audit inquiry`.

---

## Contributing

PRs welcome. The detection rules are intentionally pluggable — every rule is a tuple in the `_RULES` list in `src/bash_vet_mcp/scanner.py`. Adding a new rule is one tuple + one test case. The pattern-matching engine handles regex compilation, deduplication, severity scoring, and chain-mode escalation automatically.

Bug reports + feature requests: open a GitHub issue.

---

## License

MIT — see [LICENSE](./LICENSE).

---

## Related

- [Production-AI MCP Suite (Gumroad bundle)](https://temurah.gumroad.com/l/production-ai-mcp-suite) — this server plus 6 others in one curated bundle
- [silentwatch-mcp](https://github.com/temurkhan13/silentwatch-mcp) — cron silent-failure detection
- [openclaw-health-mcp](https://github.com/temurkhan13/openclaw-health-mcp) — deployment health
- [openclaw-cost-tracker-mcp](https://github.com/temurkhan13/openclaw-cost-tracker-mcp) — token-cost telemetry + 429 prediction
- [openclaw-skill-vetter-mcp](https://github.com/temurkhan13/openclaw-skill-vetter-mcp) — skill security vetting
- [openclaw-upgrade-orchestrator-mcp](https://github.com/temurkhan13/openclaw-upgrade-orchestrator-mcp) — upgrade safety + provider-side regression detection
- [openclaw-output-vetter-mcp](https://github.com/temurkhan13/openclaw-output-vetter-mcp) — response grounding + swallowed-exception detection
- [AI Production Discipline Framework](https://temurah.gumroad.com/l/ai-production-discipline-framework) — Notion template, $29 — the methodology these MCP tools implement
- [SPEC.md](./SPEC.md) — full server design

---

Built by [Temur Khan](https://www.notion.so/@temurkhan) — independent practitioner on production AI systems.
Contact: **temur@pixelette.tech**
