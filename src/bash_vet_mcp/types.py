"""Domain types for bash-vet-mcp.

All models are frozen pydantic — round-trip through JSON cleanly + serve as
MCP tool/resource response payloads.
"""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Severity ladder."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    """Top-level verdict for a vet operation."""

    CLEAN = "clean"
    """No findings."""
    CAUTION = "caution"
    """Only LOW findings — usually safe, document if intentional."""
    REVIEW = "review"
    """MEDIUM findings — sandbox-test or get a second pair of eyes."""
    BLOCK = "block"
    """HIGH or CRITICAL — refuse to run."""
    UNVERIFIED = "unverified"
    """Could not parse the input as bash; verdict undecidable."""


class CommandFinding(BaseModel):
    """One detected dangerous pattern in a shell command."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    """Stable rule identifier (e.g., `DESTRUCTIVE.RM_RECURSIVE`)."""
    severity: Severity
    pattern_kind: str
    """Human-friendly pattern category (e.g., `destructive-rm`, `package-glob-remove`)."""
    snippet: str
    """The offending fragment, truncated to 200 chars."""
    description: str
    """Plain-English explanation of why this is dangerous."""
    recommendation: str
    """What the operator should do — refuse, sandbox-test, document, or proceed with caveats."""
    position: int | None = None
    """Character offset in the original command, when available."""


class CommandVetReport(BaseModel):
    """Response for `vet_command` and `vet_command_chain`."""

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    risk_score: int
    """0–100. Severity-weighted: CRITICAL=40, HIGH=15, MEDIUM=5, LOW=1, INFO=0; capped at 100."""
    finding_count: int
    findings: list[CommandFinding]
    summary: str
    parse_error: str | None = None
    """Set if the input wasn't parseable as bash. Verdict will be UNVERIFIED."""


class DetectionRule(BaseModel):
    """A single detection rule, returned by `list_detection_rules`."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Severity
    pattern_kind: str
    description: str
    example_match: str
    """Example command fragment that this rule matches, for transparency."""


class DetectionRulesReport(BaseModel):
    """Response for `list_detection_rules`."""

    model_config = ConfigDict(frozen=True)

    total_rules: int
    rules: list[DetectionRule] = Field(default_factory=list)
