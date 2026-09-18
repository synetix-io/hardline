"""Turn findings into a grade an engineer will screenshot.

Two sub-scores, one grade. Exposure and evidence are different questions
(could they get in? / could you prove it?) and a router can be good at one
and terrible at the other. Any critical finding caps the grade at D.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .parser import Config
from .redact import redact
from .rules import Finding, _is_patched, run as run_rules

DEDUCT = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}


@dataclass
class Report:
    grade: str
    score: int
    exposure_score: int
    evidence_score: int
    version: str | None
    model: str | None
    identity: str | None
    patched: bool | None
    mikrotrick_exposed: bool
    counts: dict[str, int]
    findings: list[Finding]
    line_count: int
    rules_run: int
    ai_summary: str | None = None
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _axis_score(findings: list[Finding], axis: str) -> int:
    s = 100
    for f in findings:
        if f.axis == axis:
            s -= DEDUCT[f.severity]
    return max(0, s)


def _grade(score: int, has_critical: bool) -> str:
    g = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    if has_critical and g in ("A", "B", "C"):
        g = "D"
    return g


def build_report(cfg: Config) -> Report:
    findings = run_rules(cfg)
    for f in findings:
        f.evidence = [redact(l) for l in f.evidence]
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f.severity] += 1
    score = max(0, 100 - sum(DEDUCT[f.severity] for f in findings))
    return Report(
        grade=_grade(score, counts["critical"] > 0),
        score=score,
        exposure_score=_axis_score(findings, "exposure"),
        evidence_score=_axis_score(findings, "evidence"),
        version=cfg.version,
        model=cfg.model,
        identity=cfg.identity,
        patched=_is_patched(cfg.version),
        mikrotrick_exposed=any(f.id == "HL-001" for f in findings),
        counts=counts,
        findings=findings,
        line_count=cfg.line_count,
        rules_run=len(__import__("hardline.rules", fromlist=["RULES"]).RULES),
    )
