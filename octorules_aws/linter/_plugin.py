"""AWS WAF lint plugin -- orchestrates all AWS-specific linter checks."""

from __future__ import annotations

import json
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.phases import PHASE_BY_NAME

from octorules_aws.linter._rules import AWS_RULE_METAS
from octorules_aws.validate import validate_rules

# Phase names owned by this provider.
_AWS_PHASE_NAMES = frozenset(
    {
        "aws_waf_custom_rules",
        "aws_waf_rate_rules",
        "aws_waf_managed_rules",
        "aws_waf_rule_group_rules",
    }
)

AWS_RULE_IDS: frozenset[str] = frozenset(r.rule_id for r in AWS_RULE_METAS)


def _check_cross_phase_metrics(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA501: Detect duplicate MetricName values across AWS phases.

    AWS WAF requires MetricName to be unique across all rules in a Web ACL,
    not just within a single phase.
    """
    # Collect (MetricName -> list of (phase, ref)) across all AWS phases
    seen: dict[str, list[tuple[str, str]]] = {}
    for phase_name, rules in rules_data.items():
        if phase_name not in _AWS_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue
        for rule in rules:
            vc = rule.get("VisibilityConfig")
            if not isinstance(vc, dict):
                continue
            metric = vc.get("MetricName")
            if not isinstance(metric, str) or not metric:
                continue
            ref = str(rule.get("ref", ""))
            seen.setdefault(metric, []).append((phase_name, ref))

    for metric, locations in sorted(seen.items()):
        # Only flag if the SAME metric appears in more than one phase
        phases = {phase for phase, _ in locations}
        if len(phases) > 1:
            labels = [f"{ref} ({phase})" for phase, ref in locations]
            ctx.add(
                LintResult(
                    rule_id="WA501",
                    severity=Severity.ERROR,
                    message=(f"MetricName '{metric}' used across phases: " + ", ".join(labels)),
                    phase=locations[0][0],
                )
            )


def _check_duplicate_statements(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA520: Detect duplicate Statement dicts within each AWS phase.

    If two rules in the same phase have identical Statement dicts (after
    serializing to sorted JSON), warn about potential copy-paste error.
    """
    for phase_name, rules in rules_data.items():
        if phase_name not in _AWS_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        # Collect (serialized_statement -> list of refs)
        seen: dict[str, list[str]] = {}
        for rule in rules:
            stmt = rule.get("Statement")
            if not isinstance(stmt, dict):
                continue
            ref = str(rule.get("ref", ""))
            key = json.dumps(stmt, sort_keys=True)
            seen.setdefault(key, []).append(ref)

        for _, refs in sorted(seen.items()):
            if len(refs) > 1:
                ctx.add(
                    LintResult(
                        rule_id="WA520",
                        severity=Severity.WARNING,
                        message=(
                            f"Duplicate Statement in rules: {', '.join(refs)}"
                            " (possible copy-paste error)"
                        ),
                        phase=phase_name,
                    )
                )


def aws_lint(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all AWS WAF lint checks on a zone rules file."""
    for phase_name, rules in rules_data.items():
        if phase_name not in _AWS_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        results = validate_rules(rules, phase=phase_name)
        for result in results:
            ctx.add(result)

    # Cross-phase checks (run after per-phase validation)
    _check_cross_phase_metrics(rules_data, ctx)
    _check_duplicate_statements(rules_data, ctx)
