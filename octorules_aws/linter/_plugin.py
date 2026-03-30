"""AWS WAF lint plugin -- orchestrates all AWS-specific linter checks."""

from __future__ import annotations

import json
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.phases import PHASE_BY_NAME

from octorules_aws import AWS_PHASE_NAMES
from octorules_aws._statement_util import IPSET_ARN_RE as _IPSET_ARN_RE
from octorules_aws._statement_util import collect_ipset_arns as _collect_ipset_arns_from_statement
from octorules_aws.linter._rules import AWS_RULE_METAS
from octorules_aws.validate import _estimate_rule_wcu, validate_rules

# Re-export for backward compatibility
_AWS_PHASE_NAMES = AWS_PHASE_NAMES

AWS_RULE_IDS: frozenset[str] = frozenset(r.rule_id for r in AWS_RULE_METAS)

# Default Web ACL WCU limit
_WCU_LIMIT = 1500


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


def _check_wcu_capacity(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA340: Estimate total WCU across all AWS phases and warn if over limit.

    AWS WAF Web ACLs have a default capacity of 1500 WCU. This check sums
    the estimated WCU for all rules across all phases and warns if the total
    exceeds the limit.
    """
    total_wcu = 0
    # Track per-phase totals for the message
    phase_totals: list[tuple[str, int]] = []

    for phase_name, rules in rules_data.items():
        if phase_name not in _AWS_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        phase_wcu = 0
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            phase_wcu += _estimate_rule_wcu(rule)

        if phase_wcu > 0:
            phase_totals.append((phase_name, phase_wcu))
            total_wcu += phase_wcu

    if total_wcu > _WCU_LIMIT:
        # Use the first phase as the result phase
        result_phase = phase_totals[0][0] if phase_totals else ""
        ctx.add(
            LintResult(
                rule_id="WA340",
                severity=Severity.WARNING,
                message=(f"Estimated total WCU ({total_wcu}) exceeds Web ACL limit ({_WCU_LIMIT})"),
                phase=result_phase,
            )
        )


def _check_ipset_references(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA326: Check if IPSet ARNs reference IP Sets not in the lists section.

    Extracts the IP Set name from the ARN and checks if it appears in the
    lists section of the rules data. If not, emit an INFO suggestion.
    """
    # Collect list names from the lists section
    lists_section = rules_data.get("lists")
    if not isinstance(lists_section, list):
        # No lists section — nothing to compare against
        return

    list_names: set[str] = set()
    for lst in lists_section:
        if isinstance(lst, dict):
            name = lst.get("name")
            if isinstance(name, str):
                list_names.add(name)

    if not list_names:
        # Lists section exists but is empty — skip
        return

    # Collect all IPSet ARNs from all AWS phases
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
            if not isinstance(rule, dict):
                continue
            stmt = rule.get("Statement")
            if not isinstance(stmt, dict):
                continue

            ref = str(rule.get("ref", ""))
            arns = _collect_ipset_arns_from_statement(stmt)

            for arn in arns:
                match = _IPSET_ARN_RE.match(arn)
                if not match:
                    continue  # Not a valid ipset ARN — WA302 handles format
                ipset_name = match.group(1)
                if ipset_name not in list_names:
                    ctx.add(
                        LintResult(
                            rule_id="WA326",
                            severity=Severity.INFO,
                            message=(
                                f"IPSetReferenceStatement references '{ipset_name}'"
                                " which is not in the lists section. If this is a"
                                " managed IP Set, add it to lists for full lifecycle"
                                " management."
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="Statement.IPSetReferenceStatement.ARN",
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
    _check_wcu_capacity(rules_data, ctx)
    _check_ipset_references(rules_data, ctx)
