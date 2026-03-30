"""AWS WAF audit extension — extracts IP ranges from IPSetReferenceStatement rules."""

from __future__ import annotations

from octorules.audit import RuleIPInfo
from octorules.extensions import register_audit_extension
from octorules.phases import PHASE_BY_NAME

from octorules_aws import AWS_PHASE_NAMES
from octorules_aws._statement_util import IPSET_ARN_RE as _IPSET_ARN_RE
from octorules_aws._statement_util import collect_ipset_arns as _collect_ipset_arns


def _extract_ips(rules_data: dict, phase_name: str) -> list[RuleIPInfo]:
    """Extract IP ranges from AWS WAF rules in *phase_name*.

    Populates ``list_refs`` with IPSet names extracted from ARNs.
    The core audit resolver expands these to actual IPs from the
    ``lists`` section.
    """
    if phase_name not in AWS_PHASE_NAMES:
        return []
    if phase_name not in PHASE_BY_NAME:
        return []

    rules = rules_data.get(phase_name)
    if not isinstance(rules, list):
        return []

    results: list[RuleIPInfo] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ref = str(rule.get("ref", ""))
        action_dict = rule.get("Action", {})
        action = ""
        if isinstance(action_dict, dict):
            # Action is {"Allow": {}} or {"Block": {}} etc.
            action = next(iter(action_dict), "")

        stmt = rule.get("Statement")
        if not isinstance(stmt, dict):
            continue

        arns = _collect_ipset_arns(stmt)
        list_refs: list[str] = []
        for arn in arns:
            match = _IPSET_ARN_RE.match(arn)
            if match:
                list_refs.append(match.group(1))

        if list_refs:
            results.append(
                RuleIPInfo(
                    zone_name="",  # Stamped by caller
                    phase_name=phase_name,
                    ref=ref,
                    action=action,
                    ip_ranges=[],
                    list_refs=list_refs,
                )
            )

    return results


def register_aws_audit() -> None:
    """Register the AWS WAF audit IP extractor."""
    register_audit_extension("aws_waf", _extract_ips)
