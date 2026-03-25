"""AWS WAF audit extension — extracts IP ranges from IPSetReferenceStatement rules."""

from __future__ import annotations

import re

from octorules.audit import RuleIPInfo
from octorules.extensions import register_audit_extension
from octorules.phases import PHASE_BY_NAME

from octorules_aws import AWS_PHASE_NAMES

# ARN pattern to extract IP Set name
_IPSET_ARN_RE = re.compile(r"^arn:aws[\w-]*:wafv2:[^:]+:[^:]+:[^/]+/ipset/([^/]+)/[^/]+$")


def _collect_ipset_arns(stmt: dict) -> list[str]:
    """Recursively collect IPSetReferenceStatement ARNs from a statement tree."""
    arns: list[str] = []
    for stype, inner in stmt.items():
        if stype == "IPSetReferenceStatement" and isinstance(inner, dict):
            arn = inner.get("ARN")
            if isinstance(arn, str):
                arns.append(arn)
        elif stype in ("AndStatement", "OrStatement") and isinstance(inner, dict):
            stmts = inner.get("Statements", [])
            if isinstance(stmts, list):
                for s in stmts:
                    if isinstance(s, dict):
                        arns.extend(_collect_ipset_arns(s))
        elif stype == "NotStatement" and isinstance(inner, dict):
            nested = inner.get("Statement")
            if isinstance(nested, dict):
                arns.extend(_collect_ipset_arns(nested))
        elif stype == "RateBasedStatement" and isinstance(inner, dict):
            sds = inner.get("ScopeDownStatement")
            if isinstance(sds, dict):
                arns.extend(_collect_ipset_arns(sds))
    return arns


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
