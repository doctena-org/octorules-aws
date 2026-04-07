"""Shared helpers for collecting ARNs from AWS WAF statement trees."""

import re

# ARN pattern to extract IP Set name
IPSET_ARN_RE = re.compile(r"^arn:aws[\w-]*:wafv2:[^:]+:[^:]+:[^/]+/ipset/([^/]+)/[^/]+$")

# ARN pattern to extract Regex Pattern Set name
REGEX_SET_ARN_RE = re.compile(
    r"^arn:aws[\w-]*:wafv2:[^:]+:[^:]+:[^/]+/regexpatternset/([^/]+)/[^/]+$"
)


def _collect_arns(stmt: dict, statement_type: str) -> list[str]:
    """Recursively collect ARNs for *statement_type* from a statement tree."""
    arns: list[str] = []
    for stype, inner in stmt.items():
        if stype == statement_type and isinstance(inner, dict):
            arn = inner.get("ARN")
            if isinstance(arn, str):
                arns.append(arn)
        elif stype in ("AndStatement", "OrStatement") and isinstance(inner, dict):
            stmts = inner.get("Statements", [])
            if isinstance(stmts, list):
                for s in stmts:
                    if isinstance(s, dict):
                        arns.extend(_collect_arns(s, statement_type))
        elif stype == "NotStatement" and isinstance(inner, dict):
            nested = inner.get("Statement")
            if isinstance(nested, dict):
                arns.extend(_collect_arns(nested, statement_type))
        elif stype == "RateBasedStatement" and isinstance(inner, dict):
            sds = inner.get("ScopeDownStatement")
            if isinstance(sds, dict):
                arns.extend(_collect_arns(sds, statement_type))
    return arns


def collect_ipset_arns(stmt: dict) -> list[str]:
    """Recursively collect IPSetReferenceStatement ARNs from a statement tree."""
    return _collect_arns(stmt, "IPSetReferenceStatement")


def collect_regex_set_arns(stmt: dict) -> list[str]:
    """Recursively collect RegexPatternSetReferenceStatement ARNs from a statement tree."""
    return _collect_arns(stmt, "RegexPatternSetReferenceStatement")
