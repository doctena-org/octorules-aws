"""Shared helpers for collecting IPSet ARNs from AWS WAF statement trees."""

from __future__ import annotations

import re

# ARN pattern to extract IP Set name
IPSET_ARN_RE = re.compile(r"^arn:aws[\w-]*:wafv2:[^:]+:[^:]+:[^/]+/ipset/([^/]+)/[^/]+$")


def collect_ipset_arns(stmt: dict) -> list[str]:
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
                        arns.extend(collect_ipset_arns(s))
        elif stype == "NotStatement" and isinstance(inner, dict):
            nested = inner.get("Statement")
            if isinstance(nested, dict):
                arns.extend(collect_ipset_arns(nested))
        elif stype == "RateBasedStatement" and isinstance(inner, dict):
            sds = inner.get("ScopeDownStatement")
            if isinstance(sds, dict):
                arns.extend(collect_ipset_arns(sds))
    return arns
