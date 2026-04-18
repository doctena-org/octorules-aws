"""AWS WAF lint plugin -- orchestrates all AWS-specific linter checks."""

import ipaddress
import json
from collections.abc import Iterable
from contextvars import ContextVar
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.phases import PHASE_BY_NAME
from octorules.reserved_ips import is_reserved

from octorules_aws import AWS_PHASE_NAMES
from octorules_aws._statement_util import IPSET_ARN_RE as _IPSET_ARN_RE
from octorules_aws._statement_util import REGEX_SET_ARN_RE as _REGEX_SET_ARN_RE
from octorules_aws._statement_util import collect_ipset_arns as _collect_ipset_arns_from_statement
from octorules_aws._statement_util import collect_regex_set_arns as _collect_regex_set_arns
from octorules_aws.validate import RULE_IDS as _validate_ids
from octorules_aws.validate import _estimate_rule_wcu, validate_rules

# Re-export for backward compatibility
_AWS_PHASE_NAMES = AWS_PHASE_NAMES

# Rule IDs emitted by cross-phase/cross-rule checks in this module.
_PLUGIN_RULE_IDS: frozenset[str] = frozenset(
    {
        "WA024",
        "WA158",
        "WA162",
        "WA163",
        "WA164",
        "WA326",
        "WA327",
        "WA340",
        "WA501",
        "WA520",
        "WA601",
        "WA603",
    }
)

_CATCH_ALL_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

AWS_RULE_IDS: frozenset[str] = _validate_ids | _PLUGIN_RULE_IDS

# Default Web ACL WCU limit.  Override via ``set_wcu_limit()`` for accounts
# with custom capacity (up to 5000 via AWS support).
_wcu_limit_var: ContextVar[int] = ContextVar("wcu_limit", default=1500)


def set_wcu_limit(limit: int) -> None:
    """Override the WCU limit used by the WA340 check.

    The default is 1500 (AWS WAF standard).  Call this from provider init
    if the user has configured a custom ``wcu_limit`` in their provider config.

    The value is stored in a :class:`contextvars.ContextVar` so that
    concurrent threads or async tasks each see their own limit.
    """
    _wcu_limit_var.set(limit)


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

    wcu_limit = _wcu_limit_var.get()
    if total_wcu > wcu_limit:
        # Use the first phase as the result phase
        result_phase = phase_totals[0][0] if phase_totals else ""
        ctx.add(
            LintResult(
                rule_id="WA340",
                severity=Severity.WARNING,
                message=(f"Estimated total WCU ({total_wcu}) exceeds Web ACL limit ({wcu_limit})"),
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


def _check_regex_set_references(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA327: Check if RegexPatternSet ARNs reference sets not in the lists section.

    Extracts the regex pattern set name from the ARN and checks if it appears
    in the lists section with kind=regex. If not, emit an INFO suggestion.
    """
    lists_section = rules_data.get("lists")
    if not isinstance(lists_section, list):
        return

    regex_list_names: set[str] = set()
    for lst in lists_section:
        if isinstance(lst, dict):
            name = lst.get("name")
            kind = lst.get("kind")
            if isinstance(name, str) and kind == "regex":
                regex_list_names.add(name)

    if not regex_list_names:
        # No regex lists defined -- skip (same logic as WA326 for IP sets)
        return

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
            arns = _collect_regex_set_arns(stmt)

            for arn in arns:
                match = _REGEX_SET_ARN_RE.match(arn)
                if not match:
                    continue  # Not a valid regex set ARN -- WA302 handles format
                set_name = match.group(1)
                if set_name not in regex_list_names:
                    ctx.add(
                        LintResult(
                            rule_id="WA327",
                            severity=Severity.INFO,
                            message=(
                                f"RegexPatternSetReferenceStatement references"
                                f" '{set_name}' which is not in the lists section"
                                " (kind: regex). If this is a managed Regex Pattern"
                                " Set, add it to lists for full lifecycle management."
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="Statement.RegexPatternSetReferenceStatement.ARN",
                        )
                    )


_DEFAULT_RULE_LIMIT = 100


def _check_rule_count(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA601: Warn if the total rule count across AWS phases exceeds 100.

    AWS Web ACLs have a default limit of 100 rules (extendable to 500 with
    AWS support).  This counts all rules across all AWS phases and warns
    when the total may exceed the default limit.
    """
    total = 0
    first_phase = ""
    for phase_name, rules in rules_data.items():
        if phase_name not in _AWS_PHASE_NAMES:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue
        count = sum(1 for r in rules if isinstance(r, dict))
        if count > 0 and not first_phase:
            first_phase = phase_name
        total += count

    if total > _DEFAULT_RULE_LIMIT:
        ctx.add(
            LintResult(
                rule_id="WA601",
                severity=Severity.WARNING,
                message=(
                    f"Total rule count ({total}) may exceed"
                    f" the default Web ACL limit of {_DEFAULT_RULE_LIMIT}"
                ),
                phase=first_phase,
            )
        )


_MAX_IPSET_ITEMS = 10_000


def _check_list_item_counts(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA158: Warn if any IP set in the lists section exceeds 10,000 items."""
    lists_section = rules_data.get("lists")
    if not isinstance(lists_section, list):
        return

    for lst in lists_section:
        if not isinstance(lst, dict):
            continue
        items = lst.get("items")
        if not isinstance(items, list):
            continue
        # Deduplicate: AWS WAF counts unique addresses.
        unique_count = len(set(str(i) for i in items))
        if unique_count > _MAX_IPSET_ITEMS:
            name = lst.get("name", "<unknown>")
            dup_note = ""
            if unique_count < len(items):
                dup_note = f" ({len(items)} total, {len(items) - unique_count} duplicates)"
            ctx.add(
                LintResult(
                    rule_id="WA158",
                    severity=Severity.WARNING,
                    message=(
                        f"IP set '{name}' has {unique_count} unique items{dup_note},"
                        f" exceeding the {_MAX_IPSET_ITEMS} address limit"
                    ),
                    phase="",
                )
            )


# Reserved/bogon network detection is provided by octorules.reserved_ips
# (single source of truth across providers; see core v0.26.0).


def _iter_ip_lists(
    rules_data: dict[str, Any],
) -> Iterable[tuple[str, list]]:
    """Yield (name, items) for each IP kind entry under ``lists``."""
    lists_section = rules_data.get("lists")
    if not isinstance(lists_section, list):
        return
    for lst in lists_section:
        if not isinstance(lst, dict):
            continue
        if lst.get("kind") != "ip":
            continue
        items = lst.get("items")
        if not isinstance(items, list):
            continue
        yield lst.get("name", "<unknown>"), items


def _check_list_reserved_ips(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA162: Warn if any IP set item in the lists section is a reserved/bogon address."""
    for name, items in _iter_ip_lists(rules_data):
        for item in items:
            item_str = str(item)
            desc = is_reserved(item_str)
            if desc:
                ctx.add(
                    LintResult(
                        rule_id="WA162",
                        severity=Severity.WARNING,
                        message=(
                            f"IP set '{name}' contains reserved/bogon address {item_str!r} ({desc})"
                        ),
                        phase="",
                    )
                )


def _check_list_catch_all(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA163: Warn if an IP set contains a catch-all CIDR (0.0.0.0/0 or ::/0)."""
    for name, items in _iter_ip_lists(rules_data):
        for item in items:
            item_str = str(item).strip()
            if item_str in _CATCH_ALL_CIDRS:
                ctx.add(
                    LintResult(
                        rule_id="WA163",
                        severity=Severity.WARNING,
                        message=(
                            f"IP set '{name}' contains catch-all CIDR {item_str!r}"
                            " which matches every address"
                        ),
                        phase="",
                    )
                )


def _check_list_ipset_overlap(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA164: Detect overlapping IP/CIDR entries within a single IP set.

    Uses a sweep-line algorithm (O(n log n)) — ported from CF478 in
    octorules-cloudflare v0.7.8.  Large IPSets (AWS allows up to 10,000
    entries per set) need efficient overlap detection to keep lint fast.
    """

    def _sweep(
        name: str,
        items: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]],
    ) -> None:
        # Sort by network address ascending, then prefix length ascending
        # (broadest first when addresses are equal).
        sorted_items = sorted(items, key=lambda x: (int(x[1].network_address), x[1].prefixlen))
        active: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for val, net in sorted_items:
            while active and int(active[-1][1].broadcast_address) < int(net.network_address):
                active.pop()
            if active:
                parent_val, _parent_net = active[-1]
                if val != parent_val:
                    ctx.add(
                        LintResult(
                            rule_id="WA164",
                            severity=Severity.WARNING,
                            message=(
                                f"IP set '{name}' has overlapping entries:"
                                f" {val!r} overlaps with {parent_val!r}"
                            ),
                            phase="",
                        )
                    )
            active.append((val, net))

    for name, items in _iter_ip_lists(rules_data):
        v4: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        v6: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for item in items:
            item_str = str(item).strip()
            if not item_str or item_str in _CATCH_ALL_CIDRS:
                # Catch-all is handled by WA163; bare 0/0 would dominate every
                # other entry and produce overlap noise.  Skip it here.
                continue
            try:
                net = ipaddress.ip_network(item_str, strict=False)
            except ValueError:
                continue  # syntactic errors are WA020's concern
            (v4 if net.version == 4 else v6).append((item_str, net))
        _sweep(name, v4)
        _sweep(name, v6)


# Terminating actions — these stop rule evaluation on match.
# Count is NOT terminating (it logs and continues to the next rule).
_TERMINATING_ACTIONS = frozenset({"Allow", "Block", "Captcha", "Challenge"})

# Threshold for GeoMatchStatement "likely always true" (matches WA341 heuristic).
_GEO_ALWAYS_TRUE_THRESHOLD = 200


def _is_likely_always_true(rule: dict) -> bool:
    """Heuristic: does this rule's Statement likely match all traffic?

    Reuses the same heuristic as WA341: GeoMatchStatement with >= 200
    country codes.  Future heuristics (e.g. IPSet with 0.0.0.0/0) can
    be added here.
    """
    stmt = rule.get("Statement", {})
    if not isinstance(stmt, dict):
        return False
    for stype, inner in stmt.items():
        if not isinstance(inner, dict):
            continue
        if stype == "GeoMatchStatement":
            codes = inner.get("CountryCodes", [])
            if isinstance(codes, list) and len(codes) >= _GEO_ALWAYS_TRUE_THRESHOLD:
                return True
    return False


def _check_unreachable_rules(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """WA603: Detect rules that are unreachable after a likely-always-true terminating rule.

    AWS WAF evaluates rules in Priority order and stops at the first
    matching terminating action (Block, Allow, Captcha, Challenge).
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

        # Sort by Priority (rules without valid priority are skipped)
        prioritized: list[tuple[int, dict]] = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            pri = rule.get("Priority")
            if isinstance(pri, int) and not isinstance(pri, bool) and pri >= 0:
                prioritized.append((pri, rule))
        prioritized.sort(key=lambda x: x[0])

        found_terminating = False
        terminating_ref = ""
        for _pri, rule in prioritized:
            ref = str(rule.get("ref", ""))
            enabled = rule.get("enabled", True)
            if not enabled:
                continue

            if found_terminating:
                ctx.add(
                    LintResult(
                        rule_id="WA603",
                        severity=Severity.WARNING,
                        message=(
                            f"Rule likely unreachable — preceded by always-true"
                            f" terminating rule {terminating_ref!r}"
                        ),
                        phase=phase_name,
                        ref=ref,
                    )
                )
                continue

            action = rule.get("Action", {})
            if isinstance(action, dict):
                action_type = next(iter(action), "")
            else:
                action_type = ""

            if action_type in _TERMINATING_ACTIONS and _is_likely_always_true(rule):
                found_terminating = True
                terminating_ref = ref


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
            ctx.add(
                LintResult(
                    rule_id="WA024",
                    severity=Severity.ERROR,
                    message=f"Phase '{phase_name}' value is not a list",
                    phase=phase_name,
                )
            )
            continue

        results = validate_rules(rules, phase=phase_name)
        for result in results:
            ctx.add(result)

    # Cross-phase checks (run after per-phase validation)
    _check_cross_phase_metrics(rules_data, ctx)
    _check_duplicate_statements(rules_data, ctx)
    _check_wcu_capacity(rules_data, ctx)
    _check_rule_count(rules_data, ctx)
    _check_ipset_references(rules_data, ctx)
    _check_regex_set_references(rules_data, ctx)
    _check_list_item_counts(rules_data, ctx)
    _check_list_reserved_ips(rules_data, ctx)
    _check_list_catch_all(rules_data, ctx)
    _check_list_ipset_overlap(rules_data, ctx)
    _check_unreachable_rules(rules_data, ctx)
