"""AWS WAF lint rule definitions -- all AWS-specific RuleMeta instances."""

from __future__ import annotations

from octorules.linter.engine import Severity
from octorules.linter.rules.registry import RuleMeta

WA001 = RuleMeta("WA001", "structure", "Rule missing 'ref'", Severity.ERROR)
WA010 = RuleMeta("WA010", "structure", "Invalid ref format", Severity.ERROR)
WA002 = RuleMeta("WA002", "structure", "Rule missing 'Priority'", Severity.ERROR)
WA100 = RuleMeta("WA100", "priority", "Priority must be a non-negative integer", Severity.ERROR)
WA101 = RuleMeta("WA101", "priority", "Duplicate Priority across rules", Severity.ERROR)
WA003 = RuleMeta("WA003", "structure", "Rule missing 'VisibilityConfig'", Severity.ERROR)
WA400 = RuleMeta("WA400", "visibility", "VisibilityConfig missing required field", Severity.ERROR)
WA401 = RuleMeta("WA401", "visibility", "VisibilityConfig field wrong type", Severity.ERROR)
WA402 = RuleMeta("WA402", "visibility", "MetricName exceeds 128 characters", Severity.ERROR)
WA500 = RuleMeta("WA500", "visibility", "Duplicate MetricName across rules", Severity.ERROR)
WA004 = RuleMeta("WA004", "action", "Rule missing both Action and OverrideAction", Severity.ERROR)
WA005 = RuleMeta("WA005", "action", "Rule has both Action and OverrideAction", Severity.ERROR)
WA200 = RuleMeta("WA200", "action", "Invalid Action type", Severity.ERROR)
WA201 = RuleMeta("WA201", "action", "Invalid OverrideAction type", Severity.ERROR)
WA300 = RuleMeta("WA300", "statement", "Statement must have exactly one type", Severity.ERROR)
WA301 = RuleMeta("WA301", "statement", "Unknown statement type", Severity.WARNING)
WA302 = RuleMeta("WA302", "statement", "ARN format mismatch", Severity.WARNING)
WA303 = RuleMeta("WA303", "statement", "RateBasedStatement.Limit invalid", Severity.ERROR)
WA304 = RuleMeta(
    "WA304", "statement", "RateBasedStatement missing AggregateKeyType", Severity.ERROR
)
WA305 = RuleMeta("WA305", "statement", "Invalid AggregateKeyType", Severity.ERROR)
WA306 = RuleMeta("WA306", "statement", "RateBasedStatement.Limit exceeds maximum", Severity.ERROR)
WA307 = RuleMeta("WA307", "statement", "SearchString exceeds 8192-byte limit", Severity.ERROR)
WA308 = RuleMeta("WA308", "statement", "RegexString exceeds 512-byte limit", Severity.ERROR)
WA309 = RuleMeta(
    "WA309",
    "statement",
    "RateBasedStatement without ScopeDownStatement rate-limits all traffic",
    Severity.WARNING,
)
WA310 = RuleMeta(
    "WA310", "statement", "And/OrStatement must have at least 2 nested statements", Severity.ERROR
)
WA311 = RuleMeta(
    "WA311", "statement", "NotStatement missing required 'Statement' field", Severity.ERROR
)
WA312 = RuleMeta("WA312", "statement", "ByteMatchStatement missing required field", Severity.ERROR)
WA313 = RuleMeta("WA313", "statement", "Invalid country code format", Severity.WARNING)
WA501 = RuleMeta("WA501", "visibility", "Duplicate MetricName across phases", Severity.ERROR)

# WA020-WA021: YAML structure checks
WA020 = RuleMeta("WA020", "structure", "Unknown top-level rule field", Severity.WARNING)
WA021 = RuleMeta("WA021", "structure", "Action/OverrideAction must be dict", Severity.ERROR)

# WA314-WA321: Statement deep validation
WA314 = RuleMeta("WA314", "statement", "Missing required field in statement type", Severity.ERROR)
WA315 = RuleMeta("WA315", "statement", "Invalid enum value in statement", Severity.ERROR)
WA316 = RuleMeta("WA316", "statement", "FieldToMatch validation error", Severity.ERROR)
WA317 = RuleMeta("WA317", "statement", "TextTransformations validation error", Severity.ERROR)
WA318 = RuleMeta("WA318", "statement", "RateBasedStatement conditional requirement", Severity.ERROR)
WA319 = RuleMeta(
    "WA319", "statement", "Invalid regex pattern in RegexMatchStatement", Severity.ERROR
)
WA320 = RuleMeta(
    "WA320", "statement", "FieldToMatch type incompatible with statement type", Severity.WARNING
)
WA321 = RuleMeta(
    "WA321",
    "statement",
    "Redundant double negation (NotStatement wrapping NotStatement)",
    Severity.WARNING,
)

# WA350-WA353: Action parameter validation
WA350 = RuleMeta("WA350", "action", "Action must have exactly one key", Severity.ERROR)
WA351 = RuleMeta("WA351", "action", "Unknown action type", Severity.ERROR)
WA352 = RuleMeta("WA352", "action", "OverrideAction on non-group statement", Severity.WARNING)
WA353 = RuleMeta("WA353", "action", "CustomResponse status code invalid", Severity.ERROR)

# WA022: Duplicate ref
WA022 = RuleMeta("WA022", "structure", "Duplicate ref within phase", Severity.ERROR)

# WA323-WA325: Statement limit checks
WA323 = RuleMeta("WA323", "statement", "GeoMatchStatement exceeds 25 country codes", Severity.ERROR)
WA324 = RuleMeta(
    "WA324", "statement", "RateBasedStatement.CustomKeys exceeds maximum of 5", Severity.ERROR
)
WA325 = RuleMeta(
    "WA325",
    "statement",
    "FieldToMatch Headers/Cookies MatchPattern exceeds maximum of 5 patterns",
    Severity.ERROR,
)

# WA331-WA332: TextTransformation limit checks
WA331 = RuleMeta(
    "WA331", "statement", "TextTransformations exceeds maximum of 10 per statement", Severity.ERROR
)
WA332 = RuleMeta("WA332", "statement", "Duplicate TextTransformation Priority", Severity.ERROR)

# WA334-WA336: Statement value validation
WA334 = RuleMeta(
    "WA334", "statement", "SizeConstraintStatement.Size must be non-negative", Severity.ERROR
)
WA335 = RuleMeta("WA335", "statement", "JsonBody.MatchScope invalid", Severity.ERROR)
WA336 = RuleMeta("WA336", "statement", "JsonBody.InvalidFallbackBehavior invalid", Severity.ERROR)

# WA520: Cross-rule analysis
WA520 = RuleMeta(
    "WA520", "cross-rule", "Duplicate statement across rules in phase", Severity.WARNING
)

# WA326: Cross-file ARN reference validation
WA326 = RuleMeta(
    "WA326",
    "cross-rule",
    "IPSetReferenceStatement references IP Set not in lists section",
    Severity.INFO,
)

# WA340: WCU capacity estimation
WA340 = RuleMeta(
    "WA340", "cross-rule", "Estimated total WCU exceeds Web ACL limit", Severity.WARNING
)

# WA341-WA343: Heuristic always-true/false/contradictory
WA341 = RuleMeta("WA341", "statement", "GeoMatchStatement likely always true", Severity.WARNING)
WA342 = RuleMeta(
    "WA342",
    "statement",
    "Contradictory AND conditions (non-overlapping GeoMatch sets)",
    Severity.WARNING,
)
WA343 = RuleMeta(
    "WA343",
    "statement",
    "Always-false pattern (SizeConstraint size < 0 is impossible)",
    Severity.WARNING,
)

# WA600: Best practice
WA600 = RuleMeta("WA600", "best_practice", "Rule is disabled (enabled: false)", Severity.INFO)

AWS_RULE_METAS: list[RuleMeta] = [obj for obj in globals().values() if isinstance(obj, RuleMeta)]
