"""AWS WAF lint rule definitions -- all AWS-specific RuleMeta instances."""

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
WA307 = RuleMeta("WA307", "statement", "SearchString exceeds 200-byte limit", Severity.ERROR)
WA308 = RuleMeta("WA308", "statement", "RegexString exceeds 512-byte limit", Severity.ERROR)
WA309 = RuleMeta(
    "WA309",
    "statement",
    "RateBasedStatement without ScopeDownStatement rate-limits all traffic",
    Severity.WARNING,
)
WA310 = RuleMeta(
    "WA310", "statement", "And/OrStatement must have 2-10 nested statements", Severity.ERROR
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

# WA102: Non-contiguous priorities
WA102 = RuleMeta("WA102", "priority", "Non-contiguous rule priorities", Severity.INFO)

# WA022: Duplicate ref
WA022 = RuleMeta("WA022", "structure", "Duplicate ref within phase", Severity.ERROR)

# WA023-WA024: Type checks
WA023 = RuleMeta("WA023", "structure", "Rule entry is not a dict", Severity.ERROR)
WA024 = RuleMeta("WA024", "structure", "Phase value is not a list", Severity.ERROR)

# WA322: Non-dict in compound statement
WA322 = RuleMeta(
    "WA322", "statement", "Statement entry in And/OrStatement is not a dict", Severity.ERROR
)

# WA328: Empty SearchString
WA328 = RuleMeta("WA328", "statement", "ByteMatchStatement SearchString is empty", Severity.ERROR)

# WA323-WA325: Statement limit checks
WA323 = RuleMeta("WA323", "statement", "GeoMatchStatement exceeds 50 country codes", Severity.ERROR)
WA324 = RuleMeta(
    "WA324", "statement", "RateBasedStatement.CustomKeys exceeds maximum of 5", Severity.ERROR
)
WA325 = RuleMeta(
    "WA325",
    "statement",
    "FieldToMatch Headers/Cookies MatchPattern exceeds maximum of 5 patterns",
    Severity.ERROR,
)

# WA154: Reserved label namespace
WA154 = RuleMeta(
    "WA154", "structure", "RuleLabels uses reserved aws:/awswaf: namespace", Severity.ERROR
)

# WA156: Managed rule group version not pinned
WA156 = RuleMeta(
    "WA156", "statement", "ManagedRuleGroupStatement version not pinned", Severity.WARNING
)

# WA157-WA161: Managed rule group config validation
WA157 = RuleMeta(
    "WA157", "statement", "ExcludedRules must be a list of dicts with Name", Severity.ERROR
)
WA159 = RuleMeta(
    "WA159",
    "statement",
    "RuleActionOverrides entry missing Name or ActionToUse",
    Severity.ERROR,
)
WA160 = RuleMeta(
    "WA160", "statement", "RuleActionOverrides ActionToUse has invalid action", Severity.ERROR
)
WA161 = RuleMeta(
    "WA161",
    "statement",
    "Deprecated ExcludedRules — use RuleActionOverrides instead",
    Severity.INFO,
)

# WA330: Statement nesting depth
WA330 = RuleMeta("WA330", "statement", "Statement nesting exceeds maximum depth", Severity.ERROR)

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

# WA354-WA357: CustomResponse parameter limits
WA354 = RuleMeta("WA354", "action", "CustomResponse body exceeds 4,096 bytes", Severity.ERROR)
WA355 = RuleMeta("WA355", "action", "CustomResponse exceeds 10 custom headers", Severity.ERROR)
WA356 = RuleMeta("WA356", "action", "CustomResponse header name invalid", Severity.ERROR)
WA357 = RuleMeta("WA357", "action", "CustomResponseBodyKey is empty", Severity.WARNING)

# WA520: Cross-rule analysis
WA520 = RuleMeta(
    "WA520", "cross-rule", "Duplicate statement across rules in phase", Severity.WARNING
)

# WA158: IP set item count limit
WA158 = RuleMeta("WA158", "cross-rule", "IP set exceeds 10,000 address limit", Severity.WARNING)

# WA162: Reserved/bogon IP in IP set
WA162 = RuleMeta("WA162", "cross-rule", "Reserved/bogon IP address in IP set", Severity.WARNING)

# WA326: Cross-file ARN reference validation
WA326 = RuleMeta(
    "WA326",
    "cross-rule",
    "IPSetReferenceStatement references IP Set not in lists section",
    Severity.INFO,
)

# WA327: Cross-file regex pattern set ARN reference validation
WA327 = RuleMeta(
    "WA327",
    "cross-rule",
    "RegexPatternSetReferenceStatement references Regex Pattern Set not in lists section",
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

# WA600-WA602: Best practice
WA600 = RuleMeta("WA600", "best_practice", "Rule is disabled (enabled: false)", Severity.INFO)
WA601 = RuleMeta(
    "WA601",
    "best_practice",
    "Total rule count may exceed default Web ACL limit of 100",
    Severity.WARNING,
)
WA602 = RuleMeta(
    "WA602",
    "best_practice",
    "Count action on ManagedRuleGroupStatement logs all traffic",
    Severity.INFO,
)

# WA337: Invalid custom key type in CustomKeys
WA337 = RuleMeta("WA337", "statement", "Invalid custom key type in CustomKeys", Severity.ERROR)

# WA338: Invalid OversizeHandling value
WA338 = RuleMeta("WA338", "statement", "Invalid OversizeHandling value", Severity.ERROR)

# WA339: Invalid FallbackBehavior value
WA339 = RuleMeta("WA339", "statement", "Invalid FallbackBehavior value", Severity.ERROR)

# WA603: Unreachable rule after catch-all
WA603 = RuleMeta(
    "WA603",
    "cross-rule",
    "Rule likely unreachable after always-true terminating rule",
    Severity.WARNING,
)

AWS_RULE_METAS: list[RuleMeta] = [obj for obj in globals().values() if isinstance(obj, RuleMeta)]
