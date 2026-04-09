"""Offline validation for AWS WAF rules."""

import re

from octorules.linter.engine import LintResult, Severity


def _result(
    rule_id: str,
    severity: Severity,
    message: str,
    phase: str,
    ref: str = "",
    *,
    field: str = "",
    suggestion: str = "",
) -> LintResult:
    """Create a LintResult with common defaults."""
    return LintResult(
        rule_id=rule_id,
        severity=severity,
        message=message,
        phase=phase,
        ref=ref,
        field=field,
        suggestion=suggestion,
    )


def _is_strict_int(val: object) -> bool:
    """True if *val* is an int but not a bool."""
    return isinstance(val, int) and not isinstance(val, bool)


_VALID_ACTIONS = frozenset({"Allow", "Block", "Count", "Captcha", "Challenge"})
_VALID_OVERRIDE_ACTIONS = frozenset({"None", "Count"})

_KNOWN_STATEMENT_TYPES = frozenset(
    {
        "AndStatement",
        "AsnMatchStatement",
        "ByteMatchStatement",
        "GeoMatchStatement",
        "IPSetReferenceStatement",
        "LabelMatchStatement",
        "ManagedRuleGroupStatement",
        "NotStatement",
        "OrStatement",
        "RateBasedStatement",
        "RegexMatchStatement",
        "RegexPatternSetReferenceStatement",
        "RuleGroupReferenceStatement",
        "SizeConstraintStatement",
        "SqliMatchStatement",
        "XssMatchStatement",
    }
)

_ARN_RE = re.compile(r"^arn:aws[\w-]*:wafv2:")
_NAME_RE = re.compile(r"^[\w-]+$")
_MAX_NAME_LEN = 128

_VISIBILITY_FIELDS: dict[str, type] = {
    "SampledRequestsEnabled": bool,
    "CloudWatchMetricsEnabled": bool,
    "MetricName": str,
}

_VALID_AGGREGATE_KEY_TYPES = frozenset({"IP", "FORWARDED_IP", "CUSTOM_KEYS", "CONSTANT"})
_MAX_RATE_LIMIT = 2_000_000_000
_MAX_CUSTOM_KEYS = 5
_VALID_EVALUATION_WINDOW_SECS = frozenset({60, 120, 300, 600})

# --- WA337: Valid custom aggregation key types --------------------------------
_VALID_CUSTOM_KEY_TYPES = frozenset(
    {
        "ASN",
        "Cookie",
        "ForwardedIP",
        "HTTPMethod",
        "Header",
        "IP",
        "JA3Fingerprint",
        "JA4Fingerprint",
        "LabelNamespace",
        "QueryArgument",
        "QueryString",
        "UriPath",
    }
)

# --- WA338/WA339: OversizeHandling and FallbackBehavior ----------------------
_VALID_OVERSIZE_HANDLING = frozenset({"CONTINUE", "MATCH", "NO_MATCH"})
_VALID_FALLBACK_BEHAVIORS = frozenset({"MATCH", "NO_MATCH"})
_MAX_TEXT_TRANSFORMATIONS = 10
_MAX_MATCH_PATTERN_ENTRIES = 5

# --- WA335/WA336: JsonBody enum values ----------------------------------------
_VALID_MATCH_SCOPES = frozenset({"ALL", "KEY", "VALUE"})
_VALID_INVALID_FALLBACK_BEHAVIORS = frozenset({"MATCH", "NO_MATCH", "EVALUATE_AS_STRING"})

_BYTE_MATCH_REQUIRED = (
    "FieldToMatch",
    "TextTransformations",
    "PositionalConstraint",
    "SearchString",
)
_COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")
_MAX_GEO_COUNTRY_CODES = 50
_MAX_NESTING_DEPTH = 20  # AWS WAF maximum statement nesting depth

# --- WA020: Valid top-level rule fields ------------------------------------
_VALID_RULE_FIELDS = frozenset(
    {
        "ref",
        "enabled",
        "Priority",
        "Action",
        "OverrideAction",
        "Statement",
        "VisibilityConfig",
        "RuleLabels",
    }
)

# --- WA314: Required fields per statement type -----------------------------
# Note: ByteMatchStatement is handled by _check_byte_match (WA312),
# GeoMatchStatement.CountryCodes is handled by _check_geo_match (WA313).
# They are excluded here to avoid double-reporting.
_STATEMENT_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "AsnMatchStatement": ("AsnList",),
    "IPSetReferenceStatement": ("ARN",),
    "RegexMatchStatement": ("RegexString", "FieldToMatch", "TextTransformations"),
    "RegexPatternSetReferenceStatement": ("ARN", "FieldToMatch", "TextTransformations"),
    "SizeConstraintStatement": (
        "FieldToMatch",
        "ComparisonOperator",
        "Size",
        "TextTransformations",
    ),
    "SqliMatchStatement": ("FieldToMatch", "TextTransformations"),
    "XssMatchStatement": ("FieldToMatch", "TextTransformations"),
    "LabelMatchStatement": ("Scope", "Key"),
    "ManagedRuleGroupStatement": ("VendorName", "Name"),
    "RuleGroupReferenceStatement": ("ARN",),
}

# --- WA315: Enum values ---------------------------------------------------
_VALID_POSITIONAL_CONSTRAINTS = frozenset(
    {"EXACTLY", "STARTS_WITH", "ENDS_WITH", "CONTAINS", "CONTAINS_WORD"}
)
_VALID_COMPARISON_OPERATORS = frozenset({"EQ", "NE", "LE", "LT", "GE", "GT"})
_VALID_LABEL_SCOPES = frozenset({"LABEL", "NAMESPACE"})
_VALID_SENSITIVITY_LEVELS = frozenset({"LOW", "HIGH"})

# --- WA316: FieldToMatch valid keys ----------------------------------------
_VALID_FIELD_TO_MATCH_KEYS = frozenset(
    {
        "AllQueryArguments",
        "Body",
        "Cookies",
        "HeaderOrder",
        "Headers",
        "JA3Fingerprint",
        "JA4Fingerprint",
        "JsonBody",
        "Method",
        "QueryString",
        "SingleHeader",
        "SingleQueryArgument",
        "UriFragment",
        "UriPath",
    }
)

# --- WA317: TextTransformation valid types ---------------------------------
_VALID_TEXT_TRANSFORM_TYPES = frozenset(
    {
        "NONE",
        "COMPRESS_WHITE_SPACE",
        "HTML_ENTITY_DECODE",
        "LOWERCASE",
        "CMD_LINE",
        "URL_DECODE",
        "BASE64_DECODE",
        "HEX_DECODE",
        "MD5",
        "REPLACE_COMMENTS",
        "ESCAPE_SEQ_DECODE",
        "SQL_HEX_DECODE",
        "CSS_DECODE",
        "JS_DECODE",
        "NORMALIZE_PATH",
        "NORMALIZE_PATH_WIN",
        "REMOVE_NULLS",
        "REPLACE_NULLS",
        "BASE64_DECODE_EXT",
        "URL_DECODE_UNI",
        "UTF8_TO_UNICODE",
    }
)

# --- WA307/WA308: Size limits -----------------------------------------------
_MAX_SEARCH_STRING_BYTES = 200  # AWS API: ByteMatchStatement.SearchString max 200 bytes
_MAX_REGEX_STRING_BYTES = 512  # AWS API: RegexMatchStatement.RegexString max 512 chars

# --- WA354-WA357: CustomResponse limits ------------------------------------
_MAX_CUSTOM_RESPONSE_BODY_BYTES = 4096
_MAX_CUSTOM_RESPONSE_HEADERS = 10
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# --- WA320: FieldToMatch types that inspect request content -----------------
# Only statement types that inspect request content can use JsonBody.
_JSONBODY_STATEMENT_TYPES = frozenset(
    {
        "ByteMatchStatement",
        "RegexMatchStatement",
        "RegexPatternSetReferenceStatement",
        "SizeConstraintStatement",
        "SqliMatchStatement",
        "XssMatchStatement",
    }
)

# --- WA352: Statement types that support OverrideAction --------------------
_GROUP_STATEMENT_TYPES = frozenset({"ManagedRuleGroupStatement", "RuleGroupReferenceStatement"})


def validate_rules(rules: list[dict], *, phase: str = "") -> list[LintResult]:
    """Validate normalized AWS WAF rules. Returns list of issues."""
    results: list[LintResult] = []
    seen_priorities: dict[int, list[str]] = {}
    seen_metrics: dict[str, list[str]] = {}
    seen_refs: dict[str, int] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            results.append(_result("WA023", Severity.ERROR, "Rule entry is not a dict", phase))
            continue

        ref = rule.get("ref", "")
        if not ref:
            results.append(
                _result(
                    rule_id="WA001",
                    severity=Severity.ERROR,
                    message="Rule missing 'ref'",
                    phase=phase,
                )
            )
        ref_str = str(ref)

        # WA022: duplicate ref
        if ref_str:
            seen_refs[ref_str] = seen_refs.get(ref_str, 0) + 1
            if seen_refs[ref_str] == 2:
                results.append(
                    _result(
                        rule_id="WA022",
                        severity=Severity.ERROR,
                        message=f"Duplicate ref {ref_str!r}",
                        phase=phase,
                        ref=ref_str,
                    )
                )

        _check_unknown_fields(rule, results, phase, ref_str)
        _check_enabled(rule, results, phase, ref_str)
        _check_ref_format(ref_str, results, phase)
        _check_priority(rule, results, phase, ref_str, seen_priorities)
        _check_visibility(rule, results, phase, ref_str, seen_metrics)
        _check_actions(rule, results, phase, ref_str)
        _check_action_params(rule, results, phase, ref_str)
        _check_rule_labels(rule, results, phase, ref_str)
        _check_statement(rule, results, phase, ref_str)
        _check_count_managed_group(rule, results, phase, ref_str)

    _check_duplicate_priorities(seen_priorities, results, phase)
    _check_priority_gaps(seen_priorities, results, phase)
    _check_duplicate_metrics(seen_metrics, results, phase)

    return results


# --- YAML structure checks (WA020-WA021) -----------------------------------
def _check_unknown_fields(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """WA020: Warn on unknown top-level rule fields."""
    unknown = set(rule) - _VALID_RULE_FIELDS
    for field in sorted(unknown):
        results.append(
            _result(
                rule_id="WA020",
                severity=Severity.WARNING,
                message=f"Unknown top-level rule field: '{field}'",
                phase=phase,
                ref=ref,
                field=field,
            )
        )


# --- Best-practice checks (WA600) -------------------------------------------
def _check_enabled(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """WA600: Inform when a rule has enabled: false."""
    if rule.get("enabled") is False:
        results.append(
            _result(
                rule_id="WA600",
                severity=Severity.INFO,
                message="Rule is disabled (enabled: false)",
                phase=phase,
                ref=ref,
                field="enabled",
                suggestion="Remove if no longer needed",
            )
        )


def _check_count_managed_group(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """WA602: Count action on ManagedRuleGroupStatement without ScopeDownStatement."""
    action = rule.get("Action")
    override_action = rule.get("OverrideAction")
    # Check both Action and OverrideAction — managed rule groups referenced
    # from a Web ACL use OverrideAction, while those in a Rule Group use Action.
    has_count = (isinstance(action, dict) and "Count" in action) or (
        isinstance(override_action, dict) and "Count" in override_action
    )
    if not has_count:
        return
    stmt = rule.get("Statement")
    if not isinstance(stmt, dict):
        return
    if "ManagedRuleGroupStatement" not in stmt:
        return
    mrg = stmt["ManagedRuleGroupStatement"]
    if isinstance(mrg, dict) and "ScopeDownStatement" in mrg:
        return
    field = (
        "OverrideAction"
        if (isinstance(override_action, dict) and "Count" in override_action)
        else "Action"
    )
    results.append(
        _result(
            rule_id="WA602",
            severity=Severity.INFO,
            message=(
                "Count action on ManagedRuleGroupStatement without"
                " ScopeDownStatement logs all traffic through the managed"
                " rule group — consider adding a ScopeDownStatement or"
                " switching to Block"
            ),
            phase=phase,
            ref=ref,
            field=field,
        )
    )


# --- Per-rule checks --------------------------------------------------------
def _check_ref_format(ref: str, results: list[LintResult], phase: str) -> None:
    """WA010: Rule name must be 1-128 alphanumeric/underscore/hyphen characters."""
    if not ref:
        return
    if len(ref) > _MAX_NAME_LEN:
        results.append(
            _result(
                rule_id="WA010",
                severity=Severity.ERROR,
                message=f"ref exceeds {_MAX_NAME_LEN} characters ({len(ref)})",
                phase=phase,
                ref=ref,
                field="ref",
            )
        )
    elif not _NAME_RE.fullmatch(ref):
        results.append(
            _result(
                rule_id="WA010",
                severity=Severity.ERROR,
                message="ref contains invalid characters (allowed: A-Z, a-z, 0-9, _, -)",
                phase=phase,
                ref=ref,
                field="ref",
            )
        )


def _check_priority(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    seen: dict[int, list[str]],
) -> None:
    if "Priority" not in rule:
        results.append(
            _result(
                rule_id="WA002",
                severity=Severity.ERROR,
                message="Rule missing 'Priority'",
                phase=phase,
                ref=ref,
            )
        )
        return
    pri = rule["Priority"]
    if not _is_strict_int(pri) or pri < 0:
        results.append(
            _result(
                rule_id="WA100",
                severity=Severity.ERROR,
                message=f"Priority must be a non-negative integer, got {pri!r}",
                phase=phase,
                ref=ref,
                field="Priority",
            )
        )
        return
    seen.setdefault(pri, []).append(ref)


def _check_visibility(
    rule: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    seen_metrics: dict[str, list[str]],
) -> None:
    """WA003/WA400/WA401/WA402 -- Validate VisibilityConfig fields and track metric names."""
    if "VisibilityConfig" not in rule:
        results.append(
            _result(
                rule_id="WA003",
                severity=Severity.ERROR,
                message="Rule missing 'VisibilityConfig'",
                phase=phase,
                ref=ref,
            )
        )
        return
    vc = rule["VisibilityConfig"]
    for fname, ftype in _VISIBILITY_FIELDS.items():
        if fname not in vc:
            results.append(
                _result(
                    rule_id="WA400",
                    severity=Severity.ERROR,
                    message=f"VisibilityConfig missing required field '{fname}'",
                    phase=phase,
                    ref=ref,
                    field=f"VisibilityConfig.{fname}",
                )
            )
        else:
            val = vc[fname]
            ok = isinstance(val, ftype)
            # int is a parent of bool in Python — reject bare ints for bool fields
            if ftype is bool and _is_strict_int(val):
                ok = False
            if not ok:
                results.append(
                    _result(
                        rule_id="WA401",
                        severity=Severity.ERROR,
                        message=(
                            f"VisibilityConfig.{fname} must be {ftype.__name__},"
                            f" got {type(val).__name__}"
                        ),
                        phase=phase,
                        ref=ref,
                        field=f"VisibilityConfig.{fname}",
                    )
                )
    mn = vc.get("MetricName")
    if isinstance(mn, str):
        if len(mn) > _MAX_NAME_LEN:
            results.append(
                _result(
                    rule_id="WA402",
                    severity=Severity.ERROR,
                    message=f"MetricName exceeds {_MAX_NAME_LEN} characters ({len(mn)})",
                    phase=phase,
                    ref=ref,
                    field="VisibilityConfig.MetricName",
                )
            )
        seen_metrics.setdefault(mn, []).append(ref)


def _check_actions(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    has_action = "Action" in rule
    has_override = "OverrideAction" in rule

    if not has_action and not has_override:
        results.append(
            _result(
                rule_id="WA004",
                severity=Severity.ERROR,
                message="Rule must have either 'Action' or 'OverrideAction'",
                phase=phase,
                ref=ref,
            )
        )
    if has_action and has_override:
        results.append(
            _result(
                rule_id="WA005",
                severity=Severity.ERROR,
                message="Rule must not have both 'Action' and 'OverrideAction'",
                phase=phase,
                ref=ref,
            )
        )

    if has_action and isinstance(rule["Action"], dict):
        invalid = set(rule["Action"]) - _VALID_ACTIONS
        if invalid:
            results.append(
                _result(
                    rule_id="WA200",
                    severity=Severity.ERROR,
                    message=f"Invalid Action type: {sorted(invalid)}",
                    phase=phase,
                    ref=ref,
                    field="Action",
                    suggestion=f"Valid types: {sorted(_VALID_ACTIONS)}",
                )
            )

    if has_override and isinstance(rule["OverrideAction"], dict):
        invalid = set(rule["OverrideAction"]) - _VALID_OVERRIDE_ACTIONS
        if invalid:
            results.append(
                _result(
                    rule_id="WA201",
                    severity=Severity.ERROR,
                    message=f"Invalid OverrideAction type: {sorted(invalid)}",
                    phase=phase,
                    ref=ref,
                    field="OverrideAction",
                    suggestion=f"Valid types: {sorted(_VALID_OVERRIDE_ACTIONS)}",
                )
            )


def _check_action_params(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """WA021/WA350/WA351/WA352/WA353/WA356/WA357 — Action parameter validation."""
    # WA021: Action/OverrideAction must be dict
    if "Action" in rule and not isinstance(rule["Action"], dict):
        results.append(
            _result(
                rule_id="WA021",
                severity=Severity.ERROR,
                message=f"Action must be a dict, got {type(rule['Action']).__name__}",
                phase=phase,
                ref=ref,
                field="Action",
            )
        )
    if "OverrideAction" in rule and not isinstance(rule["OverrideAction"], dict):
        results.append(
            _result(
                rule_id="WA021",
                severity=Severity.ERROR,
                message=(
                    f"OverrideAction must be a dict, got {type(rule['OverrideAction']).__name__}"
                ),
                phase=phase,
                ref=ref,
                field="OverrideAction",
            )
        )

    # WA350: Action must have exactly one key
    if "Action" in rule and isinstance(rule["Action"], dict):
        action = rule["Action"]
        if len(action) != 1:
            results.append(
                _result(
                    rule_id="WA350",
                    severity=Severity.ERROR,
                    message=(
                        f"Action must have exactly 1 key, found {len(action)}: {sorted(action)}"
                    ),
                    phase=phase,
                    ref=ref,
                    field="Action",
                )
            )
        # WA351: Unknown action type (complements WA200 — WA200 checks for
        # invalid keys among _all_ keys; WA351 flags individual unknown ones)
        for key in action:
            if key not in _VALID_ACTIONS:
                results.append(
                    _result(
                        rule_id="WA351",
                        severity=Severity.ERROR,
                        message=f"Unknown action type: '{key}'",
                        phase=phase,
                        ref=ref,
                        field="Action",
                        suggestion=f"Valid types: {sorted(_VALID_ACTIONS)}",
                    )
                )

        # WA353/WA354/WA355: CustomResponse validation
        for action_key in ("Block",):
            block = action.get(action_key)
            if isinstance(block, dict):
                cr = block.get("CustomResponse")
                if isinstance(cr, dict):
                    # WA353: CustomResponse status code
                    if "ResponseCode" in cr:
                        code = cr["ResponseCode"]
                        if (
                            not isinstance(code, int)
                            or isinstance(code, bool)
                            or code < 200
                            or code > 599
                        ):
                            results.append(
                                _result(
                                    rule_id="WA353",
                                    severity=Severity.ERROR,
                                    message=(
                                        f"CustomResponse.ResponseCode must be an integer"
                                        f" in 200-599, got {code!r}"
                                    ),
                                    phase=phase,
                                    ref=ref,
                                    field="Action.Block.CustomResponse.ResponseCode",
                                )
                            )

                    # WA354: CustomResponse body size limit
                    body = cr.get("ResponseBody")
                    if body is not None:
                        byte_len = len(str(body).encode("utf-8"))
                        if byte_len > _MAX_CUSTOM_RESPONSE_BODY_BYTES:
                            results.append(
                                _result(
                                    rule_id="WA354",
                                    severity=Severity.ERROR,
                                    message=(
                                        f"CustomResponse body exceeds"
                                        f" {_MAX_CUSTOM_RESPONSE_BODY_BYTES}-byte"
                                        f" limit ({byte_len} bytes)"
                                    ),
                                    phase=phase,
                                    ref=ref,
                                    field="Action.Block.CustomResponse.ResponseBody",
                                )
                            )

                    # WA355: CustomResponse header count limit
                    headers = cr.get("ResponseHeaders")
                    if isinstance(headers, list) and len(headers) > _MAX_CUSTOM_RESPONSE_HEADERS:
                        results.append(
                            _result(
                                rule_id="WA355",
                                severity=Severity.ERROR,
                                message=(
                                    f"CustomResponse exceeds"
                                    f" {_MAX_CUSTOM_RESPONSE_HEADERS} custom headers"
                                    f" ({len(headers)} found)"
                                ),
                                phase=phase,
                                ref=ref,
                                field="Action.Block.CustomResponse.ResponseHeaders",
                            )
                        )

                    # WA356: CustomResponse header name validation (RFC 7230 token)
                    if isinstance(headers, list):
                        for hdr in headers:
                            if not isinstance(hdr, dict):
                                continue
                            hdr_name = hdr.get("Name")
                            if isinstance(hdr_name, str) and not _HEADER_NAME_RE.match(hdr_name):
                                results.append(
                                    _result(
                                        rule_id="WA356",
                                        severity=Severity.ERROR,
                                        message=(
                                            f"CustomResponse header name {hdr_name!r}"
                                            f" is not a valid RFC 7230 token"
                                        ),
                                        phase=phase,
                                        ref=ref,
                                        field="Action.Block.CustomResponse.ResponseHeaders",
                                        suggestion=(
                                            "Header names must match"
                                            " ^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$"
                                        ),
                                    )
                                )

                    # WA357: CustomResponseBodyKey must be non-empty when present
                    body_key = cr.get("CustomResponseBodyKey")
                    if body_key is not None:
                        if not isinstance(body_key, str) or not body_key:
                            results.append(
                                _result(
                                    rule_id="WA357",
                                    severity=Severity.WARNING,
                                    message="CustomResponseBodyKey is empty",
                                    phase=phase,
                                    ref=ref,
                                    field="Action.Block.CustomResponse.CustomResponseBodyKey",
                                    suggestion=(
                                        "Provide a non-empty key referencing an entry"
                                        " in CustomResponseBodies"
                                    ),
                                )
                            )

    if "OverrideAction" in rule and isinstance(rule["OverrideAction"], dict):
        override = rule["OverrideAction"]
        if len(override) != 1:
            results.append(
                _result(
                    rule_id="WA350",
                    severity=Severity.ERROR,
                    message=(
                        f"OverrideAction must have exactly 1 key,"
                        f" found {len(override)}: {sorted(override)}"
                    ),
                    phase=phase,
                    ref=ref,
                    field="OverrideAction",
                )
            )

    # WA352: OverrideAction on non-group statement
    if "OverrideAction" in rule and isinstance(rule.get("OverrideAction"), dict):
        stmt = rule.get("Statement")
        if isinstance(stmt, dict):
            stmt_types = set(stmt.keys())
            if not (stmt_types & _GROUP_STATEMENT_TYPES):
                results.append(
                    _result(
                        rule_id="WA352",
                        severity=Severity.WARNING,
                        message=(
                            "OverrideAction is only valid with ManagedRuleGroupStatement"
                            " or RuleGroupReferenceStatement"
                        ),
                        phase=phase,
                        ref=ref,
                        field="OverrideAction",
                    )
                )


def _check_rule_labels(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """WA154: RuleLabels entries must not use reserved aws:/awswaf: namespaces."""
    labels = rule.get("RuleLabels")
    if not isinstance(labels, list):
        return
    for label in labels:
        if not isinstance(label, dict):
            continue
        name = label.get("Name")
        if isinstance(name, str) and (name.startswith("aws:") or name.startswith("awswaf:")):
            results.append(
                _result(
                    rule_id="WA154",
                    severity=Severity.ERROR,
                    message=f"RuleLabels entry '{name}' uses reserved namespace",
                    phase=phase,
                    ref=ref,
                    field="RuleLabels",
                )
            )


def _check_statement(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    if "Statement" not in rule:
        return
    stmt = rule["Statement"]
    if not isinstance(stmt, dict):
        return
    _validate_statement(stmt, results, phase, ref)


# --- Recursive statement validation -----------------------------------------
def _validate_statement(
    stmt: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
    depth: int = 0,
) -> None:
    """Validate a single statement dict and recurse into nested statements."""
    if depth > _MAX_NESTING_DEPTH:
        results.append(
            _result(
                rule_id="WA330",
                severity=Severity.ERROR,
                message=f"Statement nesting exceeds maximum depth of {_MAX_NESTING_DEPTH}",
                phase=phase,
                ref=ref,
                field="Statement",
            )
        )
        return
    keys = set(stmt)

    if len(keys) != 1:
        results.append(
            _result(
                rule_id="WA300",
                severity=Severity.ERROR,
                message=f"Statement must have exactly one type, found {len(keys)}: {sorted(keys)}",
                phase=phase,
                ref=ref,
                field="Statement",
            )
        )
        return

    for k in keys:
        if k not in _KNOWN_STATEMENT_TYPES:
            results.append(
                _result(
                    rule_id="WA301",
                    severity=Severity.WARNING,
                    message=f"Unknown statement type: {k}",
                    phase=phase,
                    ref=ref,
                    field="Statement",
                )
            )

    _check_arns(stmt, results, phase, ref)

    # Type-specific checks
    if "RateBasedStatement" in stmt:
        _check_rate_based(stmt["RateBasedStatement"], results, phase, ref, depth)
    if "ByteMatchStatement" in stmt:
        _check_byte_match(stmt["ByteMatchStatement"], results, phase, ref)
    if "GeoMatchStatement" in stmt:
        _check_geo_match(stmt["GeoMatchStatement"], results, phase, ref)

    # Deep validation (WA314-WA318)
    _check_statement_fields(stmt, results, phase, ref)

    # Heuristic patterns (WA341-WA343) — leaf-level only; recursion is
    # handled by _check_compound/_check_not below.
    _check_heuristic_patterns(stmt, results, phase, ref)

    # Recurse into compound statements
    if "AndStatement" in stmt:
        _check_compound(stmt["AndStatement"], "AndStatement", results, phase, ref, depth)
    if "OrStatement" in stmt:
        _check_compound(stmt["OrStatement"], "OrStatement", results, phase, ref, depth)
    if "NotStatement" in stmt:
        _check_not(stmt["NotStatement"], results, phase, ref, depth)


def _check_rate_based(
    rbs: object,
    results: list[LintResult],
    phase: str,
    ref: str,
    depth: int = 0,
) -> None:
    """WA303/WA304/WA305/WA306 — RateBasedStatement checks."""
    if not isinstance(rbs, dict):
        return

    if "Limit" not in rbs:
        results.append(
            _result(
                rule_id="WA303",
                severity=Severity.ERROR,
                message="RateBasedStatement requires a 'Limit' field",
                phase=phase,
                ref=ref,
                field="Statement.RateBasedStatement.Limit",
            )
        )
    else:
        lim = rbs["Limit"]
        if not _is_strict_int(lim):
            results.append(
                _result(
                    rule_id="WA303",
                    severity=Severity.ERROR,
                    message=f"RateBasedStatement.Limit must be an integer >= 10, got {lim!r}",
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.Limit",
                )
            )
        elif lim < 10:
            results.append(
                _result(
                    rule_id="WA303",
                    severity=Severity.ERROR,
                    message=f"RateBasedStatement.Limit must be an integer >= 10, got {lim!r}",
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.Limit",
                )
            )
        elif lim > _MAX_RATE_LIMIT:
            results.append(
                _result(
                    rule_id="WA306",
                    severity=Severity.ERROR,
                    message=(
                        f"RateBasedStatement.Limit must be <= {_MAX_RATE_LIMIT:,}, got {lim:,}"
                    ),
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.Limit",
                )
            )

    if "AggregateKeyType" not in rbs:
        results.append(
            _result(
                rule_id="WA304",
                severity=Severity.ERROR,
                message="RateBasedStatement missing 'AggregateKeyType'",
                phase=phase,
                ref=ref,
                field="Statement.RateBasedStatement.AggregateKeyType",
            )
        )
    else:
        akt = rbs["AggregateKeyType"]
        if akt not in _VALID_AGGREGATE_KEY_TYPES:
            results.append(
                _result(
                    rule_id="WA305",
                    severity=Severity.ERROR,
                    message=f"Invalid AggregateKeyType: {akt!r}",
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.AggregateKeyType",
                    suggestion=f"Valid values: {sorted(_VALID_AGGREGATE_KEY_TYPES)}",
                )
            )

    # WA303: EvaluationWindowSec validation (optional field)
    if "EvaluationWindowSec" in rbs:
        ews = rbs["EvaluationWindowSec"]
        if not _is_strict_int(ews) or ews not in _VALID_EVALUATION_WINDOW_SECS:
            results.append(
                _result(
                    rule_id="WA303",
                    severity=Severity.ERROR,
                    message=(
                        f"RateBasedStatement.EvaluationWindowSec must be one of"
                        f" {sorted(_VALID_EVALUATION_WINDOW_SECS)}, got {ews!r}"
                    ),
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.EvaluationWindowSec",
                )
            )

    # WA309: RateBasedStatement without ScopeDownStatement
    if "ScopeDownStatement" not in rbs:
        results.append(
            _result(
                rule_id="WA309",
                severity=Severity.WARNING,
                message="RateBasedStatement without ScopeDownStatement rate-limits all traffic",
                phase=phase,
                ref=ref,
                field="Statement.RateBasedStatement.ScopeDownStatement",
                suggestion="Add a ScopeDownStatement to limit which requests are counted",
            )
        )

    # Recurse into ScopeDownStatement
    sds = rbs.get("ScopeDownStatement")
    if isinstance(sds, dict):
        _validate_statement(sds, results, phase, ref, depth + 1)


def _check_byte_match(
    bms: object,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA312/WA307 — ByteMatchStatement required fields and size limits."""
    if not isinstance(bms, dict):
        return
    for field in _BYTE_MATCH_REQUIRED:
        if field not in bms:
            results.append(
                _result(
                    rule_id="WA312",
                    severity=Severity.ERROR,
                    message=f"ByteMatchStatement missing required field '{field}'",
                    phase=phase,
                    ref=ref,
                    field=f"Statement.ByteMatchStatement.{field}",
                )
            )

    # WA307: SearchString size limit
    search_string = bms.get("SearchString")
    if isinstance(search_string, str):
        byte_len = len(search_string.encode("utf-8"))
        if byte_len > _MAX_SEARCH_STRING_BYTES:
            results.append(
                _result(
                    rule_id="WA307",
                    severity=Severity.ERROR,
                    message=(
                        f"SearchString exceeds {_MAX_SEARCH_STRING_BYTES}-byte"
                        f" AWS WAF limit ({byte_len} bytes)"
                    ),
                    phase=phase,
                    ref=ref,
                    field="Statement.ByteMatchStatement.SearchString",
                )
            )


def _check_geo_match(
    gms: object,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA313/WA323 — GeoMatchStatement country code format and count."""
    if not isinstance(gms, dict):
        return
    codes = gms.get("CountryCodes", [])

    # WA323: CountryCodes list length
    if isinstance(codes, list) and len(codes) > _MAX_GEO_COUNTRY_CODES:
        results.append(
            _result(
                rule_id="WA323",
                severity=Severity.ERROR,
                message=(
                    f"GeoMatchStatement exceeds maximum of {_MAX_GEO_COUNTRY_CODES}"
                    f" country codes (got {len(codes)})"
                ),
                phase=phase,
                ref=ref,
                field="Statement.GeoMatchStatement.CountryCodes",
            )
        )

    for code in codes:
        if not isinstance(code, str) or not _COUNTRY_CODE_RE.fullmatch(code):
            results.append(
                _result(
                    rule_id="WA313",
                    severity=Severity.WARNING,
                    message=f"Invalid country code: {code!r} (expected ISO 3166-1 alpha-2)",
                    phase=phase,
                    ref=ref,
                    field="Statement.GeoMatchStatement.CountryCodes",
                )
            )


# --- Deep statement validation (WA314-WA318) --------------------------------
def _check_statement_fields(
    stmt: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA314-WA318: Deep validation of statement-type-specific fields."""
    for stype, inner in stmt.items():
        if not isinstance(inner, dict):
            continue

        # WA314: Required fields per statement type
        required = _STATEMENT_REQUIRED_FIELDS.get(stype)
        if required:
            for field in required:
                if field not in inner:
                    results.append(
                        _result(
                            rule_id="WA314",
                            severity=Severity.ERROR,
                            message=f"{stype} missing required field '{field}'",
                            phase=phase,
                            ref=ref,
                            field=f"Statement.{stype}.{field}",
                        )
                    )

        # WA319: Regex pattern validation
        if stype == "RegexMatchStatement":
            regex_str = inner.get("RegexString")
            if isinstance(regex_str, str):
                try:
                    re.compile(regex_str)
                except re.error as exc:
                    results.append(
                        _result(
                            rule_id="WA319",
                            severity=Severity.ERROR,
                            message=f"Invalid regex pattern: {exc}",
                            phase=phase,
                            ref=ref,
                            field="Statement.RegexMatchStatement.RegexString",
                            suggestion="Fix the regex syntax",
                        )
                    )

                # WA308: RegexString size limit
                byte_len = len(regex_str.encode("utf-8"))
                if byte_len > _MAX_REGEX_STRING_BYTES:
                    results.append(
                        _result(
                            rule_id="WA308",
                            severity=Severity.ERROR,
                            message=(
                                f"RegexString exceeds {_MAX_REGEX_STRING_BYTES}-byte"
                                f" AWS WAF limit ({byte_len} bytes)"
                            ),
                            phase=phase,
                            ref=ref,
                            field="Statement.RegexMatchStatement.RegexString",
                        )
                    )

        # WA334: SizeConstraintStatement.Size must be non-negative
        if stype == "SizeConstraintStatement" and "Size" in inner:
            size_val = inner["Size"]
            if _is_strict_int(size_val) and size_val < 0:
                results.append(
                    _result(
                        rule_id="WA334",
                        severity=Severity.ERROR,
                        message=(
                            f"SizeConstraintStatement.Size must be non-negative (got {size_val})"
                        ),
                        phase=phase,
                        ref=ref,
                        field=f"Statement.{stype}.Size",
                    )
                )

        # WA156: ManagedRuleGroupStatement version not pinned
        if stype == "ManagedRuleGroupStatement" and "Version" not in inner:
            results.append(
                _result(
                    rule_id="WA156",
                    severity=Severity.WARNING,
                    message="ManagedRuleGroupStatement version not pinned",
                    phase=phase,
                    ref=ref,
                    field="Statement.ManagedRuleGroupStatement.Version",
                    suggestion="Pin a version to avoid unexpected rule changes",
                )
            )

        # WA157/WA159-WA161: Managed rule group config validation
        if stype == "ManagedRuleGroupStatement":
            _check_managed_rule_group_config(inner, results, phase, ref)

        # WA315: Enum validation
        _check_statement_enums(stype, inner, results, phase, ref)

        # WA316: FieldToMatch validation
        if "FieldToMatch" in inner and isinstance(inner["FieldToMatch"], dict):
            _check_field_to_match(stype, inner["FieldToMatch"], results, phase, ref)

        # WA317: TextTransformations validation
        if "TextTransformations" in inner:
            _check_text_transformations(stype, inner["TextTransformations"], results, phase, ref)

        # WA318: RateBasedStatement conditional requirements
        if stype == "RateBasedStatement":
            _check_rate_based_conditional(inner, results, phase, ref)


def _check_managed_rule_group_config(
    inner: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA157/WA159-WA161: Validate ManagedRuleGroupStatement config fields."""
    _prefix = "Statement.ManagedRuleGroupStatement"

    # WA157: ExcludedRules must be a list of dicts with Name
    if "ExcludedRules" in inner:
        excluded = inner["ExcludedRules"]
        if not isinstance(excluded, list):
            results.append(
                _result(
                    rule_id="WA157",
                    severity=Severity.ERROR,
                    message="ExcludedRules must be a list",
                    phase=phase,
                    ref=ref,
                    field=f"{_prefix}.ExcludedRules",
                )
            )
        else:
            for idx, entry in enumerate(excluded):
                if not isinstance(entry, dict):
                    results.append(
                        _result(
                            rule_id="WA157",
                            severity=Severity.ERROR,
                            message=(
                                f"ExcludedRules[{idx}] must be a dict, got {type(entry).__name__}"
                            ),
                            phase=phase,
                            ref=ref,
                            field=f"{_prefix}.ExcludedRules[{idx}]",
                        )
                    )
                elif "Name" not in entry or not isinstance(entry.get("Name"), str):
                    results.append(
                        _result(
                            rule_id="WA157",
                            severity=Severity.ERROR,
                            message=f"ExcludedRules[{idx}] missing required 'Name' string field",
                            phase=phase,
                            ref=ref,
                            field=f"{_prefix}.ExcludedRules[{idx}].Name",
                        )
                    )

    # WA159: RuleActionOverrides entry missing Name or ActionToUse
    if "RuleActionOverrides" in inner:
        overrides = inner["RuleActionOverrides"]
        if isinstance(overrides, list):
            for idx, entry in enumerate(overrides):
                if not isinstance(entry, dict):
                    results.append(
                        _result(
                            rule_id="WA159",
                            severity=Severity.ERROR,
                            message=f"RuleActionOverrides[{idx}] must be a dict",
                            phase=phase,
                            ref=ref,
                            field=f"{_prefix}.RuleActionOverrides[{idx}]",
                        )
                    )
                    continue
                missing = []
                if "Name" not in entry or not isinstance(entry.get("Name"), str):
                    missing.append("Name")
                if "ActionToUse" not in entry or not isinstance(entry.get("ActionToUse"), dict):
                    missing.append("ActionToUse")
                if missing:
                    results.append(
                        _result(
                            rule_id="WA159",
                            severity=Severity.ERROR,
                            message=(
                                f"RuleActionOverrides[{idx}] missing required"
                                f" field(s): {', '.join(missing)}"
                            ),
                            phase=phase,
                            ref=ref,
                            field=f"{_prefix}.RuleActionOverrides[{idx}]",
                        )
                    )
                    continue

                # WA160: ActionToUse has invalid action
                action_to_use = entry["ActionToUse"]
                action_keys = set(action_to_use)
                if len(action_keys) != 1 or not action_keys.issubset(_VALID_ACTIONS):
                    results.append(
                        _result(
                            rule_id="WA160",
                            severity=Severity.ERROR,
                            message=(
                                f"RuleActionOverrides[{idx}].ActionToUse must contain"
                                f" exactly one of {sorted(_VALID_ACTIONS)},"
                                f" got {sorted(action_keys)}"
                            ),
                            phase=phase,
                            ref=ref,
                            field=f"{_prefix}.RuleActionOverrides[{idx}].ActionToUse",
                        )
                    )

    # WA161: Deprecated ExcludedRules — suggest migration
    if "ExcludedRules" in inner and "RuleActionOverrides" not in inner:
        results.append(
            _result(
                rule_id="WA161",
                severity=Severity.INFO,
                message="ExcludedRules is deprecated — use RuleActionOverrides instead",
                phase=phase,
                ref=ref,
                field=f"{_prefix}.ExcludedRules",
                suggestion="Migrate to RuleActionOverrides with ActionToUse: {Count: {}}",
            )
        )


def _check_statement_enums(
    stype: str,
    inner: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA315: Validate enum fields within statement types."""
    if stype == "ByteMatchStatement" and "PositionalConstraint" in inner:
        val = inner["PositionalConstraint"]
        if val not in _VALID_POSITIONAL_CONSTRAINTS:
            results.append(
                _result(
                    rule_id="WA315",
                    severity=Severity.ERROR,
                    message=f"Invalid PositionalConstraint: {val!r}",
                    phase=phase,
                    ref=ref,
                    field=f"Statement.{stype}.PositionalConstraint",
                    suggestion=f"Valid values: {sorted(_VALID_POSITIONAL_CONSTRAINTS)}",
                )
            )

    if stype == "SizeConstraintStatement" and "ComparisonOperator" in inner:
        val = inner["ComparisonOperator"]
        if val not in _VALID_COMPARISON_OPERATORS:
            results.append(
                _result(
                    rule_id="WA315",
                    severity=Severity.ERROR,
                    message=f"Invalid ComparisonOperator: {val!r}",
                    phase=phase,
                    ref=ref,
                    field=f"Statement.{stype}.ComparisonOperator",
                    suggestion=f"Valid values: {sorted(_VALID_COMPARISON_OPERATORS)}",
                )
            )

    if stype == "LabelMatchStatement" and "Scope" in inner:
        val = inner["Scope"]
        if val not in _VALID_LABEL_SCOPES:
            results.append(
                _result(
                    rule_id="WA315",
                    severity=Severity.ERROR,
                    message=f"Invalid LabelMatchStatement.Scope: {val!r}",
                    phase=phase,
                    ref=ref,
                    field=f"Statement.{stype}.Scope",
                    suggestion=f"Valid values: {sorted(_VALID_LABEL_SCOPES)}",
                )
            )

    if stype == "SqliMatchStatement" and "SensitivityLevel" in inner:
        val = inner["SensitivityLevel"]
        if val not in _VALID_SENSITIVITY_LEVELS:
            results.append(
                _result(
                    rule_id="WA315",
                    severity=Severity.ERROR,
                    message=f"Invalid SensitivityLevel: {val!r}",
                    phase=phase,
                    ref=ref,
                    field=f"Statement.{stype}.SensitivityLevel",
                    suggestion=f"Valid values: {sorted(_VALID_SENSITIVITY_LEVELS)}",
                )
            )


def _check_field_to_match(
    stype: str,
    ftm: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA316: FieldToMatch must have exactly 1 key from the valid set."""
    field_prefix = f"Statement.{stype}.FieldToMatch"

    if len(ftm) != 1:
        results.append(
            _result(
                rule_id="WA316",
                severity=Severity.ERROR,
                message=(f"FieldToMatch must have exactly 1 key, found {len(ftm)}: {sorted(ftm)}"),
                phase=phase,
                ref=ref,
                field=field_prefix,
            )
        )

    for key in ftm:
        if key not in _VALID_FIELD_TO_MATCH_KEYS:
            results.append(
                _result(
                    rule_id="WA316",
                    severity=Severity.ERROR,
                    message=f"Unknown FieldToMatch key: '{key}'",
                    phase=phase,
                    ref=ref,
                    field=field_prefix,
                    suggestion=f"Valid keys: {sorted(_VALID_FIELD_TO_MATCH_KEYS)}",
                )
            )

    # Nested requirements
    if "SingleHeader" in ftm:
        sh = ftm["SingleHeader"]
        if isinstance(sh, dict) and "Name" not in sh:
            results.append(
                _result(
                    rule_id="WA316",
                    severity=Severity.ERROR,
                    message="SingleHeader requires a 'Name' field",
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}.SingleHeader.Name",
                )
            )

    if "SingleQueryArgument" in ftm:
        sqa = ftm["SingleQueryArgument"]
        if isinstance(sqa, dict) and "Name" not in sqa:
            results.append(
                _result(
                    rule_id="WA316",
                    severity=Severity.ERROR,
                    message="SingleQueryArgument requires a 'Name' field",
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}.SingleQueryArgument.Name",
                )
            )

    # WA325: Headers/Cookies MatchPattern limit
    for ftm_key in ("Headers", "Cookies"):
        if ftm_key in ftm:
            container = ftm[ftm_key]
            if isinstance(container, dict):
                mp = container.get("MatchPattern")
                if isinstance(mp, dict):
                    for pat_key in (
                        "IncludedHeaders",
                        "ExcludedHeaders",
                        "IncludedCookies",
                        "ExcludedCookies",
                    ):
                        pat_list = mp.get(pat_key)
                        if (
                            isinstance(pat_list, list)
                            and len(pat_list) > _MAX_MATCH_PATTERN_ENTRIES
                        ):
                            results.append(
                                _result(
                                    rule_id="WA325",
                                    severity=Severity.ERROR,
                                    message=(
                                        f"FieldToMatch {ftm_key} MatchPattern.{pat_key}"
                                        f" exceeds maximum of {_MAX_MATCH_PATTERN_ENTRIES}"
                                        f" patterns (got {len(pat_list)})"
                                    ),
                                    phase=phase,
                                    ref=ref,
                                    field=f"{field_prefix}.{ftm_key}.MatchPattern.{pat_key}",
                                )
                            )

    if "JsonBody" in ftm:
        jb = ftm["JsonBody"]
        if isinstance(jb, dict):
            for required_field in ("MatchScope", "InvalidFallbackBehavior"):
                if required_field not in jb:
                    results.append(
                        _result(
                            rule_id="WA316",
                            severity=Severity.ERROR,
                            message=f"JsonBody requires '{required_field}' field",
                            phase=phase,
                            ref=ref,
                            field=f"{field_prefix}.JsonBody.{required_field}",
                        )
                    )

            # WA335: JsonBody.MatchScope validation
            ms = jb.get("MatchScope")
            if isinstance(ms, str) and ms not in _VALID_MATCH_SCOPES:
                results.append(
                    _result(
                        rule_id="WA335",
                        severity=Severity.ERROR,
                        message=(
                            f"JsonBody.MatchScope must be one of:"
                            f" {', '.join(sorted(_VALID_MATCH_SCOPES))} (got {ms!r})"
                        ),
                        phase=phase,
                        ref=ref,
                        field=f"{field_prefix}.JsonBody.MatchScope",
                        suggestion=f"Valid values: {sorted(_VALID_MATCH_SCOPES)}",
                    )
                )

            # WA336: JsonBody.InvalidFallbackBehavior validation
            ifb = jb.get("InvalidFallbackBehavior")
            if isinstance(ifb, str) and ifb not in _VALID_INVALID_FALLBACK_BEHAVIORS:
                results.append(
                    _result(
                        rule_id="WA336",
                        severity=Severity.ERROR,
                        message=(
                            f"JsonBody.InvalidFallbackBehavior must be one of:"
                            f" {', '.join(sorted(_VALID_INVALID_FALLBACK_BEHAVIORS))}"
                            f" (got {ifb!r})"
                        ),
                        phase=phase,
                        ref=ref,
                        field=f"{field_prefix}.JsonBody.InvalidFallbackBehavior",
                        suggestion=f"Valid values: {sorted(_VALID_INVALID_FALLBACK_BEHAVIORS)}",
                    )
                )

    # WA320: FieldToMatch type incompatible with statement type
    if "JsonBody" in ftm and stype not in _JSONBODY_STATEMENT_TYPES:
        results.append(
            _result(
                rule_id="WA320",
                severity=Severity.WARNING,
                message=f"FieldToMatch type 'JsonBody' is not applicable to {stype}",
                phase=phase,
                ref=ref,
                field=field_prefix,
                suggestion=(f"JsonBody is only applicable to: {sorted(_JSONBODY_STATEMENT_TYPES)}"),
            )
        )

    # WA338: OversizeHandling validation (Body, JsonBody, Headers, Cookies, HeaderOrder)
    for ftm_key in ("Body", "JsonBody", "Headers", "Cookies", "HeaderOrder"):
        if ftm_key in ftm:
            container = ftm[ftm_key]
            if isinstance(container, dict):
                oh = container.get("OversizeHandling")
                if isinstance(oh, str) and oh not in _VALID_OVERSIZE_HANDLING:
                    results.append(
                        _result(
                            rule_id="WA338",
                            severity=Severity.ERROR,
                            message=(
                                f"FieldToMatch {ftm_key}.OversizeHandling must be one of:"
                                f" {', '.join(sorted(_VALID_OVERSIZE_HANDLING))} (got {oh!r})"
                            ),
                            phase=phase,
                            ref=ref,
                            field=f"{field_prefix}.{ftm_key}.OversizeHandling",
                            suggestion=f"Valid values: {sorted(_VALID_OVERSIZE_HANDLING)}",
                        )
                    )

    # WA339: FallbackBehavior validation (JA3Fingerprint, JA4Fingerprint, UriFragment)
    for ftm_key in ("JA3Fingerprint", "JA4Fingerprint", "UriFragment"):
        if ftm_key in ftm:
            container = ftm[ftm_key]
            if isinstance(container, dict):
                fb = container.get("FallbackBehavior")
                if isinstance(fb, str) and fb not in _VALID_FALLBACK_BEHAVIORS:
                    results.append(
                        _result(
                            rule_id="WA339",
                            severity=Severity.ERROR,
                            message=(
                                f"FieldToMatch {ftm_key}.FallbackBehavior must be one of:"
                                f" {', '.join(sorted(_VALID_FALLBACK_BEHAVIORS))} (got {fb!r})"
                            ),
                            phase=phase,
                            ref=ref,
                            field=f"{field_prefix}.{ftm_key}.FallbackBehavior",
                            suggestion=f"Valid values: {sorted(_VALID_FALLBACK_BEHAVIORS)}",
                        )
                    )

    # WA339: FallbackBehavior in ForwardedIPConfig (inside IPSetReferenceStatement etc.)
    # Note: ForwardedIPConfig is at inner level, not inside FieldToMatch, so it's
    # handled by _check_rate_based_conditional via ForwardedIPConfig check.
    # Here we only check FieldToMatch sub-keys.


def _check_text_transformations(
    stype: str,
    tt: object,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA317: TextTransformations must be a non-empty list with valid elements."""
    field_prefix = f"Statement.{stype}.TextTransformations"

    if not isinstance(tt, list):
        results.append(
            _result(
                rule_id="WA317",
                severity=Severity.ERROR,
                message=f"TextTransformations must be a list, got {type(tt).__name__}",
                phase=phase,
                ref=ref,
                field=field_prefix,
            )
        )
        return

    if len(tt) == 0:
        results.append(
            _result(
                rule_id="WA317",
                severity=Severity.ERROR,
                message="TextTransformations must not be empty",
                phase=phase,
                ref=ref,
                field=field_prefix,
            )
        )
        return

    # WA331: TextTransformations count limit
    if len(tt) > _MAX_TEXT_TRANSFORMATIONS:
        results.append(
            _result(
                rule_id="WA331",
                severity=Severity.ERROR,
                message=(
                    f"TextTransformations exceeds maximum of"
                    f" {_MAX_TEXT_TRANSFORMATIONS} per statement (got {len(tt)})"
                ),
                phase=phase,
                ref=ref,
                field=field_prefix,
            )
        )

    # WA332: Duplicate TextTransformation Priority
    seen_priorities: dict[int, int] = {}
    for i, elem in enumerate(tt):
        if isinstance(elem, dict):
            pri = elem.get("Priority")
            if _is_strict_int(pri):
                if pri in seen_priorities:
                    results.append(
                        _result(
                            rule_id="WA332",
                            severity=Severity.ERROR,
                            message=f"Duplicate TextTransformation Priority {pri}",
                            phase=phase,
                            ref=ref,
                            field=f"{field_prefix}[{i}].Priority",
                        )
                    )
                else:
                    seen_priorities[pri] = i

    for i, elem in enumerate(tt):
        if not isinstance(elem, dict):
            results.append(
                _result(
                    rule_id="WA317",
                    severity=Severity.ERROR,
                    message=f"TextTransformations[{i}] must be a dict, got {type(elem).__name__}",
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}[{i}]",
                )
            )
            continue
        if "Priority" not in elem:
            results.append(
                _result(
                    rule_id="WA317",
                    severity=Severity.ERROR,
                    message=f"TextTransformations[{i}] missing required field 'Priority'",
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}[{i}].Priority",
                )
            )
        elif not _is_strict_int(elem["Priority"]):
            results.append(
                _result(
                    rule_id="WA317",
                    severity=Severity.ERROR,
                    message=(
                        f"TextTransformations[{i}].Priority must be an int,"
                        f" got {type(elem['Priority']).__name__}"
                    ),
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}[{i}].Priority",
                )
            )
        if "Type" not in elem:
            results.append(
                _result(
                    rule_id="WA317",
                    severity=Severity.ERROR,
                    message=f"TextTransformations[{i}] missing required field 'Type'",
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}[{i}].Type",
                )
            )
        elif not isinstance(elem["Type"], str):
            results.append(
                _result(
                    rule_id="WA317",
                    severity=Severity.ERROR,
                    message=(
                        f"TextTransformations[{i}].Type must be a string,"
                        f" got {type(elem['Type']).__name__}"
                    ),
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}[{i}].Type",
                )
            )
        elif elem["Type"] not in _VALID_TEXT_TRANSFORM_TYPES:
            results.append(
                _result(
                    rule_id="WA317",
                    severity=Severity.ERROR,
                    message=f"Invalid TextTransformation type: {elem['Type']!r}",
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}[{i}].Type",
                    suggestion=f"Valid types: {sorted(_VALID_TEXT_TRANSFORM_TYPES)}",
                )
            )


def _check_rate_based_conditional(
    inner: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA318: RateBasedStatement conditional requirements."""
    akt = inner.get("AggregateKeyType")

    if akt == "CUSTOM_KEYS":
        custom_keys = inner.get("CustomKeys")
        if not isinstance(custom_keys, list) or len(custom_keys) == 0:
            results.append(
                _result(
                    rule_id="WA318",
                    severity=Severity.ERROR,
                    message=(
                        "RateBasedStatement with AggregateKeyType=CUSTOM_KEYS"
                        " requires non-empty 'CustomKeys' list"
                    ),
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.CustomKeys",
                )
            )
        elif isinstance(custom_keys, list) and len(custom_keys) > _MAX_CUSTOM_KEYS:
            results.append(
                _result(
                    rule_id="WA324",
                    severity=Severity.ERROR,
                    message=(
                        f"RateBasedStatement.CustomKeys exceeds maximum"
                        f" of {_MAX_CUSTOM_KEYS} (got {len(custom_keys)})"
                    ),
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.CustomKeys",
                )
            )

        # WA337: Validate individual CustomKeys entry types
        if isinstance(custom_keys, list):
            for idx, entry in enumerate(custom_keys):
                if not isinstance(entry, dict):
                    continue
                entry_keys = set(entry)
                if len(entry_keys) == 1:
                    key_type = next(iter(entry_keys))
                    if key_type not in _VALID_CUSTOM_KEY_TYPES:
                        results.append(
                            _result(
                                rule_id="WA337",
                                severity=Severity.ERROR,
                                message=(f"CustomKeys[{idx}] has invalid type '{key_type}'"),
                                phase=phase,
                                ref=ref,
                                field=f"Statement.RateBasedStatement.CustomKeys[{idx}]",
                                suggestion=(f"Valid types: {sorted(_VALID_CUSTOM_KEY_TYPES)}"),
                            )
                        )

    if akt == "FORWARDED_IP":
        if "ForwardedIPConfig" not in inner:
            results.append(
                _result(
                    rule_id="WA318",
                    severity=Severity.ERROR,
                    message=(
                        "RateBasedStatement with AggregateKeyType=FORWARDED_IP"
                        " requires 'ForwardedIPConfig'"
                    ),
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.ForwardedIPConfig",
                )
            )

    # WA339: FallbackBehavior in ForwardedIPConfig
    fip_config = inner.get("ForwardedIPConfig")
    if isinstance(fip_config, dict):
        fb = fip_config.get("FallbackBehavior")
        if isinstance(fb, str) and fb not in _VALID_FALLBACK_BEHAVIORS:
            results.append(
                _result(
                    rule_id="WA339",
                    severity=Severity.ERROR,
                    message=(
                        f"ForwardedIPConfig.FallbackBehavior must be one of:"
                        f" {', '.join(sorted(_VALID_FALLBACK_BEHAVIORS))} (got {fb!r})"
                    ),
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.ForwardedIPConfig.FallbackBehavior",
                    suggestion=f"Valid values: {sorted(_VALID_FALLBACK_BEHAVIORS)}",
                )
            )


def _check_compound(
    inner: object,
    name: str,
    results: list[LintResult],
    phase: str,
    ref: str,
    depth: int = 0,
) -> None:
    """WA310 — And/OrStatement must have 2-10 nested statements."""
    if not isinstance(inner, dict):
        return
    stmts = inner.get("Statements", [])
    if not isinstance(stmts, list):
        return
    if len(stmts) < 2:
        results.append(
            _result(
                rule_id="WA310",
                severity=Severity.ERROR,
                message=f"{name} must have at least 2 nested statements, found {len(stmts)}",
                phase=phase,
                ref=ref,
                field=f"Statement.{name}.Statements",
            )
        )
    elif len(stmts) > 10:
        results.append(
            _result(
                rule_id="WA310",
                severity=Severity.ERROR,
                message=f"{name} exceeds maximum of 10 nested statements, found {len(stmts)}",
                phase=phase,
                ref=ref,
                field=f"Statement.{name}.Statements",
            )
        )
    for s in stmts:
        if isinstance(s, dict):
            _validate_statement(s, results, phase, ref, depth + 1)


def _check_not(
    inner: object,
    results: list[LintResult],
    phase: str,
    ref: str,
    depth: int = 0,
) -> None:
    """WA311/WA321 — NotStatement must have exactly 1 nested statement."""
    if not isinstance(inner, dict):
        return
    nested = inner.get("Statement")
    if nested is None:
        results.append(
            _result(
                rule_id="WA311",
                severity=Severity.ERROR,
                message="NotStatement missing required 'Statement' field",
                phase=phase,
                ref=ref,
                field="Statement.NotStatement.Statement",
            )
        )
    elif isinstance(nested, dict):
        # WA321: Redundant double negation
        if "NotStatement" in nested:
            results.append(
                _result(
                    rule_id="WA321",
                    severity=Severity.WARNING,
                    message="Redundant double negation — NotStatement wrapping NotStatement",
                    phase=phase,
                    ref=ref,
                    field="Statement.NotStatement",
                    suggestion="Remove both NotStatement wrappers to simplify",
                )
            )
        _validate_statement(nested, results, phase, ref, depth + 1)


# --- ARN checks -------------------------------------------------------------
def _check_arns(
    stmt: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """Warn on ARN strings that don't look like WAFv2 ARNs.

    Only inspects the immediate inner dict of *stmt* (e.g. the value inside
    ``{"IPSetReferenceStatement": {...}}``).  Does NOT recurse into nested
    dicts/lists — ``_validate_statement`` already handles compound children.
    """
    for inner in stmt.values():
        if not isinstance(inner, dict):
            continue
        for key, val in inner.items():
            if isinstance(val, str) and val.startswith("arn:") and not _ARN_RE.match(val):
                results.append(
                    _result(
                        rule_id="WA302",
                        severity=Severity.WARNING,
                        message=f"ARN doesn't match expected 'arn:aws*:wafv2:' format: {val}",
                        phase=phase,
                        ref=ref,
                        field=key,
                    )
                )


# --- WCU estimation (WA340) -------------------------------------------------

# Base WCU costs per statement type. Types with TextTransformations get
# +1 per transformation on top of the base.
_WCU_BASE: dict[str, int] = {
    "AsnMatchStatement": 1,
    "ByteMatchStatement": 2,
    "RegexMatchStatement": 3,
    "RegexPatternSetReferenceStatement": 5,
    "GeoMatchStatement": 2,
    "IPSetReferenceStatement": 1,
    "SizeConstraintStatement": 2,
    "SqliMatchStatement": 15,
    "XssMatchStatement": 15,
    "LabelMatchStatement": 1,
    "ManagedRuleGroupStatement": 100,  # varies, use 100 as estimate
    "RuleGroupReferenceStatement": 1,
}

# Statement types where each TextTransformation adds +1 WCU
_WCU_TEXT_TRANSFORM_TYPES = frozenset(
    {
        "ByteMatchStatement",
        "RegexMatchStatement",
        "RegexPatternSetReferenceStatement",
        "SizeConstraintStatement",
        "SqliMatchStatement",
        "XssMatchStatement",
    }
)


def _estimate_wcu(statement: dict) -> int:
    """Recursively estimate the WCU cost of a statement tree."""
    for stype, inner in statement.items():
        if stype == "AndStatement":
            if not isinstance(inner, dict):
                return 1
            stmts = inner.get("Statements", [])
            if not isinstance(stmts, list):
                return 1
            return 1 + sum(_estimate_wcu(s) for s in stmts if isinstance(s, dict))

        if stype == "OrStatement":
            if not isinstance(inner, dict):
                return 1
            stmts = inner.get("Statements", [])
            if not isinstance(stmts, list):
                return 1
            return 1 + sum(_estimate_wcu(s) for s in stmts if isinstance(s, dict))

        if stype == "NotStatement":
            if not isinstance(inner, dict):
                return 1
            nested = inner.get("Statement")
            if isinstance(nested, dict):
                return 1 + _estimate_wcu(nested)
            return 1

        if stype == "RateBasedStatement":
            if not isinstance(inner, dict):
                return 2
            cost = 2
            sds = inner.get("ScopeDownStatement")
            if isinstance(sds, dict):
                cost += _estimate_wcu(sds)
            return cost

        # Leaf statement
        base = _WCU_BASE.get(stype, 1)
        if stype in _WCU_TEXT_TRANSFORM_TYPES and isinstance(inner, dict):
            tts = inner.get("TextTransformations", [])
            if isinstance(tts, list):
                base += len(tts)
        return base

    # Empty statement dict
    return 0


def _estimate_rule_wcu(rule: dict) -> int:
    """Estimate WCU for a single rule (1 base + statement cost)."""
    stmt = rule.get("Statement")
    if not isinstance(stmt, dict):
        return 1
    return 1 + _estimate_wcu(stmt)


# --- Heuristic always-true/false/contradictory (WA341-WA343) ---------------

_GEO_ALWAYS_TRUE_THRESHOLD = 200


def _check_heuristic_patterns(
    stmt: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA341/WA342/WA343: Detect likely always-true, contradictory, and always-false patterns."""
    for stype, inner in stmt.items():
        if not isinstance(inner, dict):
            continue

        # WA341: GeoMatchStatement with >= 200 country codes (likely always true)
        if stype == "GeoMatchStatement":
            codes = inner.get("CountryCodes", [])
            if isinstance(codes, list) and len(codes) >= _GEO_ALWAYS_TRUE_THRESHOLD:
                results.append(
                    _result(
                        rule_id="WA341",
                        severity=Severity.WARNING,
                        message=(
                            f"GeoMatchStatement with {len(codes)} country codes"
                            " is likely always true (covers nearly all countries)"
                        ),
                        phase=phase,
                        ref=ref,
                        field="Statement.GeoMatchStatement.CountryCodes",
                        suggestion="Remove the GeoMatchStatement if all traffic should match",
                    )
                )

        # WA343: SizeConstraintStatement with Size=0 and ComparisonOperator=LT
        if stype == "SizeConstraintStatement":
            size_val = inner.get("Size")
            comp_op = inner.get("ComparisonOperator")
            if (
                isinstance(size_val, int)
                and not isinstance(size_val, bool)
                and size_val == 0
                and comp_op == "LT"
            ):
                results.append(
                    _result(
                        rule_id="WA343",
                        severity=Severity.WARNING,
                        message=(
                            "SizeConstraintStatement with Size=0 and ComparisonOperator=LT"
                            " is always false (size cannot be negative)"
                        ),
                        phase=phase,
                        ref=ref,
                        field="Statement.SizeConstraintStatement",
                        suggestion=("Use ComparisonOperator=EQ for empty, or GT for non-empty"),
                    )
                )

        # WA342: AndStatement with contradictory GeoMatch sets
        if stype == "AndStatement":
            stmts = inner.get("Statements", [])
            if isinstance(stmts, list):
                _check_contradictory_geo(stmts, results, phase, ref)

    # No explicit recursion here -- _validate_statement already recurses into
    # compound children via _check_compound/_check_not, which call
    # _validate_statement (and thus _check_heuristic_patterns) on each child.


def _check_contradictory_geo(
    stmts: list[dict],
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA342: Detect AndStatement with non-overlapping GeoMatch country code sets."""
    geo_sets: list[set[str]] = []
    for s in stmts:
        if not isinstance(s, dict):
            continue
        gms = s.get("GeoMatchStatement")
        if not isinstance(gms, dict):
            continue
        codes = gms.get("CountryCodes", [])
        if isinstance(codes, list) and codes:
            geo_sets.append({c for c in codes if isinstance(c, str)})

    # Check all pairs for empty intersection
    for i in range(len(geo_sets)):
        for j in range(i + 1, len(geo_sets)):
            if geo_sets[i] and geo_sets[j] and not (geo_sets[i] & geo_sets[j]):
                results.append(
                    _result(
                        rule_id="WA342",
                        severity=Severity.WARNING,
                        message=(
                            "AndStatement contains GeoMatchStatements with"
                            " non-overlapping country codes — no request can"
                            " match both conditions simultaneously"
                        ),
                        phase=phase,
                        ref=ref,
                        field="Statement.AndStatement",
                        suggestion="Use OrStatement to match traffic from either set",
                    )
                )
                return  # One warning per AndStatement is enough


# --- Cross-rule checks ------------------------------------------------------
def _check_duplicate_priorities(
    seen: dict[int, list[str]],
    results: list[LintResult],
    phase: str,
) -> None:
    for pri, refs in sorted(seen.items()):
        if len(refs) > 1:
            results.append(
                _result(
                    rule_id="WA101",
                    severity=Severity.ERROR,
                    message=f"Duplicate Priority {pri} in rules: {', '.join(refs)}",
                    phase=phase,
                )
            )


def _check_priority_gaps(
    seen_priorities: dict[int, list[str]],
    results: list[LintResult],
    phase: str,
) -> None:
    """WA102: Warn if any gap > 1 between sorted priority values."""
    pris = sorted(seen_priorities.keys())
    if len(pris) < 2:
        return
    for i in range(len(pris) - 1):
        if pris[i + 1] - pris[i] > 1:
            results.append(
                _result(
                    rule_id="WA102",
                    severity=Severity.INFO,
                    message=f"Priority gap between {pris[i]} and {pris[i + 1]}",
                    phase=phase,
                )
            )
            break  # Only warn once per phase


def _check_duplicate_metrics(
    seen: dict[str, list[str]],
    results: list[LintResult],
    phase: str,
) -> None:
    for name, refs in sorted(seen.items()):
        if len(refs) > 1:
            results.append(
                _result(
                    rule_id="WA500",
                    severity=Severity.ERROR,
                    message=f"Duplicate MetricName '{name}' in rules: {', '.join(refs)}",
                    phase=phase,
                )
            )
