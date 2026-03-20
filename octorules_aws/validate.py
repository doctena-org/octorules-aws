"""Offline validation for AWS WAF rules."""

from __future__ import annotations

import re

from octorules.linter.engine import LintResult, Severity

_VALID_ACTIONS = frozenset({"Allow", "Block", "Count", "Captcha", "Challenge"})
_VALID_OVERRIDE_ACTIONS = frozenset({"None", "Count"})

_KNOWN_STATEMENT_TYPES = frozenset(
    {
        "AndStatement",
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

_BYTE_MATCH_REQUIRED = (
    "FieldToMatch",
    "TextTransformations",
    "PositionalConstraint",
    "SearchString",
)
_COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")

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
        "Body",
        "QueryString",
        "UriPath",
        "SingleHeader",
        "Headers",
        "Cookies",
        "JsonBody",
        "Method",
        "AllQueryArguments",
        "SingleQueryArgument",
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

# --- WA352: Statement types that support OverrideAction --------------------
_GROUP_STATEMENT_TYPES = frozenset({"ManagedRuleGroupStatement", "RuleGroupReferenceStatement"})


def validate_rules(rules: list[dict], *, phase: str = "") -> list[LintResult]:
    """Validate normalized AWS WAF rules. Returns list of issues."""
    results: list[LintResult] = []
    seen_priorities: dict[int, list[str]] = {}
    seen_metrics: dict[str, list[str]] = {}
    seen_refs: dict[str, int] = {}

    for rule in rules:
        ref = rule.get("ref", "")
        if not ref:
            results.append(
                LintResult(
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
                    LintResult(
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
        _check_statement(rule, results, phase, ref_str)

    _check_duplicate_priorities(seen_priorities, results, phase)
    _check_duplicate_metrics(seen_metrics, results, phase)

    return results


# --- YAML structure checks (WA020–WA021) -----------------------------------


def _check_unknown_fields(rule: dict, results: list[LintResult], phase: str, ref: str) -> None:
    """WA020: Warn on unknown top-level rule fields."""
    unknown = set(rule) - _VALID_RULE_FIELDS
    for field in sorted(unknown):
        results.append(
            LintResult(
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
            LintResult(
                rule_id="WA600",
                severity=Severity.INFO,
                message="Rule is disabled (enabled: false)",
                phase=phase,
                ref=ref,
                field="enabled",
                suggestion="Remove if no longer needed",
            )
        )


# --- Per-rule checks --------------------------------------------------------


def _check_ref_format(ref: str, results: list[LintResult], phase: str) -> None:
    """WA010: Rule name must be 1-128 alphanumeric/underscore/hyphen characters."""
    if not ref:
        return
    if len(ref) > _MAX_NAME_LEN:
        results.append(
            LintResult(
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
            LintResult(
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
            LintResult(
                rule_id="WA002",
                severity=Severity.ERROR,
                message="Rule missing 'Priority'",
                phase=phase,
                ref=ref,
            )
        )
        return
    pri = rule["Priority"]
    if not isinstance(pri, int) or isinstance(pri, bool) or pri < 0:
        results.append(
            LintResult(
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
    if "VisibilityConfig" not in rule:
        results.append(
            LintResult(
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
                LintResult(
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
            if ftype is bool and isinstance(val, int) and not isinstance(val, bool):
                ok = False
            if not ok:
                results.append(
                    LintResult(
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
                LintResult(
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
            LintResult(
                rule_id="WA004",
                severity=Severity.ERROR,
                message="Rule must have either 'Action' or 'OverrideAction'",
                phase=phase,
                ref=ref,
            )
        )
    if has_action and has_override:
        results.append(
            LintResult(
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
                LintResult(
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
                LintResult(
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
    """WA021/WA350/WA351/WA352/WA353 — Action parameter validation."""
    # WA021: Action/OverrideAction must be dict
    if "Action" in rule and not isinstance(rule["Action"], dict):
        results.append(
            LintResult(
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
            LintResult(
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
                LintResult(
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
                    LintResult(
                        rule_id="WA351",
                        severity=Severity.ERROR,
                        message=f"Unknown action type: '{key}'",
                        phase=phase,
                        ref=ref,
                        field="Action",
                        suggestion=f"Valid types: {sorted(_VALID_ACTIONS)}",
                    )
                )

        # WA353: CustomResponse status code
        for action_key in ("Block",):
            block = action.get(action_key)
            if isinstance(block, dict):
                cr = block.get("CustomResponse")
                if isinstance(cr, dict) and "ResponseCode" in cr:
                    code = cr["ResponseCode"]
                    if (
                        not isinstance(code, int)
                        or isinstance(code, bool)
                        or code < 200
                        or code > 599
                    ):
                        results.append(
                            LintResult(
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

    if "OverrideAction" in rule and isinstance(rule["OverrideAction"], dict):
        override = rule["OverrideAction"]
        if len(override) != 1:
            results.append(
                LintResult(
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
                    LintResult(
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
) -> None:
    """Validate a single statement dict and recurse into nested statements."""
    keys = set(stmt)

    if len(keys) != 1:
        results.append(
            LintResult(
                rule_id="WA300",
                severity=Severity.ERROR,
                message=f"Statement must have exactly one type, found {len(keys)}: {sorted(keys)}",
                phase=phase,
                ref=ref,
                field="Statement",
            )
        )

    for k in keys:
        if k not in _KNOWN_STATEMENT_TYPES:
            results.append(
                LintResult(
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
        _check_rate_based(stmt["RateBasedStatement"], results, phase, ref)
    if "ByteMatchStatement" in stmt:
        _check_byte_match(stmt["ByteMatchStatement"], results, phase, ref)
    if "GeoMatchStatement" in stmt:
        _check_geo_match(stmt["GeoMatchStatement"], results, phase, ref)

    # Deep validation (WA314–WA318)
    _check_statement_fields(stmt, results, phase, ref)

    # Recurse into compound statements
    if "AndStatement" in stmt:
        _check_compound(stmt["AndStatement"], "AndStatement", results, phase, ref)
    if "OrStatement" in stmt:
        _check_compound(stmt["OrStatement"], "OrStatement", results, phase, ref)
    if "NotStatement" in stmt:
        _check_not(stmt["NotStatement"], results, phase, ref)


def _check_rate_based(
    rbs: object,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA303/WA304/WA305/WA306 — RateBasedStatement checks."""
    if not isinstance(rbs, dict):
        return

    if "Limit" in rbs:
        lim = rbs["Limit"]
        if not isinstance(lim, int) or isinstance(lim, bool):
            results.append(
                LintResult(
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
                LintResult(
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
                LintResult(
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
            LintResult(
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
                LintResult(
                    rule_id="WA305",
                    severity=Severity.ERROR,
                    message=f"Invalid AggregateKeyType: {akt!r}",
                    phase=phase,
                    ref=ref,
                    field="Statement.RateBasedStatement.AggregateKeyType",
                    suggestion=f"Valid values: {sorted(_VALID_AGGREGATE_KEY_TYPES)}",
                )
            )

    # Recurse into ScopeDownStatement
    sds = rbs.get("ScopeDownStatement")
    if isinstance(sds, dict):
        _validate_statement(sds, results, phase, ref)


def _check_byte_match(
    bms: object,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA312 — ByteMatchStatement required fields."""
    if not isinstance(bms, dict):
        return
    for field in _BYTE_MATCH_REQUIRED:
        if field not in bms:
            results.append(
                LintResult(
                    rule_id="WA312",
                    severity=Severity.ERROR,
                    message=f"ByteMatchStatement missing required field '{field}'",
                    phase=phase,
                    ref=ref,
                    field=f"Statement.ByteMatchStatement.{field}",
                )
            )


def _check_geo_match(
    gms: object,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA313 — GeoMatchStatement country code format."""
    if not isinstance(gms, dict):
        return
    for code in gms.get("CountryCodes", []):
        if not isinstance(code, str) or not _COUNTRY_CODE_RE.fullmatch(code):
            results.append(
                LintResult(
                    rule_id="WA313",
                    severity=Severity.WARNING,
                    message=f"Invalid country code: {code!r} (expected ISO 3166-1 alpha-2)",
                    phase=phase,
                    ref=ref,
                    field="Statement.GeoMatchStatement.CountryCodes",
                )
            )


# --- Deep statement validation (WA314–WA318) --------------------------------


def _check_statement_fields(
    stmt: dict,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA314–WA318: Deep validation of statement-type-specific fields."""
    for stype, inner in stmt.items():
        if not isinstance(inner, dict):
            continue

        # WA314: Required fields per statement type
        required = _STATEMENT_REQUIRED_FIELDS.get(stype)
        if required:
            for field in required:
                if field not in inner:
                    results.append(
                        LintResult(
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
                        LintResult(
                            rule_id="WA319",
                            severity=Severity.ERROR,
                            message=f"Invalid regex pattern: {exc}",
                            phase=phase,
                            ref=ref,
                            field="Statement.RegexMatchStatement.RegexString",
                            suggestion="Fix the regex syntax",
                        )
                    )

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
                LintResult(
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
                LintResult(
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
                LintResult(
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
                LintResult(
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
            LintResult(
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
                LintResult(
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
                LintResult(
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
                LintResult(
                    rule_id="WA316",
                    severity=Severity.ERROR,
                    message="SingleQueryArgument requires a 'Name' field",
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}.SingleQueryArgument.Name",
                )
            )

    if "JsonBody" in ftm:
        jb = ftm["JsonBody"]
        if isinstance(jb, dict):
            for required_field in ("MatchScope", "InvalidFallbackBehavior"):
                if required_field not in jb:
                    results.append(
                        LintResult(
                            rule_id="WA316",
                            severity=Severity.ERROR,
                            message=f"JsonBody requires '{required_field}' field",
                            phase=phase,
                            ref=ref,
                            field=f"{field_prefix}.JsonBody.{required_field}",
                        )
                    )


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
            LintResult(
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
            LintResult(
                rule_id="WA317",
                severity=Severity.ERROR,
                message="TextTransformations must not be empty",
                phase=phase,
                ref=ref,
                field=field_prefix,
            )
        )
        return

    for i, elem in enumerate(tt):
        if not isinstance(elem, dict):
            results.append(
                LintResult(
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
                LintResult(
                    rule_id="WA317",
                    severity=Severity.ERROR,
                    message=f"TextTransformations[{i}] missing required field 'Priority'",
                    phase=phase,
                    ref=ref,
                    field=f"{field_prefix}[{i}].Priority",
                )
            )
        elif not isinstance(elem["Priority"], int) or isinstance(elem["Priority"], bool):
            results.append(
                LintResult(
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
                LintResult(
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
                LintResult(
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
                LintResult(
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
                LintResult(
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

    if akt == "FORWARDED_IP":
        if "ForwardedIPConfig" not in inner:
            results.append(
                LintResult(
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


def _check_compound(
    inner: object,
    name: str,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA310 — And/OrStatement must have >= 2 nested statements."""
    if not isinstance(inner, dict):
        return
    stmts = inner.get("Statements", [])
    if not isinstance(stmts, list):
        return
    if len(stmts) < 2:
        results.append(
            LintResult(
                rule_id="WA310",
                severity=Severity.ERROR,
                message=f"{name} must have at least 2 nested statements, found {len(stmts)}",
                phase=phase,
                ref=ref,
                field=f"Statement.{name}.Statements",
            )
        )
    for s in stmts:
        if isinstance(s, dict):
            _validate_statement(s, results, phase, ref)


def _check_not(
    inner: object,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """WA311/WA321 — NotStatement must have exactly 1 nested statement."""
    if not isinstance(inner, dict):
        return
    nested = inner.get("Statement")
    if nested is None:
        results.append(
            LintResult(
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
                LintResult(
                    rule_id="WA321",
                    severity=Severity.WARNING,
                    message="Redundant double negation — NotStatement wrapping NotStatement",
                    phase=phase,
                    ref=ref,
                    field="Statement.NotStatement",
                    suggestion="Remove both NotStatement wrappers to simplify",
                )
            )
        _validate_statement(nested, results, phase, ref)


# --- ARN checks -------------------------------------------------------------


def _check_arns(
    obj: dict | list,
    results: list[LintResult],
    phase: str,
    ref: str,
) -> None:
    """Warn on ARN strings that don't look like WAFv2 ARNs."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, str) and val.startswith("arn:") and not _ARN_RE.match(val):
                results.append(
                    LintResult(
                        rule_id="WA302",
                        severity=Severity.WARNING,
                        message=f"ARN doesn't match expected 'arn:aws*:wafv2:' format: {val}",
                        phase=phase,
                        ref=ref,
                        field=key,
                    )
                )
            elif isinstance(val, (dict, list)):
                _check_arns(val, results, phase, ref)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _check_arns(item, results, phase, ref)


# --- Cross-rule checks ------------------------------------------------------


def _check_duplicate_priorities(
    seen: dict[int, list[str]],
    results: list[LintResult],
    phase: str,
) -> None:
    for pri, refs in sorted(seen.items()):
        if len(refs) > 1:
            results.append(
                LintResult(
                    rule_id="WA101",
                    severity=Severity.ERROR,
                    message=f"Duplicate Priority {pri} in rules: {', '.join(refs)}",
                    phase=phase,
                )
            )


def _check_duplicate_metrics(
    seen: dict[str, list[str]],
    results: list[LintResult],
    phase: str,
) -> None:
    for name, refs in sorted(seen.items()):
        if len(refs) > 1:
            results.append(
                LintResult(
                    rule_id="WA500",
                    severity=Severity.ERROR,
                    message=f"Duplicate MetricName '{name}' in rules: {', '.join(refs)}",
                    phase=phase,
                )
            )
