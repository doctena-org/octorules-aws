"""Tests for AWS WAF rule validation."""

from __future__ import annotations

import pytest
from octorules.linter.engine import LintResult

from octorules_aws.validate import validate_rules


def _rule(**overrides):
    """Build a minimal valid AWS WAF rule with overrides."""
    base = {
        "ref": "test-rule",
        "Priority": 0,
        "Action": {"Block": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "test-metric",
        },
        "Statement": {
            "ByteMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
                "SearchString": "bad",
            }
        },
    }
    base.update(overrides)
    return base


def _ids(results: list[LintResult]) -> list[str]:
    return [r.rule_id for r in results]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestValidRules:
    def test_no_errors(self):
        assert validate_rules([_rule()]) == []

    def test_empty_list(self):
        assert validate_rules([]) == []

    def test_phase_passed_through(self):
        r = _rule()
        del r["ref"]
        results = validate_rules([r], phase="aws_waf_custom_rules")
        assert results[0].phase == "aws_waf_custom_rules"

    def test_returns_lint_result_instances(self):
        r = _rule()
        del r["ref"]
        results = validate_rules([r])
        assert all(isinstance(r, LintResult) for r in results)


# ---------------------------------------------------------------------------
# WA001  Missing ref
# ---------------------------------------------------------------------------


class TestMissingRef:
    def test_wa001_missing_ref(self):
        r = _rule()
        del r["ref"]
        assert "WA001" in _ids(validate_rules([r]))

    def test_wa001_empty_ref(self):
        assert "WA001" in _ids(validate_rules([_rule(ref="")]))


# ---------------------------------------------------------------------------
# WA010  ref format
# ---------------------------------------------------------------------------


class TestDuplicateRef:
    def test_wa022_duplicate_ref(self):
        rules = [_rule(ref="dup"), _rule(ref="dup")]
        assert "WA022" in _ids(validate_rules(rules))

    def test_wa022_unique_refs_ok(self):
        rules = [_rule(ref="a"), _rule(ref="b")]
        assert "WA022" not in _ids(validate_rules(rules))

    def test_wa022_fires_once_for_triple(self):
        rules = [_rule(ref="dup"), _rule(ref="dup"), _rule(ref="dup")]
        wa022 = [r for r in validate_rules(rules) if r.rule_id == "WA022"]
        assert len(wa022) == 1

    def test_wa022_empty_ref_not_flagged(self):
        """Empty refs are caught by WA001, not WA022."""
        rules = [_rule(ref=""), _rule(ref="")]
        assert "WA022" not in _ids(validate_rules(rules))


class TestRefFormat:
    def test_wa010_too_long(self):
        assert "WA010" in _ids(validate_rules([_rule(ref="a" * 129)]))

    def test_wa010_max_length_ok(self):
        assert "WA010" not in _ids(validate_rules([_rule(ref="a" * 128)]))

    def test_wa010_invalid_chars_space(self):
        assert "WA010" in _ids(validate_rules([_rule(ref="bad name")]))

    def test_wa010_invalid_chars_dot(self):
        assert "WA010" in _ids(validate_rules([_rule(ref="bad.name")]))

    def test_wa010_valid_chars(self):
        assert "WA010" not in _ids(validate_rules([_rule(ref="My_Rule-01")]))

    def test_wa010_not_emitted_for_empty_ref(self):
        # WA001 covers empty ref; WA010 should not also fire
        ids = _ids(validate_rules([_rule(ref="")]))
        assert "WA001" in ids
        assert "WA010" not in ids


# ---------------------------------------------------------------------------
# WA002  Missing Priority
# ---------------------------------------------------------------------------


class TestMissingPriority:
    def test_wa002_missing_priority(self):
        r = _rule()
        del r["Priority"]
        assert "WA002" in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# WA100-WA101  Priority checks
# ---------------------------------------------------------------------------


class TestPriority:
    def test_wa100_negative(self):
        assert "WA100" in _ids(validate_rules([_rule(Priority=-1)]))

    def test_wa100_not_integer(self):
        assert "WA100" in _ids(validate_rules([_rule(Priority="5")]))

    def test_wa100_bool_rejected(self):
        assert "WA100" in _ids(validate_rules([_rule(Priority=True)]))

    def test_wa100_float_rejected(self):
        assert "WA100" in _ids(validate_rules([_rule(Priority=1.5)]))

    def test_wa100_zero_accepted(self):
        assert "WA100" not in _ids(validate_rules([_rule(Priority=0)]))

    def test_wa101_duplicate(self):
        a = _rule(ref="a", Priority=1)
        b = _rule(ref="b", Priority=1)
        b["VisibilityConfig"]["MetricName"] = "other"
        assert "WA101" in _ids(validate_rules([a, b]))

    def test_wa101_no_false_positive(self):
        a = _rule(ref="a", Priority=1)
        b = _rule(ref="b", Priority=2)
        b["VisibilityConfig"]["MetricName"] = "other"
        assert "WA101" not in _ids(validate_rules([a, b]))


# ---------------------------------------------------------------------------
# WA003  Missing VisibilityConfig
# ---------------------------------------------------------------------------


class TestMissingVisibility:
    def test_wa003_missing_visibility_config(self):
        r = _rule()
        del r["VisibilityConfig"]
        assert "WA003" in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# WA004-WA005  Action / OverrideAction presence
# ---------------------------------------------------------------------------


class TestActionPresence:
    def test_wa004_missing_both_actions(self):
        r = _rule()
        del r["Action"]
        assert "WA004" in _ids(validate_rules([r]))

    def test_wa005_both_actions_present(self):
        r = _rule(OverrideAction={"Count": {}})
        assert "WA005" in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# WA200-WA201  Action type checks
# ---------------------------------------------------------------------------


class TestActions:
    @pytest.mark.parametrize("action_key", ["Allow", "Block", "Count", "Captcha", "Challenge"])
    def test_wa200_valid_actions(self, action_key):
        assert "WA200" not in _ids(validate_rules([_rule(Action={action_key: {}})]))

    def test_wa200_invalid_action(self):
        assert "WA200" in _ids(validate_rules([_rule(Action={"Drop": {}})]))

    @pytest.mark.parametrize("override_key", ["None", "Count"])
    def test_wa201_valid_override(self, override_key):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {override_key: {}}
        assert "WA201" not in _ids(validate_rules([r]))

    def test_wa201_invalid_override(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"Block": {}}
        assert "WA201" in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# WA300-WA306  Statement checks
# ---------------------------------------------------------------------------


class TestStatement:
    def test_wa300_empty_statement(self):
        assert "WA300" in _ids(validate_rules([_rule(Statement={})]))

    def test_wa300_multiple_types(self):
        stmt = {"ByteMatchStatement": {}, "GeoMatchStatement": {}}
        assert "WA300" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa300_exactly_one_ok(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": ["US"]}}
        assert "WA300" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa301_unknown_type(self):
        assert "WA301" in _ids(validate_rules([_rule(Statement={"FooStatement": {}})]))

    @pytest.mark.parametrize(
        "stype",
        [
            "ByteMatchStatement",
            "GeoMatchStatement",
            "IPSetReferenceStatement",
            "RateBasedStatement",
            "SqliMatchStatement",
            "XssMatchStatement",
            "ManagedRuleGroupStatement",
            "RuleGroupReferenceStatement",
        ],
    )
    def test_wa301_known_types(self, stype):
        assert "WA301" not in _ids(
            validate_rules([_rule(Statement={stype: {"AggregateKeyType": "IP", "Limit": 100}})])
        )

    def test_wa302_invalid_arn(self):
        stmt = {"IPSetReferenceStatement": {"ARN": "arn:gcp:storage:us:12345:bucket"}}
        assert "WA302" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa302_valid_arn(self):
        stmt = {
            "IPSetReferenceStatement": {
                "ARN": "arn:aws:wafv2:us-east-1:123456789:regional/ipset/my-ip-set/abc"
            }
        }
        assert "WA302" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa302_nested_arn(self):
        stmt = {
            "NotStatement": {
                "Statement": {"IPSetReferenceStatement": {"ARN": "arn:azure:something:bad"}}
            }
        }
        assert "WA302" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa302_non_arn_string_ignored(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "hello",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA302" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa303_rate_limit_below_10(self):
        stmt = {"RateBasedStatement": {"Limit": 5, "AggregateKeyType": "IP"}}
        assert "WA303" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa303_rate_limit_not_integer(self):
        stmt = {"RateBasedStatement": {"Limit": "200", "AggregateKeyType": "IP"}}
        assert "WA303" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa303_rate_limit_bool(self):
        stmt = {"RateBasedStatement": {"Limit": True, "AggregateKeyType": "IP"}}
        assert "WA303" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa303_rate_limit_exactly_10(self):
        stmt = {"RateBasedStatement": {"Limit": 10, "AggregateKeyType": "IP"}}
        assert "WA303" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa304_missing_aggregate_key_type(self):
        stmt = {"RateBasedStatement": {"Limit": 200}}
        assert "WA304" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_valid_rate_based_statement(self):
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "IP"}}
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA303" not in _ids(results)
        assert "WA304" not in _ids(results)


# ---------------------------------------------------------------------------
# WA305  AggregateKeyType enum
# ---------------------------------------------------------------------------


class TestAggregateKeyType:
    @pytest.mark.parametrize("akt", ["IP", "FORWARDED_IP", "CUSTOM_KEYS", "CONSTANT"])
    def test_wa305_valid(self, akt):
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": akt}}
        assert "WA305" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa305_invalid(self):
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "HEADER"}}
        assert "WA305" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA306  Limit upper bound
# ---------------------------------------------------------------------------


class TestLimitUpperBound:
    def test_wa306_exceeds_max(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 2_000_000_001,
                "AggregateKeyType": "IP",
            }
        }
        assert "WA306" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa306_at_max(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 2_000_000_000,
                "AggregateKeyType": "IP",
            }
        }
        assert "WA306" not in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA310  And/Or min 2 statements
# ---------------------------------------------------------------------------


class TestCompoundStatements:
    def test_wa310_and_zero_statements(self):
        stmt = {"AndStatement": {"Statements": []}}
        assert "WA310" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa310_and_one_statement(self):
        stmt = {"AndStatement": {"Statements": [{"ByteMatchStatement": {}}]}}
        assert "WA310" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa310_and_two_ok(self):
        stmt = {
            "AndStatement": {
                "Statements": [
                    {"ByteMatchStatement": {}},
                    {"GeoMatchStatement": {}},
                ]
            }
        }
        assert "WA310" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa310_or_one_statement(self):
        stmt = {"OrStatement": {"Statements": [{"ByteMatchStatement": {}}]}}
        assert "WA310" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa310_or_two_ok(self):
        stmt = {
            "OrStatement": {
                "Statements": [
                    {"ByteMatchStatement": {}},
                    {"GeoMatchStatement": {}},
                ]
            }
        }
        assert "WA310" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_nested_and_inside_or(self):
        """Recursive validation: And inside Or still checked."""
        stmt = {
            "OrStatement": {
                "Statements": [
                    {"AndStatement": {"Statements": []}},
                    {"ByteMatchStatement": {}},
                ]
            }
        }
        assert "WA310" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA311  NotStatement exactly 1
# ---------------------------------------------------------------------------


class TestNotStatement:
    def test_wa311_missing_statement(self):
        stmt = {"NotStatement": {}}
        assert "WA311" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa311_valid(self):
        stmt = {"NotStatement": {"Statement": {"GeoMatchStatement": {}}}}
        assert "WA311" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa311_recursive(self):
        """NotStatement inside AndStatement still validated."""
        stmt = {
            "AndStatement": {
                "Statements": [
                    {"NotStatement": {}},
                    {"ByteMatchStatement": {}},
                ]
            }
        }
        assert "WA311" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA312  ByteMatchStatement required fields
# ---------------------------------------------------------------------------


class TestByteMatch:
    def test_wa312_missing_field_to_match(self):
        stmt = {
            "ByteMatchStatement": {
                "TextTransformations": [{}],
                "PositionalConstraint": "CONTAINS",
                "SearchString": "x",
            }
        }
        assert "WA312" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa312_missing_text_transformations(self):
        stmt = {
            "ByteMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "PositionalConstraint": "CONTAINS",
                "SearchString": "x",
            }
        }
        assert "WA312" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa312_missing_positional_constraint(self):
        stmt = {
            "ByteMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{}],
                "SearchString": "x",
            }
        }
        assert "WA312" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa312_missing_search_string(self):
        stmt = {
            "ByteMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA312" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa312_all_present(self):
        # _rule() default has all required fields
        assert "WA312" not in _ids(validate_rules([_rule()]))

    def test_wa312_empty_byte_match(self):
        stmt = {"ByteMatchStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        wa312_count = _ids(results).count("WA312")
        assert wa312_count == 4  # All 4 fields missing

    def test_wa312_nested_byte_match(self):
        """ByteMatchStatement inside NotStatement still validated."""
        stmt = {"NotStatement": {"Statement": {"ByteMatchStatement": {}}}}
        assert "WA312" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA313  GeoMatchStatement country codes
# ---------------------------------------------------------------------------


class TestGeoMatch:
    def test_wa313_valid_codes(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": ["US", "DE", "FR"]}}
        assert "WA313" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa313_three_letter_code(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": ["USA"]}}
        assert "WA313" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa313_lowercase(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": ["us"]}}
        assert "WA313" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa313_numeric(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": ["12"]}}
        assert "WA313" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa313_non_string(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": [42]}}
        assert "WA313" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa313_empty_list_ok(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": []}}
        assert "WA313" not in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA400-WA402  VisibilityConfig checks
# ---------------------------------------------------------------------------


class TestVisibilityConfig:
    def test_wa400_missing_sampled(self):
        vc = {"CloudWatchMetricsEnabled": True, "MetricName": "m"}
        results = validate_rules([_rule(VisibilityConfig=vc)])
        assert "WA400" in _ids(results)

    def test_wa400_missing_cloudwatch(self):
        vc = {"SampledRequestsEnabled": True, "MetricName": "m"}
        results = validate_rules([_rule(VisibilityConfig=vc)])
        assert "WA400" in _ids(results)

    def test_wa400_missing_metric_name(self):
        vc = {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True}
        results = validate_rules([_rule(VisibilityConfig=vc)])
        assert "WA400" in _ids(results)

    def test_wa401_bool_field_gets_int(self):
        vc = {
            "SampledRequestsEnabled": 1,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "m",
        }
        results = validate_rules([_rule(VisibilityConfig=vc)])
        assert "WA401" in _ids(results)

    def test_wa401_string_field_gets_int(self):
        vc = {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": 123,
        }
        results = validate_rules([_rule(VisibilityConfig=vc)])
        assert "WA401" in _ids(results)

    def test_wa401_valid_types(self):
        assert "WA401" not in _ids(validate_rules([_rule()]))

    def test_wa402_metric_name_too_long(self):
        vc = {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "m" * 129,
        }
        assert "WA402" in _ids(validate_rules([_rule(VisibilityConfig=vc)]))

    def test_wa402_metric_name_at_limit(self):
        vc = {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "m" * 128,
        }
        assert "WA402" not in _ids(validate_rules([_rule(VisibilityConfig=vc)]))


# ---------------------------------------------------------------------------
# WA500  Duplicate MetricName
# ---------------------------------------------------------------------------


class TestDuplicateMetricName:
    def test_wa500_duplicate(self):
        a = _rule(ref="a", Priority=1)
        b = _rule(ref="b", Priority=2)
        # Both use default MetricName="test-metric"
        assert "WA500" in _ids(validate_rules([a, b]))

    def test_wa500_unique(self):
        a = _rule(ref="a", Priority=1)
        b = _rule(ref="b", Priority=2)
        b["VisibilityConfig"]["MetricName"] = "other"
        assert "WA500" not in _ids(validate_rules([a, b]))


# ---------------------------------------------------------------------------
# ScopeDownStatement recursion
# ---------------------------------------------------------------------------


class TestScopeDown:
    def test_scope_down_validated(self):
        """ScopeDownStatement is recursively validated."""
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "IP",
                "ScopeDownStatement": {"FooStatement": {}},
            }
        }
        assert "WA301" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_scope_down_byte_match_checked(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "IP",
                "ScopeDownStatement": {"ByteMatchStatement": {}},
            }
        }
        assert "WA312" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# Integration / edge cases
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# WA020  Unknown top-level rule field
# ---------------------------------------------------------------------------


class TestUnknownFields:
    def test_wa020_unknown_field(self):
        r = _rule(Foo="bar")
        assert "WA020" in _ids(validate_rules([r]))

    def test_wa020_typo_in_field(self):
        r = _rule(priority=1)  # lowercase — not a known field
        assert "WA020" in _ids(validate_rules([r]))

    def test_wa020_known_fields_no_warning(self):
        r = _rule(RuleLabels=[{"Name": "test:label"}])
        assert "WA020" not in _ids(validate_rules([r]))

    def test_wa020_multiple_unknown(self):
        r = _rule(Foo="a", Bar="b")
        results = validate_rules([r])
        wa020_count = _ids(results).count("WA020")
        assert wa020_count == 2

    def test_wa020_all_valid_fields(self):
        """All valid top-level fields should not trigger WA020."""
        r = _rule(RuleLabels=[])
        assert "WA020" not in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# WA021  Action/OverrideAction must be dict
# ---------------------------------------------------------------------------


class TestActionMustBeDict:
    def test_wa021_action_string(self):
        assert "WA021" in _ids(validate_rules([_rule(Action="Block")]))

    def test_wa021_action_list(self):
        assert "WA021" in _ids(validate_rules([_rule(Action=["Block"])]))

    def test_wa021_action_int(self):
        assert "WA021" in _ids(validate_rules([_rule(Action=42)]))

    def test_wa021_action_dict_ok(self):
        assert "WA021" not in _ids(validate_rules([_rule(Action={"Block": {}})]))

    def test_wa021_override_action_string(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = "Count"
        assert "WA021" in _ids(validate_rules([r]))

    def test_wa021_override_action_dict_ok(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"Count": {}}
        assert "WA021" not in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# WA314  Missing required field in statement type
# ---------------------------------------------------------------------------


class TestStatementRequiredFields:
    def test_wa314_ipset_missing_arn(self):
        stmt = {"IPSetReferenceStatement": {}}
        assert "WA314" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_ipset_has_arn(self):
        stmt = {
            "IPSetReferenceStatement": {
                "ARN": "arn:aws:wafv2:us-east-1:123456789:regional/ipset/test/abc"
            }
        }
        assert "WA314" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_regex_match_missing_fields(self):
        stmt = {"RegexMatchStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        wa314_count = _ids(results).count("WA314")
        assert wa314_count == 3  # RegexString, FieldToMatch, TextTransformations

    def test_wa314_regex_match_complete(self):
        stmt = {
            "RegexMatchStatement": {
                "RegexString": "^/api/.*",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA314" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_regex_pattern_set_missing_fields(self):
        stmt = {"RegexPatternSetReferenceStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        wa314_count = _ids(results).count("WA314")
        assert wa314_count == 3  # ARN, FieldToMatch, TextTransformations

    def test_wa314_size_constraint_missing_fields(self):
        stmt = {"SizeConstraintStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        wa314_count = _ids(results).count("WA314")
        assert wa314_count == 4  # FieldToMatch, ComparisonOperator, Size, TextTransformations

    def test_wa314_size_constraint_complete(self):
        stmt = {
            "SizeConstraintStatement": {
                "FieldToMatch": {"Body": {}},
                "ComparisonOperator": "GT",
                "Size": 8192,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA314" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_sqli_missing_fields(self):
        stmt = {"SqliMatchStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        wa314_count = _ids(results).count("WA314")
        assert wa314_count == 2  # FieldToMatch, TextTransformations

    def test_wa314_sqli_complete(self):
        stmt = {
            "SqliMatchStatement": {
                "FieldToMatch": {"QueryString": {}},
                "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}],
            }
        }
        assert "WA314" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_xss_missing_fields(self):
        stmt = {"XssMatchStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        wa314_count = _ids(results).count("WA314")
        assert wa314_count == 2  # FieldToMatch, TextTransformations

    def test_wa314_xss_complete(self):
        stmt = {
            "XssMatchStatement": {
                "FieldToMatch": {"Body": {}},
                "TextTransformations": [{"Priority": 0, "Type": "HTML_ENTITY_DECODE"}],
            }
        }
        assert "WA314" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_label_match_missing_fields(self):
        stmt = {"LabelMatchStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        wa314_count = _ids(results).count("WA314")
        assert wa314_count == 2  # Scope, Key

    def test_wa314_label_match_complete(self):
        stmt = {"LabelMatchStatement": {"Scope": "LABEL", "Key": "awswaf:managed:test"}}
        assert "WA314" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_managed_rule_group_missing_fields(self):
        stmt = {"ManagedRuleGroupStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        wa314_count = _ids(results).count("WA314")
        assert wa314_count == 2  # VendorName, Name

    def test_wa314_managed_rule_group_complete(self):
        stmt = {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
            }
        }
        assert "WA314" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_rule_group_reference_missing_arn(self):
        stmt = {"RuleGroupReferenceStatement": {}}
        assert "WA314" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_rule_group_reference_complete(self):
        stmt = {
            "RuleGroupReferenceStatement": {
                "ARN": "arn:aws:wafv2:us-east-1:123456789:regional/rulegroup/test/abc"
            }
        }
        assert "WA314" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_recursive_in_and_statement(self):
        """WA314 fires recursively inside compound statements."""
        stmt = {
            "AndStatement": {
                "Statements": [
                    {"IPSetReferenceStatement": {}},
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]
            }
        }
        assert "WA314" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_recursive_in_not_statement(self):
        stmt = {"NotStatement": {"Statement": {"IPSetReferenceStatement": {}}}}
        assert "WA314" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_recursive_in_rate_based(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "IP",
                "ScopeDownStatement": {"SqliMatchStatement": {}},
            }
        }
        assert "WA314" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa314_does_not_duplicate_wa312(self):
        """ByteMatchStatement uses WA312, not WA314, for required fields."""
        stmt = {"ByteMatchStatement": {}}
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA312" in _ids(results)
        assert "WA314" not in _ids(results)


# ---------------------------------------------------------------------------
# WA315  Invalid enum value in statement
# ---------------------------------------------------------------------------


class TestStatementEnums:
    # PositionalConstraint
    @pytest.mark.parametrize(
        "val", ["EXACTLY", "STARTS_WITH", "ENDS_WITH", "CONTAINS", "CONTAINS_WORD"]
    )
    def test_wa315_valid_positional_constraint(self, val):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": val,
            }
        }
        assert "WA315" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa315_invalid_positional_constraint(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "MATCHES",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA315" in _ids(results)
        wa315 = [r for r in results if r.rule_id == "WA315"]
        assert "PositionalConstraint" in wa315[0].message

    # ComparisonOperator
    @pytest.mark.parametrize("val", ["EQ", "NE", "LE", "LT", "GE", "GT"])
    def test_wa315_valid_comparison_operator(self, val):
        stmt = {
            "SizeConstraintStatement": {
                "FieldToMatch": {"Body": {}},
                "ComparisonOperator": val,
                "Size": 100,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA315" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa315_invalid_comparison_operator(self):
        stmt = {
            "SizeConstraintStatement": {
                "FieldToMatch": {"Body": {}},
                "ComparisonOperator": "BETWEEN",
                "Size": 100,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA315" in _ids(results)

    # LabelMatchStatement.Scope
    @pytest.mark.parametrize("val", ["LABEL", "NAMESPACE"])
    def test_wa315_valid_label_scope(self, val):
        stmt = {"LabelMatchStatement": {"Scope": val, "Key": "test"}}
        assert "WA315" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa315_invalid_label_scope(self):
        stmt = {"LabelMatchStatement": {"Scope": "PREFIX", "Key": "test"}}
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA315" in _ids(results)
        wa315 = [r for r in results if r.rule_id == "WA315"]
        assert "Scope" in wa315[0].message

    # SqliMatchStatement.SensitivityLevel (optional)
    @pytest.mark.parametrize("val", ["LOW", "HIGH"])
    def test_wa315_valid_sensitivity_level(self, val):
        stmt = {
            "SqliMatchStatement": {
                "FieldToMatch": {"QueryString": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "SensitivityLevel": val,
            }
        }
        assert "WA315" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa315_invalid_sensitivity_level(self):
        stmt = {
            "SqliMatchStatement": {
                "FieldToMatch": {"QueryString": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "SensitivityLevel": "MEDIUM",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA315" in _ids(results)

    def test_wa315_sensitivity_level_absent_ok(self):
        """SensitivityLevel is optional — absence should not fire WA315."""
        stmt = {
            "SqliMatchStatement": {
                "FieldToMatch": {"QueryString": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA315" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa315_recursive_in_compound(self):
        """Enum validation fires recursively inside And/Or."""
        stmt = {
            "OrStatement": {
                "Statements": [
                    {
                        "ByteMatchStatement": {
                            "SearchString": "x",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                            "PositionalConstraint": "INVALID_ENUM",
                        }
                    },
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]
            }
        }
        assert "WA315" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA316  FieldToMatch validation
# ---------------------------------------------------------------------------


class TestFieldToMatch:
    def test_wa316_valid_single_key(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA316" not in _ids(validate_rules([_rule(Statement=stmt)]))

    @pytest.mark.parametrize(
        "key",
        [
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
        ],
    )
    def test_wa316_all_valid_keys(self, key):
        inner = {key: {}}
        if key == "SingleHeader":
            inner[key] = {"Name": "host"}
        if key == "SingleQueryArgument":
            inner[key] = {"Name": "q"}
        if key == "JsonBody":
            inner[key] = {"MatchScope": "ALL", "InvalidFallbackBehavior": "MATCH"}
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": inner,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA316" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa316_multiple_keys(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}, "QueryString": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA316" in _ids(results)
        wa316 = [r for r in results if r.rule_id == "WA316"]
        assert "exactly 1 key" in wa316[0].message

    def test_wa316_empty_field_to_match(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA316" in _ids(results)

    def test_wa316_unknown_key(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"Payload": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA316" in _ids(results)
        wa316 = [r for r in results if r.rule_id == "WA316"]
        assert any("Unknown FieldToMatch key" in r.message for r in wa316)

    def test_wa316_single_header_missing_name(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"SingleHeader": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA316" in _ids(results)
        wa316 = [r for r in results if r.rule_id == "WA316"]
        assert any("SingleHeader requires" in r.message for r in wa316)

    def test_wa316_single_header_with_name_ok(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"SingleHeader": {"Name": "user-agent"}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA316" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa316_single_query_argument_missing_name(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"SingleQueryArgument": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA316" in _ids(results)
        wa316 = [r for r in results if r.rule_id == "WA316"]
        assert any("SingleQueryArgument requires" in r.message for r in wa316)

    def test_wa316_json_body_missing_fields(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"JsonBody": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa316 = [r for r in results if r.rule_id == "WA316"]
        assert len(wa316) == 2  # MatchScope + InvalidFallbackBehavior

    def test_wa316_json_body_complete(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA316" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa316_on_regex_match_statement(self):
        """FieldToMatch validation also applies to other statement types."""
        stmt = {
            "RegexMatchStatement": {
                "RegexString": "test",
                "FieldToMatch": {"Payload": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA316" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA317  TextTransformations validation
# ---------------------------------------------------------------------------


class TestTextTransformations:
    def test_wa317_not_a_list(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": "NONE",
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)

    def test_wa317_empty_list(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)
        wa317 = [r for r in results if r.rule_id == "WA317"]
        assert "must not be empty" in wa317[0].message

    def test_wa317_valid_single(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA317" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa317_valid_multiple(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "URL_DECODE"},
                    {"Priority": 1, "Type": "LOWERCASE"},
                ],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA317" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa317_element_not_dict(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": ["NONE"],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)

    def test_wa317_missing_priority(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)
        wa317 = [r for r in results if r.rule_id == "WA317"]
        assert any("Priority" in r.message for r in wa317)

    def test_wa317_missing_type(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)

    def test_wa317_priority_not_int(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": "0", "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)

    def test_wa317_priority_bool_rejected(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": True, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)

    def test_wa317_type_not_string(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": 42}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)

    def test_wa317_invalid_type_value(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "REVERSE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA317" in _ids(results)
        wa317 = [r for r in results if r.rule_id == "WA317"]
        assert any("REVERSE" in r.message for r in wa317)

    @pytest.mark.parametrize(
        "tt_type",
        [
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
        ],
    )
    def test_wa317_all_valid_types(self, tt_type):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": tt_type}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA317" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa317_on_sqli_statement(self):
        """TextTransformations validation applies to all statement types that use it."""
        stmt = {
            "SqliMatchStatement": {
                "FieldToMatch": {"QueryString": {}},
                "TextTransformations": [],
            }
        }
        assert "WA317" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa317_on_xss_statement(self):
        stmt = {
            "XssMatchStatement": {
                "FieldToMatch": {"Body": {}},
                "TextTransformations": [{"Priority": 0, "Type": "INVALID"}],
            }
        }
        assert "WA317" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA318  RateBasedStatement conditional requirements
# ---------------------------------------------------------------------------


class TestRateBasedConditional:
    def test_wa318_custom_keys_without_custom_keys_field(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "CUSTOM_KEYS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA318" in _ids(results)
        wa318 = [r for r in results if r.rule_id == "WA318"]
        assert "CustomKeys" in wa318[0].message

    def test_wa318_custom_keys_empty_list(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "CUSTOM_KEYS",
                "CustomKeys": [],
            }
        }
        assert "WA318" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa318_custom_keys_valid(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "CUSTOM_KEYS",
                "CustomKeys": [{"Header": {"Name": "x-forwarded-for"}}],
            }
        }
        assert "WA318" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa318_forwarded_ip_without_config(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "FORWARDED_IP",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA318" in _ids(results)
        wa318 = [r for r in results if r.rule_id == "WA318"]
        assert "ForwardedIPConfig" in wa318[0].message

    def test_wa318_forwarded_ip_with_config(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "FORWARDED_IP",
                "ForwardedIPConfig": {
                    "HeaderName": "X-Forwarded-For",
                    "FallbackBehavior": "MATCH",
                },
            }
        }
        assert "WA318" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa318_ip_type_no_requirements(self):
        """AggregateKeyType=IP has no extra requirements."""
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "IP"}}
        assert "WA318" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa318_constant_type_no_requirements(self):
        """AggregateKeyType=CONSTANT has no extra requirements."""
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "CONSTANT"}}
        assert "WA318" not in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA350  Action must have exactly one key
# ---------------------------------------------------------------------------


class TestActionOneKey:
    def test_wa350_action_zero_keys(self):
        assert "WA350" in _ids(validate_rules([_rule(Action={})]))

    def test_wa350_action_two_keys(self):
        assert "WA350" in _ids(validate_rules([_rule(Action={"Block": {}, "Count": {}})]))

    def test_wa350_action_one_key_ok(self):
        assert "WA350" not in _ids(validate_rules([_rule(Action={"Block": {}})]))

    def test_wa350_override_action_zero_keys(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {}
        assert "WA350" in _ids(validate_rules([r]))

    def test_wa350_override_action_two_keys(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"None": {}, "Count": {}}
        assert "WA350" in _ids(validate_rules([r]))

    def test_wa350_override_action_one_key_ok(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"Count": {}}
        assert "WA350" not in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# WA351  Unknown action type
# ---------------------------------------------------------------------------


class TestUnknownActionType:
    def test_wa351_unknown_action(self):
        assert "WA351" in _ids(validate_rules([_rule(Action={"Drop": {}})]))

    def test_wa351_known_action_ok(self):
        assert "WA351" not in _ids(validate_rules([_rule(Action={"Block": {}})]))

    @pytest.mark.parametrize("key", ["Allow", "Block", "Count", "Captcha", "Challenge"])
    def test_wa351_all_valid(self, key):
        assert "WA351" not in _ids(validate_rules([_rule(Action={key: {}})]))


# ---------------------------------------------------------------------------
# WA352  OverrideAction on non-group statement
# ---------------------------------------------------------------------------


class TestOverrideActionOnNonGroup:
    def test_wa352_override_on_byte_match(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"Count": {}}
        # Default statement is ByteMatchStatement — not a group
        assert "WA352" in _ids(validate_rules([r]))

    def test_wa352_override_on_managed_rule_group(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"Count": {}}
        r["Statement"] = {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "Core"}}
        assert "WA352" not in _ids(validate_rules([r]))

    def test_wa352_override_on_rule_group_reference(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"Count": {}}
        r["Statement"] = {
            "RuleGroupReferenceStatement": {
                "ARN": "arn:aws:wafv2:us-east-1:123:regional/rulegroup/test/abc"
            }
        }
        assert "WA352" not in _ids(validate_rules([r]))

    def test_wa352_override_on_geo_match(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"Count": {}}
        r["Statement"] = {"GeoMatchStatement": {"CountryCodes": ["US"]}}
        assert "WA352" in _ids(validate_rules([r]))

    def test_wa352_no_statement_no_crash(self):
        """If there's no Statement key, WA352 should not crash."""
        r = _rule()
        del r["Action"]
        del r["Statement"]
        r["OverrideAction"] = {"Count": {}}
        results = validate_rules([r])
        assert "WA352" not in _ids(results)

    def test_wa352_not_fired_for_action(self):
        """WA352 only applies to OverrideAction, not Action."""
        r = _rule(Action={"Block": {}})
        assert "WA352" not in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# WA353  CustomResponse status code
# ---------------------------------------------------------------------------


class TestCustomResponseCode:
    def test_wa353_valid_code(self):
        r = _rule(Action={"Block": {"CustomResponse": {"ResponseCode": 403}}})
        assert "WA353" not in _ids(validate_rules([r]))

    def test_wa353_code_200(self):
        r = _rule(Action={"Block": {"CustomResponse": {"ResponseCode": 200}}})
        assert "WA353" not in _ids(validate_rules([r]))

    def test_wa353_code_599(self):
        r = _rule(Action={"Block": {"CustomResponse": {"ResponseCode": 599}}})
        assert "WA353" not in _ids(validate_rules([r]))

    def test_wa353_code_below_200(self):
        r = _rule(Action={"Block": {"CustomResponse": {"ResponseCode": 199}}})
        assert "WA353" in _ids(validate_rules([r]))

    def test_wa353_code_above_599(self):
        r = _rule(Action={"Block": {"CustomResponse": {"ResponseCode": 600}}})
        assert "WA353" in _ids(validate_rules([r]))

    def test_wa353_code_not_integer(self):
        r = _rule(Action={"Block": {"CustomResponse": {"ResponseCode": "403"}}})
        assert "WA353" in _ids(validate_rules([r]))

    def test_wa353_code_bool(self):
        r = _rule(Action={"Block": {"CustomResponse": {"ResponseCode": True}}})
        assert "WA353" in _ids(validate_rules([r]))

    def test_wa353_no_custom_response_ok(self):
        r = _rule(Action={"Block": {}})
        assert "WA353" not in _ids(validate_rules([r]))

    def test_wa353_block_not_dict(self):
        """If Block value is not a dict, WA353 should not crash."""
        r = _rule(Action={"Block": "yes"})
        assert "WA353" not in _ids(validate_rules([r]))


# ---------------------------------------------------------------------------
# Integration / edge cases
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# WA600  Rule is disabled
# ---------------------------------------------------------------------------


class TestDisabledRule:
    def test_wa600_enabled_false(self):
        r = _rule(enabled=False)
        results = validate_rules([r])
        assert "WA600" in _ids(results)
        wa600 = [x for x in results if x.rule_id == "WA600"]
        assert wa600[0].severity.name == "INFO"
        assert "disabled" in wa600[0].message

    def test_wa600_enabled_true_no_warning(self):
        assert "WA600" not in _ids(validate_rules([_rule(enabled=True)]))

    def test_wa600_no_enabled_field(self):
        """Default rule (no enabled field) should not fire WA600."""
        assert "WA600" not in _ids(validate_rules([_rule()]))

    def test_wa600_enabled_none(self):
        """enabled: null should not fire WA600 (only explicit False)."""
        assert "WA600" not in _ids(validate_rules([_rule(enabled=None)]))

    def test_wa600_enabled_zero(self):
        """enabled: 0 is falsy but not 'is False' — should not fire."""
        assert "WA600" not in _ids(validate_rules([_rule(enabled=0)]))

    def test_wa600_field_ref(self):
        """WA600 should include the ref and field in the result."""
        results = validate_rules([_rule(ref="my-disabled-rule", enabled=False)])
        wa600 = [x for x in results if x.rule_id == "WA600"]
        assert wa600[0].ref == "my-disabled-rule"
        assert wa600[0].field == "enabled"

    def test_wa600_suggestion(self):
        results = validate_rules([_rule(enabled=False)])
        wa600 = [x for x in results if x.rule_id == "WA600"]
        assert "Remove" in wa600[0].suggestion

    def test_wa020_not_fired_for_enabled(self):
        """The 'enabled' field should be recognized, not flagged as unknown."""
        results = validate_rules([_rule(enabled=True)])
        assert "WA020" not in _ids(results)


class TestEdgeCases:
    def test_multiple_errors_same_rule(self):
        r = {"Priority": -1}
        results = validate_rules([r])
        ids = _ids(results)
        assert "WA001" in ids
        assert "WA100" in ids
        assert "WA003" in ids
        assert "WA004" in ids

    def test_override_action_without_action(self):
        r = _rule()
        del r["Action"]
        r["OverrideAction"] = {"Count": {}}
        results = validate_rules([r])
        assert "WA004" not in _ids(results)
        assert "WA005" not in _ids(results)

    def test_no_statement_key_no_crash(self):
        r = _rule()
        del r["Statement"]
        results = validate_rules([r])
        assert "WA300" not in _ids(results)

    def test_statement_not_dict(self):
        results = validate_rules([_rule(Statement="invalid")])
        assert "WA300" not in _ids(results)


# ---------------------------------------------------------------------------
# WA319  Invalid regex pattern in RegexMatchStatement
# ---------------------------------------------------------------------------


class TestRegexValidation:
    def _regex_stmt(self, regex_string):
        return {
            "RegexMatchStatement": {
                "RegexString": regex_string,
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }

    def test_valid_regex_no_error(self):
        stmt = self._regex_stmt("^/api/v[0-9]+")
        assert "WA319" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_invalid_regex_fires(self):
        stmt = self._regex_stmt("(unclosed")
        assert "WA319" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_invalid_regex_bad_escape(self):
        stmt = self._regex_stmt("\\k")
        # Python re treats \k as an invalid escape
        results = validate_rules([_rule(Statement=stmt)])
        # NOTE: Python 3.12+ raises re.error on bad escapes; older versions
        # may or may not.  Only assert WA319 fires when re.compile actually
        # raises -- the rule itself is correct either way.
        import re

        try:
            re.compile("\\k")
        except re.error:
            assert "WA319" in _ids(results)
        else:
            assert "WA319" not in _ids(results)

    def test_missing_regex_string_no_fire(self):
        """No RegexString key → WA314 handles it, not WA319."""
        stmt = {
            "RegexMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA314" in _ids(results)
        assert "WA319" not in _ids(results)

    def test_error_message_includes_details(self):
        stmt = self._regex_stmt("(unclosed")
        results = validate_rules([_rule(Statement=stmt)])
        wa319 = [r for r in results if r.rule_id == "WA319"]
        assert len(wa319) == 1
        assert "Invalid regex pattern" in wa319[0].message
        # The re.error message should be included
        assert len(wa319[0].message) > len("Invalid regex pattern: ")

    def test_field_is_set(self):
        stmt = self._regex_stmt("(unclosed")
        results = validate_rules([_rule(Statement=stmt)])
        wa319 = [r for r in results if r.rule_id == "WA319"]
        assert wa319[0].field == "Statement.RegexMatchStatement.RegexString"

    def test_suggestion_is_set(self):
        stmt = self._regex_stmt("(unclosed")
        results = validate_rules([_rule(Statement=stmt)])
        wa319 = [r for r in results if r.rule_id == "WA319"]
        assert wa319[0].suggestion == "Fix the regex syntax"

    def test_regex_string_not_string_no_fire(self):
        """Non-string RegexString should not fire WA319 (type issues are separate)."""
        stmt = {
            "RegexMatchStatement": {
                "RegexString": 42,
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA319" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_recursive_in_not_statement(self):
        """WA319 fires recursively inside compound statements."""
        stmt = {
            "NotStatement": {
                "Statement": {
                    "RegexMatchStatement": {
                        "RegexString": "(unclosed",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    }
                }
            }
        }
        assert "WA319" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA321  Redundant double negation (NotStatement wrapping NotStatement)
# ---------------------------------------------------------------------------


class TestDoubleNegation:
    def test_double_not_fires(self):
        stmt = {
            "NotStatement": {
                "Statement": {
                    "NotStatement": {"Statement": {"GeoMatchStatement": {"CountryCodes": ["CN"]}}}
                }
            }
        }
        assert "WA321" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_single_not_no_fire(self):
        stmt = {"NotStatement": {"Statement": {"GeoMatchStatement": {"CountryCodes": ["CN"]}}}}
        assert "WA321" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_not_wrapping_other_no_fire(self):
        """NotStatement wrapping a non-NotStatement should not fire WA321."""
        stmt = {
            "NotStatement": {
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": "x",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }
                }
            }
        }
        assert "WA321" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_severity_is_warning(self):
        stmt = {
            "NotStatement": {
                "Statement": {
                    "NotStatement": {"Statement": {"GeoMatchStatement": {"CountryCodes": ["CN"]}}}
                }
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa321 = [r for r in results if r.rule_id == "WA321"]
        assert len(wa321) == 1
        assert wa321[0].severity.name == "WARNING"

    def test_suggestion(self):
        stmt = {
            "NotStatement": {
                "Statement": {
                    "NotStatement": {"Statement": {"GeoMatchStatement": {"CountryCodes": ["CN"]}}}
                }
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa321 = [r for r in results if r.rule_id == "WA321"]
        assert wa321[0].suggestion == "Remove both NotStatement wrappers to simplify"

    def test_field_is_set(self):
        stmt = {
            "NotStatement": {
                "Statement": {
                    "NotStatement": {"Statement": {"GeoMatchStatement": {"CountryCodes": ["CN"]}}}
                }
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa321 = [r for r in results if r.rule_id == "WA321"]
        assert wa321[0].field == "Statement.NotStatement"

    def test_double_not_inside_compound(self):
        """Double negation inside an AndStatement is still detected."""
        stmt = {
            "AndStatement": {
                "Statements": [
                    {
                        "NotStatement": {
                            "Statement": {
                                "NotStatement": {
                                    "Statement": {"GeoMatchStatement": {"CountryCodes": ["CN"]}}
                                }
                            }
                        }
                    },
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]
            }
        }
        assert "WA321" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA307  SearchString exceeds 8192-byte limit
# ---------------------------------------------------------------------------


class TestSearchStringSize:
    def _byte_match_stmt(self, search_string):
        return {
            "ByteMatchStatement": {
                "SearchString": search_string,
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }

    def test_wa307_within_limit(self):
        stmt = self._byte_match_stmt("x" * 8192)
        assert "WA307" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa307_exceeds_limit(self):
        stmt = self._byte_match_stmt("x" * 8193)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA307" in _ids(results)
        wa307 = [r for r in results if r.rule_id == "WA307"]
        assert "8192-byte" in wa307[0].message
        assert "8193 bytes" in wa307[0].message

    def test_wa307_multibyte_characters(self):
        """Multi-byte UTF-8 chars count by byte length, not char count."""
        # e-acute = 2 bytes each; 4097 * 2 = 8194 bytes > 8192
        stmt = self._byte_match_stmt("\u00e9" * 4097)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA307" in _ids(results)

    def test_wa307_exactly_at_limit_multibyte(self):
        """4096 two-byte chars = 8192 bytes = exactly at limit."""
        stmt = self._byte_match_stmt("\u00e9" * 4096)
        assert "WA307" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa307_short_string(self):
        stmt = self._byte_match_stmt("bad")
        assert "WA307" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa307_missing_search_string_no_crash(self):
        """Missing SearchString is caught by WA312, not WA307."""
        stmt = {
            "ByteMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA312" in _ids(results)
        assert "WA307" not in _ids(results)

    def test_wa307_non_string_search_string_no_crash(self):
        """Non-string SearchString should not fire WA307."""
        stmt = {
            "ByteMatchStatement": {
                "SearchString": 12345,
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA307" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa307_field_is_set(self):
        stmt = self._byte_match_stmt("x" * 8193)
        results = validate_rules([_rule(Statement=stmt)])
        wa307 = [r for r in results if r.rule_id == "WA307"]
        assert wa307[0].field == "Statement.ByteMatchStatement.SearchString"

    def test_wa307_recursive_in_not(self):
        """WA307 fires recursively inside compound statements."""
        stmt = {
            "NotStatement": {
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": "x" * 8193,
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }
                }
            }
        }
        assert "WA307" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA308  RegexString exceeds 512-byte limit
# ---------------------------------------------------------------------------


class TestRegexStringSize:
    def _regex_stmt(self, regex_string):
        return {
            "RegexMatchStatement": {
                "RegexString": regex_string,
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }

    def test_wa308_within_limit(self):
        stmt = self._regex_stmt("x" * 512)
        assert "WA308" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa308_exceeds_limit(self):
        stmt = self._regex_stmt("x" * 513)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA308" in _ids(results)
        wa308 = [r for r in results if r.rule_id == "WA308"]
        assert "512-byte" in wa308[0].message
        assert "513 bytes" in wa308[0].message

    def test_wa308_multibyte_characters(self):
        """Multi-byte UTF-8 chars count by byte length, not char count."""
        # 257 two-byte chars = 514 bytes > 512
        stmt = self._regex_stmt("\u00e9" * 257)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA308" in _ids(results)

    def test_wa308_exactly_at_limit_multibyte(self):
        """256 two-byte chars = 512 bytes = exactly at limit."""
        stmt = self._regex_stmt("\u00e9" * 256)
        assert "WA308" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa308_short_regex(self):
        stmt = self._regex_stmt("^/api/.*")
        assert "WA308" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa308_missing_regex_string_no_crash(self):
        """Missing RegexString is caught by WA314, not WA308."""
        stmt = {
            "RegexMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA314" in _ids(results)
        assert "WA308" not in _ids(results)

    def test_wa308_non_string_regex_no_crash(self):
        """Non-string RegexString should not fire WA308."""
        stmt = {
            "RegexMatchStatement": {
                "RegexString": 42,
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA308" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa308_field_is_set(self):
        stmt = self._regex_stmt("x" * 513)
        results = validate_rules([_rule(Statement=stmt)])
        wa308 = [r for r in results if r.rule_id == "WA308"]
        assert wa308[0].field == "Statement.RegexMatchStatement.RegexString"

    def test_wa308_recursive_in_and(self):
        """WA308 fires recursively inside compound statements."""
        stmt = {
            "AndStatement": {
                "Statements": [
                    {
                        "RegexMatchStatement": {
                            "RegexString": "x" * 513,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        }
                    },
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]
            }
        }
        assert "WA308" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA309  RateBasedStatement without ScopeDownStatement
# ---------------------------------------------------------------------------


class TestRateBasedNoScopeDown:
    def test_wa309_no_scope_down(self):
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "IP"}}
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA309" in _ids(results)
        wa309 = [r for r in results if r.rule_id == "WA309"]
        assert "rate-limits all traffic" in wa309[0].message

    def test_wa309_with_scope_down(self):
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "IP",
                "ScopeDownStatement": {
                    "ByteMatchStatement": {
                        "SearchString": "/api",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "STARTS_WITH",
                    }
                },
            }
        }
        assert "WA309" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa309_severity_is_warning(self):
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "IP"}}
        results = validate_rules([_rule(Statement=stmt)])
        wa309 = [r for r in results if r.rule_id == "WA309"]
        assert wa309[0].severity.name == "WARNING"

    def test_wa309_suggestion(self):
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "IP"}}
        results = validate_rules([_rule(Statement=stmt)])
        wa309 = [r for r in results if r.rule_id == "WA309"]
        assert "ScopeDownStatement" in wa309[0].suggestion

    def test_wa309_field_is_set(self):
        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "IP"}}
        results = validate_rules([_rule(Statement=stmt)])
        wa309 = [r for r in results if r.rule_id == "WA309"]
        assert wa309[0].field == "Statement.RateBasedStatement.ScopeDownStatement"

    def test_wa309_not_dict_no_crash(self):
        """Non-dict RateBasedStatement should not crash WA309."""
        stmt = {"RateBasedStatement": "invalid"}
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA309" not in _ids(results)


# ---------------------------------------------------------------------------
# WA320  FieldToMatch type incompatible with statement type
# ---------------------------------------------------------------------------


class TestFieldToMatchIncompatible:
    def test_wa320_jsonbody_on_byte_match_ok(self):
        """JsonBody is valid on ByteMatchStatement."""
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA320" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa320_jsonbody_on_regex_match_ok(self):
        """JsonBody is valid on RegexMatchStatement."""
        stmt = {
            "RegexMatchStatement": {
                "RegexString": "test",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA320" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa320_jsonbody_on_size_constraint_ok(self):
        """JsonBody is valid on SizeConstraintStatement."""
        stmt = {
            "SizeConstraintStatement": {
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
                "ComparisonOperator": "GT",
                "Size": 1000,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA320" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa320_jsonbody_on_sqli_ok(self):
        """JsonBody is valid on SqliMatchStatement."""
        stmt = {
            "SqliMatchStatement": {
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA320" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa320_jsonbody_on_xss_ok(self):
        """JsonBody is valid on XssMatchStatement."""
        stmt = {
            "XssMatchStatement": {
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA320" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa320_jsonbody_on_label_match_fires(self):
        """JsonBody on LabelMatchStatement should fire WA320 -- LabelMatchStatement
        doesn't inspect request content."""
        stmt = {
            "LabelMatchStatement": {
                "Scope": "LABEL",
                "Key": "awswaf:test",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA320" in _ids(results)
        wa320 = [r for r in results if r.rule_id == "WA320"]
        assert "JsonBody" in wa320[0].message
        assert "LabelMatchStatement" in wa320[0].message

    def test_wa320_severity_is_warning(self):
        stmt = {
            "LabelMatchStatement": {
                "Scope": "LABEL",
                "Key": "awswaf:test",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa320 = [r for r in results if r.rule_id == "WA320"]
        assert wa320[0].severity.name == "WARNING"

    def test_wa320_suggestion(self):
        stmt = {
            "LabelMatchStatement": {
                "Scope": "LABEL",
                "Key": "awswaf:test",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa320 = [r for r in results if r.rule_id == "WA320"]
        assert "JsonBody is only applicable to" in wa320[0].suggestion

    def test_wa320_non_jsonbody_no_fire(self):
        """Non-JsonBody FieldToMatch keys on any statement should not fire WA320."""
        stmt = {
            "LabelMatchStatement": {
                "Scope": "LABEL",
                "Key": "awswaf:test",
                "FieldToMatch": {"UriPath": {}},
            }
        }
        assert "WA320" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa320_recursive_in_compound(self):
        """WA320 fires recursively inside compound statements."""
        stmt = {
            "OrStatement": {
                "Statements": [
                    {
                        "LabelMatchStatement": {
                            "Scope": "LABEL",
                            "Key": "awswaf:test",
                            "FieldToMatch": {
                                "JsonBody": {
                                    "MatchScope": "ALL",
                                    "InvalidFallbackBehavior": "MATCH",
                                }
                            },
                        }
                    },
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]
            }
        }
        assert "WA320" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA323  GeoMatchStatement exceeds 25 country codes
# ---------------------------------------------------------------------------


class TestGeoMatchCountLimit:
    def test_wa323_exactly_25_ok(self):
        codes = [chr(65 + i // 26) + chr(65 + i % 26) for i in range(25)]
        stmt = {"GeoMatchStatement": {"CountryCodes": codes}}
        assert "WA323" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa323_exceeds_25(self):
        codes = [chr(65 + i // 26) + chr(65 + i % 26) for i in range(26)]
        stmt = {"GeoMatchStatement": {"CountryCodes": codes}}
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA323" in _ids(results)
        wa323 = [r for r in results if r.rule_id == "WA323"]
        assert "26" in wa323[0].message
        assert "25" in wa323[0].message

    def test_wa323_empty_ok(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": []}}
        assert "WA323" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa323_field_is_set(self):
        codes = [chr(65 + i // 26) + chr(65 + i % 26) for i in range(26)]
        stmt = {"GeoMatchStatement": {"CountryCodes": codes}}
        results = validate_rules([_rule(Statement=stmt)])
        wa323 = [r for r in results if r.rule_id == "WA323"]
        assert wa323[0].field == "Statement.GeoMatchStatement.CountryCodes"


# ---------------------------------------------------------------------------
# WA324  CustomKeys exceeds maximum of 5
# ---------------------------------------------------------------------------


class TestCustomKeysLimit:
    def _rate_stmt(self, custom_keys):
        return {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "CUSTOM_KEYS",
                "CustomKeys": custom_keys,
            }
        }

    def test_wa324_exactly_5_ok(self):
        keys = [{"Header": {"Name": f"x-key-{i}"}} for i in range(5)]
        stmt = self._rate_stmt(keys)
        assert "WA324" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa324_exceeds_5(self):
        keys = [{"Header": {"Name": f"x-key-{i}"}} for i in range(6)]
        stmt = self._rate_stmt(keys)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA324" in _ids(results)
        wa324 = [r for r in results if r.rule_id == "WA324"]
        assert "6" in wa324[0].message

    def test_wa324_empty_list_fires_wa318_not_wa324(self):
        """Empty CustomKeys triggers WA318, not WA324."""
        stmt = self._rate_stmt([])
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA318" in _ids(results)
        assert "WA324" not in _ids(results)

    def test_wa324_field_is_set(self):
        keys = [{"Header": {"Name": f"x-key-{i}"}} for i in range(6)]
        stmt = self._rate_stmt(keys)
        results = validate_rules([_rule(Statement=stmt)])
        wa324 = [r for r in results if r.rule_id == "WA324"]
        assert wa324[0].field == "Statement.RateBasedStatement.CustomKeys"


# ---------------------------------------------------------------------------
# WA325  Headers/Cookies MatchPattern exceeds 5 patterns
# ---------------------------------------------------------------------------


class TestMatchPatternLimit:
    def _byte_match_with_headers(self, match_pattern):
        return {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {
                    "Headers": {
                        "MatchPattern": match_pattern,
                        "MatchScope": "ALL",
                        "OversizeHandling": "MATCH",
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }

    def _byte_match_with_cookies(self, match_pattern):
        return {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {
                    "Cookies": {
                        "MatchPattern": match_pattern,
                        "MatchScope": "ALL",
                        "OversizeHandling": "MATCH",
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }

    def test_wa325_headers_included_5_ok(self):
        mp = {"IncludedHeaders": ["a", "b", "c", "d", "e"]}
        stmt = self._byte_match_with_headers(mp)
        assert "WA325" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa325_headers_included_exceeds(self):
        mp = {"IncludedHeaders": ["a", "b", "c", "d", "e", "f"]}
        stmt = self._byte_match_with_headers(mp)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA325" in _ids(results)
        wa325 = [r for r in results if r.rule_id == "WA325"]
        assert "IncludedHeaders" in wa325[0].message
        assert "6" in wa325[0].message

    def test_wa325_headers_excluded_exceeds(self):
        mp = {"ExcludedHeaders": ["a", "b", "c", "d", "e", "f"]}
        stmt = self._byte_match_with_headers(mp)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA325" in _ids(results)
        wa325 = [r for r in results if r.rule_id == "WA325"]
        assert "ExcludedHeaders" in wa325[0].message

    def test_wa325_cookies_included_exceeds(self):
        mp = {"IncludedCookies": ["a", "b", "c", "d", "e", "f"]}
        stmt = self._byte_match_with_cookies(mp)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA325" in _ids(results)
        wa325 = [r for r in results if r.rule_id == "WA325"]
        assert "IncludedCookies" in wa325[0].message

    def test_wa325_cookies_excluded_exceeds(self):
        mp = {"ExcludedCookies": ["a", "b", "c", "d", "e", "f"]}
        stmt = self._byte_match_with_cookies(mp)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA325" in _ids(results)

    def test_wa325_headers_no_match_pattern_no_crash(self):
        """Headers without MatchPattern should not crash."""
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"Headers": {"MatchScope": "ALL", "OversizeHandling": "MATCH"}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA325" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa325_field_is_set(self):
        mp = {"IncludedHeaders": ["a", "b", "c", "d", "e", "f"]}
        stmt = self._byte_match_with_headers(mp)
        results = validate_rules([_rule(Statement=stmt)])
        wa325 = [r for r in results if r.rule_id == "WA325"]
        assert "Headers.MatchPattern.IncludedHeaders" in wa325[0].field


# ---------------------------------------------------------------------------
# WA331  TextTransformations exceeds maximum of 10 per statement
# ---------------------------------------------------------------------------


class TestTextTransformationsLimit:
    def _stmt_with_transforms(self, count):
        transforms = [{"Priority": i, "Type": "NONE"} for i in range(count)]
        return {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": transforms,
                "PositionalConstraint": "CONTAINS",
            }
        }

    def test_wa331_exactly_10_ok(self):
        stmt = self._stmt_with_transforms(10)
        assert "WA331" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa331_exceeds_10(self):
        stmt = self._stmt_with_transforms(11)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA331" in _ids(results)
        wa331 = [r for r in results if r.rule_id == "WA331"]
        assert "11" in wa331[0].message
        assert "10" in wa331[0].message

    def test_wa331_1_ok(self):
        stmt = self._stmt_with_transforms(1)
        assert "WA331" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa331_field_is_set(self):
        stmt = self._stmt_with_transforms(11)
        results = validate_rules([_rule(Statement=stmt)])
        wa331 = [r for r in results if r.rule_id == "WA331"]
        assert "TextTransformations" in wa331[0].field


# ---------------------------------------------------------------------------
# WA332  Duplicate TextTransformation Priority
# ---------------------------------------------------------------------------


class TestTextTransformationDuplicatePriority:
    def test_wa332_duplicate_priority(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "URL_DECODE"},
                    {"Priority": 0, "Type": "LOWERCASE"},
                ],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA332" in _ids(results)
        wa332 = [r for r in results if r.rule_id == "WA332"]
        assert "Priority 0" in wa332[0].message

    def test_wa332_unique_priorities_ok(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "URL_DECODE"},
                    {"Priority": 1, "Type": "LOWERCASE"},
                ],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA332" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa332_fires_once_per_duplicate(self):
        """Three transforms with same priority should fire once (at the second occurrence)."""
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "URL_DECODE"},
                    {"Priority": 0, "Type": "LOWERCASE"},
                    {"Priority": 0, "Type": "CMD_LINE"},
                ],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa332 = [r for r in results if r.rule_id == "WA332"]
        assert len(wa332) == 2  # fires at index 1 and index 2

    def test_wa332_field_is_set(self):
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "URL_DECODE"},
                    {"Priority": 0, "Type": "LOWERCASE"},
                ],
                "PositionalConstraint": "CONTAINS",
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa332 = [r for r in results if r.rule_id == "WA332"]
        assert wa332[0].field == "Statement.ByteMatchStatement.TextTransformations[1].Priority"


# ---------------------------------------------------------------------------
# WA334  SizeConstraintStatement.Size must be non-negative
# ---------------------------------------------------------------------------


class TestSizeConstraintNonNegative:
    def _size_stmt(self, size):
        return {
            "SizeConstraintStatement": {
                "FieldToMatch": {"Body": {}},
                "ComparisonOperator": "GT",
                "Size": size,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }

    def test_wa334_negative_size(self):
        stmt = self._size_stmt(-1)
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA334" in _ids(results)
        wa334 = [r for r in results if r.rule_id == "WA334"]
        assert "-1" in wa334[0].message

    def test_wa334_zero_ok(self):
        stmt = self._size_stmt(0)
        assert "WA334" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa334_positive_ok(self):
        stmt = self._size_stmt(8192)
        assert "WA334" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa334_non_int_no_fire(self):
        """Non-integer Size should not fire WA334 (type issues are separate)."""
        stmt = self._size_stmt("100")
        assert "WA334" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa334_field_is_set(self):
        stmt = self._size_stmt(-5)
        results = validate_rules([_rule(Statement=stmt)])
        wa334 = [r for r in results if r.rule_id == "WA334"]
        assert wa334[0].field == "Statement.SizeConstraintStatement.Size"


# ---------------------------------------------------------------------------
# WA335  JsonBody.MatchScope invalid
# ---------------------------------------------------------------------------


class TestJsonBodyMatchScope:
    def _json_body_stmt(self, match_scope, fallback="MATCH"):
        return {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": match_scope,
                        "InvalidFallbackBehavior": fallback,
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }

    @pytest.mark.parametrize("val", ["ALL", "KEY", "VALUE"])
    def test_wa335_valid(self, val):
        stmt = self._json_body_stmt(val)
        assert "WA335" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa335_invalid(self):
        stmt = self._json_body_stmt("KEYS")
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA335" in _ids(results)
        wa335 = [r for r in results if r.rule_id == "WA335"]
        assert "KEYS" in wa335[0].message

    def test_wa335_non_string_no_fire(self):
        """Non-string MatchScope should not fire WA335."""
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": 42,
                        "InvalidFallbackBehavior": "MATCH",
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA335" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa335_field_is_set(self):
        stmt = self._json_body_stmt("INVALID")
        results = validate_rules([_rule(Statement=stmt)])
        wa335 = [r for r in results if r.rule_id == "WA335"]
        assert "JsonBody.MatchScope" in wa335[0].field

    def test_wa335_suggestion(self):
        stmt = self._json_body_stmt("INVALID")
        results = validate_rules([_rule(Statement=stmt)])
        wa335 = [r for r in results if r.rule_id == "WA335"]
        assert wa335[0].suggestion is not None


# ---------------------------------------------------------------------------
# WA336  JsonBody.InvalidFallbackBehavior invalid
# ---------------------------------------------------------------------------


class TestJsonBodyFallbackBehavior:
    def _json_body_stmt(self, fallback, match_scope="ALL"):
        return {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": match_scope,
                        "InvalidFallbackBehavior": fallback,
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }

    @pytest.mark.parametrize("val", ["MATCH", "NO_MATCH", "EVALUATE_AS_STRING"])
    def test_wa336_valid(self, val):
        stmt = self._json_body_stmt(val)
        assert "WA336" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa336_invalid(self):
        stmt = self._json_body_stmt("IGNORE")
        results = validate_rules([_rule(Statement=stmt)])
        assert "WA336" in _ids(results)
        wa336 = [r for r in results if r.rule_id == "WA336"]
        assert "IGNORE" in wa336[0].message

    def test_wa336_non_string_no_fire(self):
        """Non-string InvalidFallbackBehavior should not fire WA336."""
        stmt = {
            "ByteMatchStatement": {
                "SearchString": "x",
                "FieldToMatch": {
                    "JsonBody": {
                        "MatchScope": "ALL",
                        "InvalidFallbackBehavior": 123,
                    }
                },
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        assert "WA336" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa336_field_is_set(self):
        stmt = self._json_body_stmt("BAD")
        results = validate_rules([_rule(Statement=stmt)])
        wa336 = [r for r in results if r.rule_id == "WA336"]
        assert "JsonBody.InvalidFallbackBehavior" in wa336[0].field

    def test_wa336_suggestion(self):
        stmt = self._json_body_stmt("BAD")
        results = validate_rules([_rule(Statement=stmt)])
        wa336 = [r for r in results if r.rule_id == "WA336"]
        assert wa336[0].suggestion is not None


# ---------------------------------------------------------------------------
# WA341  GeoMatchStatement likely always true
# ---------------------------------------------------------------------------


class TestGeoAlwaysTrue:
    def test_wa341_200_country_codes(self):
        """GeoMatch with >= 200 codes triggers WA341."""
        codes = [f"{chr(65 + i // 26)}{chr(65 + i % 26)}" for i in range(200)]
        stmt = {"GeoMatchStatement": {"CountryCodes": codes}}
        assert "WA341" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa341_249_country_codes(self):
        """GeoMatch with 249 codes (all countries) triggers WA341."""
        codes = [f"{chr(65 + i // 26)}{chr(65 + i % 26)}" for i in range(249)]
        stmt = {"GeoMatchStatement": {"CountryCodes": codes}}
        assert "WA341" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa341_199_country_codes_no_warn(self):
        """GeoMatch with < 200 codes does NOT trigger WA341."""
        codes = [f"{chr(65 + i // 26)}{chr(65 + i % 26)}" for i in range(199)]
        stmt = {"GeoMatchStatement": {"CountryCodes": codes}}
        assert "WA341" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa341_small_set_no_warn(self):
        """GeoMatch with a few codes does NOT trigger WA341."""
        stmt = {"GeoMatchStatement": {"CountryCodes": ["US", "CA", "GB"]}}
        assert "WA341" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa341_nested_in_and(self):
        """WA341 fires for GeoMatch nested in AndStatement."""
        codes = [f"{chr(65 + i // 26)}{chr(65 + i % 26)}" for i in range(200)]
        stmt = {
            "AndStatement": {
                "Statements": [
                    {"GeoMatchStatement": {"CountryCodes": codes}},
                    {"LabelMatchStatement": {"Scope": "LABEL", "Key": "test"}},
                ]
            }
        }
        assert "WA341" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA342  Contradictory AND conditions (non-overlapping GeoMatch sets)
# ---------------------------------------------------------------------------


class TestContradictoryGeo:
    def test_wa342_non_overlapping_sets(self):
        """AND with non-overlapping GeoMatch sets triggers WA342."""
        stmt = {
            "AndStatement": {
                "Statements": [
                    {"GeoMatchStatement": {"CountryCodes": ["US", "CA"]}},
                    {"GeoMatchStatement": {"CountryCodes": ["DE", "FR"]}},
                ]
            }
        }
        assert "WA342" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa342_overlapping_sets_no_warn(self):
        """AND with overlapping GeoMatch sets does NOT trigger WA342."""
        stmt = {
            "AndStatement": {
                "Statements": [
                    {"GeoMatchStatement": {"CountryCodes": ["US", "CA", "DE"]}},
                    {"GeoMatchStatement": {"CountryCodes": ["DE", "FR"]}},
                ]
            }
        }
        assert "WA342" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa342_single_geo_no_warn(self):
        """AND with only one GeoMatch does NOT trigger WA342."""
        stmt = {
            "AndStatement": {
                "Statements": [
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                    {"LabelMatchStatement": {"Scope": "LABEL", "Key": "test"}},
                ]
            }
        }
        assert "WA342" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa342_fires_once_for_triple(self):
        """Three contradictory GeoMatch sets produce only one WA342."""
        stmt = {
            "AndStatement": {
                "Statements": [
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                    {"GeoMatchStatement": {"CountryCodes": ["DE"]}},
                    {"GeoMatchStatement": {"CountryCodes": ["FR"]}},
                ]
            }
        }
        results = validate_rules([_rule(Statement=stmt)])
        wa342 = [r for r in results if r.rule_id == "WA342"]
        assert len(wa342) == 1

    def test_wa342_nested_and_in_or(self):
        """Contradictory GeoMatch inside nested AND also detected."""
        stmt = {
            "OrStatement": {
                "Statements": [
                    {
                        "AndStatement": {
                            "Statements": [
                                {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                                {"GeoMatchStatement": {"CountryCodes": ["DE"]}},
                            ]
                        }
                    },
                    {"LabelMatchStatement": {"Scope": "LABEL", "Key": "test"}},
                ]
            }
        }
        assert "WA342" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WA343  Always-false pattern (Size < 0 impossible)
# ---------------------------------------------------------------------------


class TestAlwaysFalse:
    def test_wa343_size_zero_lt(self):
        """SizeConstraint with Size=0 and LT triggers WA343."""
        stmt = {
            "SizeConstraintStatement": {
                "FieldToMatch": {"Body": {}},
                "ComparisonOperator": "LT",
                "Size": 0,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA343" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa343_size_zero_eq_no_warn(self):
        """SizeConstraint with Size=0 and EQ does NOT trigger WA343."""
        stmt = {
            "SizeConstraintStatement": {
                "FieldToMatch": {"Body": {}},
                "ComparisonOperator": "EQ",
                "Size": 0,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA343" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa343_size_nonzero_lt_no_warn(self):
        """SizeConstraint with Size=1 and LT does NOT trigger WA343."""
        stmt = {
            "SizeConstraintStatement": {
                "FieldToMatch": {"Body": {}},
                "ComparisonOperator": "LT",
                "Size": 1,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        assert "WA343" not in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa343_nested_in_not(self):
        """WA343 fires for SizeConstraint nested in NotStatement."""
        stmt = {
            "NotStatement": {
                "Statement": {
                    "SizeConstraintStatement": {
                        "FieldToMatch": {"Body": {}},
                        "ComparisonOperator": "LT",
                        "Size": 0,
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    }
                }
            }
        }
        assert "WA343" in _ids(validate_rules([_rule(Statement=stmt)]))

    def test_wa343_nested_in_rate_based(self):
        """WA343 fires for SizeConstraint in RateBasedStatement ScopeDown."""
        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "IP",
                "ScopeDownStatement": {
                    "SizeConstraintStatement": {
                        "FieldToMatch": {"Body": {}},
                        "ComparisonOperator": "LT",
                        "Size": 0,
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    }
                },
            }
        }
        assert "WA343" in _ids(validate_rules([_rule(Statement=stmt)]))


# ---------------------------------------------------------------------------
# WCU estimation (unit tests for _estimate_wcu and _estimate_rule_wcu)
# ---------------------------------------------------------------------------


class TestWcuEstimation:
    """Unit tests for WCU estimation functions."""

    def test_byte_match_base(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {
            "ByteMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
                "SearchString": "bad",
            }
        }
        # Base 2 + 1 text transformation = 3
        assert _estimate_wcu(stmt) == 3

    def test_byte_match_multiple_transforms(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {
            "ByteMatchStatement": {
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "NONE"},
                    {"Priority": 1, "Type": "LOWERCASE"},
                ],
                "PositionalConstraint": "CONTAINS",
                "SearchString": "bad",
            }
        }
        # Base 2 + 2 text transformations = 4
        assert _estimate_wcu(stmt) == 4

    def test_geo_match(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {"GeoMatchStatement": {"CountryCodes": ["US", "CA"]}}
        assert _estimate_wcu(stmt) == 2

    def test_ipset_reference(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {
            "IPSetReferenceStatement": {
                "ARN": "arn:aws:wafv2:us-east-1:123456789:regional/ipset/test/abc"
            }
        }
        assert _estimate_wcu(stmt) == 1

    def test_sqli_match(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {
            "SqliMatchStatement": {
                "FieldToMatch": {"QueryString": {}},
                "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}],
            }
        }
        # Base 15 + 1 text transformation = 16
        assert _estimate_wcu(stmt) == 16

    def test_managed_rule_group_estimate(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
            }
        }
        assert _estimate_wcu(stmt) == 100

    def test_and_statement(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {
            "AndStatement": {
                "Statements": [
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                    {"IPSetReferenceStatement": {"ARN": "arn:aws:wafv2:x:y:z/ipset/t/a"}},
                ]
            }
        }
        # 1 (And base) + 2 (Geo) + 1 (IPSet) = 4
        assert _estimate_wcu(stmt) == 4

    def test_or_statement(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {
            "OrStatement": {
                "Statements": [
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                    {"LabelMatchStatement": {"Scope": "LABEL", "Key": "test"}},
                ]
            }
        }
        # 1 (Or base) + 2 (Geo) + 1 (Label) = 4
        assert _estimate_wcu(stmt) == 4

    def test_not_statement(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {"NotStatement": {"Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}}}}
        # 1 (Not base) + 2 (Geo) = 3
        assert _estimate_wcu(stmt) == 3

    def test_rate_based_with_scope_down(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {
            "RateBasedStatement": {
                "Limit": 200,
                "AggregateKeyType": "IP",
                "ScopeDownStatement": {
                    "ByteMatchStatement": {
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                        "SearchString": "/api",
                    }
                },
            }
        }
        # 2 (Rate base) + 2 (ByteMatch base) + 1 (transform) = 5
        assert _estimate_wcu(stmt) == 5

    def test_rate_based_without_scope_down(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {"RateBasedStatement": {"Limit": 200, "AggregateKeyType": "IP"}}
        assert _estimate_wcu(stmt) == 2

    def test_label_match(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {"LabelMatchStatement": {"Scope": "LABEL", "Key": "awswaf:managed:test"}}
        assert _estimate_wcu(stmt) == 1

    def test_rule_wcu_adds_base(self):
        from octorules_aws.validate import _estimate_rule_wcu

        rule = {
            "ref": "test",
            "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
        }
        # 1 (rule base) + 2 (Geo) = 3
        assert _estimate_rule_wcu(rule) == 3

    def test_rule_wcu_missing_statement(self):
        from octorules_aws.validate import _estimate_rule_wcu

        rule = {"ref": "test"}
        assert _estimate_rule_wcu(rule) == 1

    def test_empty_statement_dict(self):
        from octorules_aws.validate import _estimate_wcu

        assert _estimate_wcu({}) == 0

    def test_unknown_statement_type_defaults_to_1(self):
        from octorules_aws.validate import _estimate_wcu

        stmt = {"FutureNewStatement": {"SomeField": "value"}}
        assert _estimate_wcu(stmt) == 1


class TestResultFactory:
    """Tests for the _result() LintResult factory helper."""

    def test_creates_lint_result_with_required_fields(self):
        """Factory returns a LintResult with all required fields set."""
        from octorules.linter.engine import LintResult, Severity

        from octorules_aws.validate import _result

        r = _result("WA001", Severity.ERROR, "test message", "custom_rules", "ref1")
        assert isinstance(r, LintResult)
        assert r.rule_id == "WA001"
        assert r.severity == Severity.ERROR
        assert r.message == "test message"
        assert r.phase == "custom_rules"
        assert r.ref == "ref1"

    def test_default_optional_fields(self):
        """Factory defaults field and suggestion to empty strings."""
        from octorules.linter.engine import Severity

        from octorules_aws.validate import _result

        r = _result("WA002", Severity.WARNING, "msg", "rate_based")
        assert r.ref == ""
        assert r.field == ""
        assert r.suggestion == ""

    def test_optional_fields_passthrough(self):
        """Factory passes field and suggestion through to LintResult."""
        from octorules.linter.engine import Severity

        from octorules_aws.validate import _result

        r = _result(
            "WA003",
            Severity.INFO,
            "msg",
            "managed",
            field="action",
            suggestion="use block",
        )
        assert r.field == "action"
        assert r.suggestion == "use block"


class TestIsStrictInt:
    """_is_strict_int rejects bools and non-int types."""

    def test_int_is_strict(self):
        from octorules_aws.validate import _is_strict_int

        assert _is_strict_int(0) is True
        assert _is_strict_int(42) is True
        assert _is_strict_int(-1) is True

    def test_bool_is_not_strict_int(self):
        from octorules_aws.validate import _is_strict_int

        assert _is_strict_int(True) is False
        assert _is_strict_int(False) is False

    def test_non_int_is_not_strict_int(self):
        from octorules_aws.validate import _is_strict_int

        assert _is_strict_int("42") is False
        assert _is_strict_int(3.14) is False
        assert _is_strict_int(None) is False
