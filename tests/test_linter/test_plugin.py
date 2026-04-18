"""Tests for the AWS WAF linter plugin."""

from octorules.linter.engine import LintContext, Severity
from octorules.linter.plugin import get_registered_plugins
from octorules.linter.rules.registry import RULE_REGISTRY

from octorules_aws.linter._plugin import AWS_RULE_IDS, aws_lint
from octorules_aws.linter._rules import AWS_RULE_METAS


class TestPluginRegistration:
    def test_aws_plugin_registered(self):
        plugins = get_registered_plugins()
        names = [p.name for p in plugins]
        assert "aws" in names

    def test_rule_ids_non_empty(self):
        assert len(AWS_RULE_IDS) > 0

    def test_all_rule_ids_start_with_wa(self):
        for rule_id in AWS_RULE_IDS:
            assert rule_id.startswith("WA"), f"Expected WA prefix, got {rule_id}"

    def test_plugin_rule_ids_match_metas(self):
        meta_ids = frozenset(r.rule_id for r in AWS_RULE_METAS)
        assert AWS_RULE_IDS == meta_ids, (
            f"AWS_RULE_IDS and AWS_RULE_METAS are out of sync: "
            f"missing from metas: {AWS_RULE_IDS - meta_ids}, "
            f"missing from plugin: {meta_ids - AWS_RULE_IDS}"
        )

    def test_all_aws_rules_in_registry(self):
        for rule_id in AWS_RULE_IDS:
            assert rule_id in RULE_REGISTRY, f"{rule_id} not in global registry"

    def test_unique_rule_ids(self):
        ids = [r.rule_id for r in AWS_RULE_METAS]
        dupes = [x for x in ids if ids.count(x) > 1]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {dupes}"


class TestAwsLint:
    def test_adds_results_for_invalid_rules(self):
        """aws_lint should find errors in rules with missing fields."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                {"Priority": -1},  # missing ref, bad priority, missing visibility, missing action
            ],
        }
        aws_lint(rules_data, ctx)
        assert len(ctx.results) > 0
        rule_ids = [r.rule_id for r in ctx.results]
        assert "WA001" in rule_ids
        assert "WA100" in rule_ids

    def test_skips_non_aws_phases(self):
        """aws_lint should ignore phases it doesn't own."""
        ctx = LintContext()
        rules_data = {
            "http_request_dynamic_redirect": [
                {"Priority": -1},  # would be invalid if checked
            ],
        }
        aws_lint(rules_data, ctx)
        assert len(ctx.results) == 0

    def test_phase_filtering(self):
        """aws_lint should respect ctx.phase_filter."""
        ctx = LintContext(phase_filter=["aws_waf_rate_rules"])
        rules_data = {
            "aws_waf_custom_rules": [{"Priority": -1}],
            "aws_waf_rate_rules": [{"Priority": -1}],
        }
        aws_lint(rules_data, ctx)
        # Only rate rules should produce findings
        phases = {r.phase for r in ctx.results}
        assert "aws_waf_custom_rules" not in phases
        assert "aws_waf_rate_rules" in phases

    def test_non_list_phase_emits_wa024(self):
        """aws_lint should emit WA024 when a phase value is not a list."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": "not-a-list",
        }
        aws_lint(rules_data, ctx)
        wa024 = [r for r in ctx.results if r.rule_id == "WA024"]
        assert len(wa024) == 1
        assert wa024[0].phase == "aws_waf_custom_rules"
        assert "not a list" in wa024[0].message

    def test_non_list_phase_dict_emits_wa024(self):
        """A dict value for a phase should also trigger WA024."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": {"ref": "oops"},
        }
        aws_lint(rules_data, ctx)
        wa024 = [r for r in ctx.results if r.rule_id == "WA024"]
        assert len(wa024) == 1

    def test_non_list_phase_skips_validate(self):
        """A non-list phase should not produce per-rule errors (no crash)."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": 42,
        }
        aws_lint(rules_data, ctx)
        ids = [r.rule_id for r in ctx.results]
        assert "WA024" in ids
        assert "WA001" not in ids

    def test_valid_rules_no_errors(self):
        """aws_lint should produce no results for valid rules."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "good-rule",
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "good-rule",
                    },
                    "Statement": {
                        "GeoMatchStatement": {"CountryCodes": ["US"]},
                    },
                }
            ],
        }
        aws_lint(rules_data, ctx)
        assert len(ctx.results) == 0

    def test_severity_filter(self):
        """aws_lint should respect the severity filter on the context."""
        ctx = LintContext(severity_filter=Severity.ERROR)
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "test-rule",
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "test-rule",
                    },
                    "Statement": {"FooStatement": {}},  # WA301 = WARNING
                },
            ],
        }
        aws_lint(rules_data, ctx)
        # WA301 is WARNING, severity filter is ERROR — should be excluded
        rule_ids = [r.rule_id for r in ctx.results]
        assert "WA301" not in rule_ids

    def test_wa600_disabled_rule_through_pipeline(self):
        """WA600 should fire for enabled: false through the full pipeline."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "disabled-rule",
                    "enabled": False,
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "disabled-rule",
                    },
                    "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                },
            ],
        }
        aws_lint(rules_data, ctx)
        wa600 = [r for r in ctx.results if r.rule_id == "WA600"]
        assert len(wa600) == 1
        assert wa600[0].phase == "aws_waf_custom_rules"

    def test_wa600_filtered_by_severity(self):
        """WA600 (INFO) should be excluded when severity filter is WARNING."""
        ctx = LintContext(severity_filter=Severity.WARNING)
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "disabled-rule",
                    "enabled": False,
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "disabled-rule",
                    },
                    "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                },
            ],
        }
        aws_lint(rules_data, ctx)
        rule_ids = [r.rule_id for r in ctx.results]
        assert "WA600" not in rule_ids

    def test_multiple_phases(self):
        """aws_lint should check all AWS phases present in the data."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [{"Priority": -1}],
            "aws_waf_rate_rules": [{"Priority": -1}],
            "aws_waf_managed_rules": [{"Priority": -1}],
            "aws_waf_rule_group_rules": [{"Priority": -1}],
        }
        aws_lint(rules_data, ctx)
        phases = {r.phase for r in ctx.results}
        assert "aws_waf_custom_rules" in phases
        assert "aws_waf_rate_rules" in phases
        assert "aws_waf_managed_rules" in phases
        assert "aws_waf_rule_group_rules" in phases


class TestCrossPhaseMetricName:
    """WA501: Detect duplicate MetricName values across AWS phases."""

    def _make_rule(self, ref, metric):
        return {
            "ref": ref,
            "Priority": 1,
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": metric,
            },
            "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
        }

    def test_same_metric_across_phases_fires(self):
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [self._make_rule("r1", "shared-metric")],
            "aws_waf_rate_rules": [self._make_rule("r2", "shared-metric")],
        }
        aws_lint(rules_data, ctx)
        wa501 = [r for r in ctx.results if r.rule_id == "WA501"]
        assert len(wa501) == 1
        assert "shared-metric" in wa501[0].message

    def test_same_metric_within_phase_no_wa501(self):
        """Within-phase duplicates are caught by WA500, not WA501."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule("r1", "same"),
                self._make_rule("r2", "same"),
            ],
        }
        aws_lint(rules_data, ctx)
        wa501 = [r for r in ctx.results if r.rule_id == "WA501"]
        assert len(wa501) == 0
        wa500 = [r for r in ctx.results if r.rule_id == "WA500"]
        assert len(wa500) == 1

    def test_unique_metrics_across_phases_ok(self):
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [self._make_rule("r1", "metric-a")],
            "aws_waf_rate_rules": [self._make_rule("r2", "metric-b")],
        }
        aws_lint(rules_data, ctx)
        wa501 = [r for r in ctx.results if r.rule_id == "WA501"]
        assert len(wa501) == 0


class TestDuplicateStatement:
    """WA520: Detect duplicate Statement dicts within a phase."""

    def _make_rule(self, ref, priority, metric, statement):
        return {
            "ref": ref,
            "Priority": priority,
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": metric,
            },
            "Statement": statement,
        }

    def test_wa520_duplicate_statements_same_phase(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": ["US"]}}
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule("r1", 1, "m1", stmt),
                self._make_rule("r2", 2, "m2", stmt),
            ],
        }
        aws_lint(rules_data, ctx)
        wa520 = [r for r in ctx.results if r.rule_id == "WA520"]
        assert len(wa520) == 1
        assert "r1" in wa520[0].message
        assert "r2" in wa520[0].message

    def test_wa520_different_statements_ok(self):
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule("r1", 1, "m1", {"GeoMatchStatement": {"CountryCodes": ["US"]}}),
                self._make_rule("r2", 2, "m2", {"GeoMatchStatement": {"CountryCodes": ["DE"]}}),
            ],
        }
        aws_lint(rules_data, ctx)
        wa520 = [r for r in ctx.results if r.rule_id == "WA520"]
        assert len(wa520) == 0

    def test_wa520_same_statement_different_phases_no_warn(self):
        """Same statement in different phases should NOT fire WA520."""
        stmt = {"GeoMatchStatement": {"CountryCodes": ["US"]}}
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [self._make_rule("r1", 1, "m1", stmt)],
            "aws_waf_rate_rules": [self._make_rule("r2", 1, "m2", stmt)],
        }
        aws_lint(rules_data, ctx)
        wa520 = [r for r in ctx.results if r.rule_id == "WA520"]
        assert len(wa520) == 0

    def test_wa520_key_order_independent(self):
        """Statement dicts with same content but different key order should match."""
        ctx = LintContext()
        stmt1 = {
            "ByteMatchStatement": {
                "SearchString": "bad",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        }
        stmt2 = {
            "ByteMatchStatement": {
                "PositionalConstraint": "CONTAINS",
                "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                "FieldToMatch": {"UriPath": {}},
                "SearchString": "bad",
            }
        }
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule("r1", 1, "m1", stmt1),
                self._make_rule("r2", 2, "m2", stmt2),
            ],
        }
        aws_lint(rules_data, ctx)
        wa520 = [r for r in ctx.results if r.rule_id == "WA520"]
        assert len(wa520) == 1

    def test_wa520_three_duplicates(self):
        """Three rules with same statement should produce one warning."""
        stmt = {"GeoMatchStatement": {"CountryCodes": ["FR"]}}
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule("r1", 1, "m1", stmt),
                self._make_rule("r2", 2, "m2", stmt),
                self._make_rule("r3", 3, "m3", stmt),
            ],
        }
        aws_lint(rules_data, ctx)
        wa520 = [r for r in ctx.results if r.rule_id == "WA520"]
        assert len(wa520) == 1
        assert "r1" in wa520[0].message
        assert "r2" in wa520[0].message
        assert "r3" in wa520[0].message

    def test_wa520_respects_phase_filter(self):
        stmt = {"GeoMatchStatement": {"CountryCodes": ["US"]}}
        ctx = LintContext(phase_filter=["aws_waf_rate_rules"])
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule("r1", 1, "m1", stmt),
                self._make_rule("r2", 2, "m2", stmt),
            ],
        }
        aws_lint(rules_data, ctx)
        wa520 = [r for r in ctx.results if r.rule_id == "WA520"]
        assert len(wa520) == 0


class TestWcuCapacity:
    """WA340: Estimated total WCU exceeds Web ACL limit."""

    def _make_rule(self, ref, priority, metric, statement):
        return {
            "ref": ref,
            "Priority": priority,
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": metric,
            },
            "Statement": statement,
        }

    def test_wa340_under_limit_no_warn(self):
        """A few simple rules should not trigger WA340."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule("r1", 1, "m1", {"GeoMatchStatement": {"CountryCodes": ["US"]}}),
                self._make_rule("r2", 2, "m2", {"GeoMatchStatement": {"CountryCodes": ["DE"]}}),
            ],
        }
        aws_lint(rules_data, ctx)
        wa340 = [r for r in ctx.results if r.rule_id == "WA340"]
        assert len(wa340) == 0

    def test_wa340_exceeds_limit(self):
        """Many managed rule groups should exceed WCU limit."""
        ctx = LintContext()
        # Each ManagedRuleGroupStatement estimates 100 WCU + 1 rule base = 101.
        # 16 of them = 1616 WCU > 1500
        rules = []
        for i in range(16):
            rules.append(
                self._make_rule(
                    f"r{i}",
                    i,
                    f"m{i}",
                    {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": f"RuleSet{i}",
                        }
                    },
                )
            )
        rules_data = {"aws_waf_managed_rules": rules}
        aws_lint(rules_data, ctx)
        wa340 = [r for r in ctx.results if r.rule_id == "WA340"]
        assert len(wa340) == 1
        assert "1500" in wa340[0].message

    def test_wa340_exactly_at_limit_no_warn(self):
        """WCU exactly at 1500 should NOT trigger WA340."""
        ctx = LintContext()
        # Each GeoMatch rule = 1 (rule base) + 2 (statement) = 3 WCU.
        # 500 rules * 3 = 1500 WCU exactly.
        rules = []
        for i in range(500):
            rules.append(
                self._make_rule(
                    f"r{i}",
                    i,
                    f"m{i}",
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                )
            )
        rules_data = {"aws_waf_custom_rules": rules}
        aws_lint(rules_data, ctx)
        wa340 = [r for r in ctx.results if r.rule_id == "WA340"]
        assert len(wa340) == 0

    def test_wa340_cross_phase_sum(self):
        """WCU is summed across all AWS phases."""
        ctx = LintContext()
        # 8 managed rule groups per phase * 2 phases = 16 * 101 = 1616 WCU
        rules_per_phase = []
        for i in range(8):
            rules_per_phase.append(
                self._make_rule(
                    f"r{i}",
                    i,
                    f"m{i}",
                    {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": f"RuleSet{i}",
                        }
                    },
                )
            )
        rules_per_phase2 = []
        for i in range(8, 16):
            rules_per_phase2.append(
                self._make_rule(
                    f"r{i}",
                    i,
                    f"m{i}",
                    {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": f"RuleSet{i}",
                        }
                    },
                )
            )
        rules_data = {
            "aws_waf_managed_rules": rules_per_phase,
            "aws_waf_custom_rules": rules_per_phase2,
        }
        aws_lint(rules_data, ctx)
        wa340 = [r for r in ctx.results if r.rule_id == "WA340"]
        assert len(wa340) == 1

    def test_wa340_respects_phase_filter(self):
        """WA340 should respect ctx.phase_filter."""
        ctx = LintContext(phase_filter=["aws_waf_custom_rules"])
        # Put expensive rules in managed_rules (filtered out)
        rules = []
        for i in range(16):
            rules.append(
                self._make_rule(
                    f"r{i}",
                    i,
                    f"m{i}",
                    {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": f"RuleSet{i}",
                        }
                    },
                )
            )
        rules_data = {"aws_waf_managed_rules": rules}
        aws_lint(rules_data, ctx)
        wa340 = [r for r in ctx.results if r.rule_id == "WA340"]
        assert len(wa340) == 0


class TestIpSetReferences:
    """WA326: IPSetReferenceStatement references IP Set not in lists section."""

    # Short ARN helpers to stay under line-length limit
    _BLOCKED = "arn:aws:wafv2:us-east-1:123:regional/ipset/blocked-ips/a1"
    _EXTERNAL = "arn:aws:wafv2:us-east-1:123:regional/ipset/external-set/b2"
    _REGEX = "arn:aws:wafv2:us-east-1:123:regional/regexpatternset/my-patterns/c3"

    def _make_rule(self, ref, priority, metric, statement):
        return {
            "ref": ref,
            "Priority": priority,
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": metric,
            },
            "Statement": statement,
        }

    def test_wa326_ipset_not_in_lists(self):
        """IPSet ARN name not in lists section triggers WA326."""
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "allowed-ips", "kind": "ip", "items": []},
            ],
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {"IPSetReferenceStatement": {"ARN": self._BLOCKED}},
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa326 = [r for r in ctx.results if r.rule_id == "WA326"]
        assert len(wa326) == 1
        assert "blocked-ips" in wa326[0].message

    def test_wa326_ipset_in_lists_no_warn(self):
        """IPSet ARN name matching a list does NOT trigger WA326."""
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "blocked-ips", "kind": "ip", "items": []},
            ],
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {"IPSetReferenceStatement": {"ARN": self._BLOCKED}},
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa326 = [r for r in ctx.results if r.rule_id == "WA326"]
        assert len(wa326) == 0

    def test_wa326_no_lists_section_no_warn(self):
        """Without a lists section, WA326 does not fire."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {"IPSetReferenceStatement": {"ARN": self._BLOCKED}},
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa326 = [r for r in ctx.results if r.rule_id == "WA326"]
        assert len(wa326) == 0

    def test_wa326_nested_ipset_in_and(self):
        """IPSet inside AndStatement is still checked."""
        ctx = LintContext()
        stmt = {
            "AndStatement": {
                "Statements": [
                    {
                        "IPSetReferenceStatement": {
                            "ARN": self._EXTERNAL,
                        }
                    },
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]
            }
        }
        rules_data = {
            "lists": [
                {"name": "allowed-ips", "kind": "ip", "items": []},
            ],
            "aws_waf_custom_rules": [self._make_rule("r1", 1, "m1", stmt)],
        }
        aws_lint(rules_data, ctx)
        wa326 = [r for r in ctx.results if r.rule_id == "WA326"]
        assert len(wa326) == 1
        assert "external-set" in wa326[0].message

    def test_wa326_non_ipset_arn_ignored(self):
        """ARNs for non-ipset resources are not checked by WA326."""
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "allowed-ips", "kind": "ip", "items": []},
            ],
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {
                        "RegexPatternSetReferenceStatement": {
                            "ARN": self._REGEX,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [
                                {"Priority": 0, "Type": "NONE"},
                            ],
                        }
                    },
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa326 = [r for r in ctx.results if r.rule_id == "WA326"]
        assert len(wa326) == 0

    def test_wa326_empty_lists_section_no_warn(self):
        """Empty lists section = no names to compare, no WA326."""
        ctx = LintContext()
        rules_data = {
            "lists": [],
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {"IPSetReferenceStatement": {"ARN": self._BLOCKED}},
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa326 = [r for r in ctx.results if r.rule_id == "WA326"]
        assert len(wa326) == 0


class TestRegexSetReferences:
    """WA327: RegexPatternSetReferenceStatement references set not in lists."""

    _REGEX_IN_LIST = (
        "arn:aws:wafv2:us-east-1:123456789012:regional/regexpatternset/bad-paths/rps-id-1"
    )
    _REGEX_EXTERNAL = (
        "arn:aws:wafv2:us-east-1:123456789012:regional/regexpatternset/external-patterns/rps-id-2"
    )

    @staticmethod
    def _make_rule(ref, priority, metric, stmt):
        return {
            "ref": ref,
            "Priority": priority,
            "Action": {"Block": {}},
            "Statement": stmt,
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": metric,
            },
        }

    def test_wa327_fires_when_regex_set_not_in_lists(self):
        """WA327 fires when regex set ARN references a set not in lists."""
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "bad-paths", "kind": "regex", "items": []},
            ],
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {
                        "RegexPatternSetReferenceStatement": {
                            "ARN": self._REGEX_EXTERNAL,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        }
                    },
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa327 = [r for r in ctx.results if r.rule_id == "WA327"]
        assert len(wa327) == 1
        assert "external-patterns" in wa327[0].message

    def test_wa327_no_fire_when_in_lists(self):
        """WA327 does not fire when regex set is in the lists section."""
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "bad-paths", "kind": "regex", "items": []},
            ],
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {
                        "RegexPatternSetReferenceStatement": {
                            "ARN": self._REGEX_IN_LIST,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        }
                    },
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa327 = [r for r in ctx.results if r.rule_id == "WA327"]
        assert len(wa327) == 0

    def test_wa327_no_fire_without_regex_lists(self):
        """Without regex lists in lists section, WA327 does not fire."""
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "blocklist", "kind": "ip", "items": []},
            ],
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {
                        "RegexPatternSetReferenceStatement": {
                            "ARN": self._REGEX_EXTERNAL,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        }
                    },
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa327 = [r for r in ctx.results if r.rule_id == "WA327"]
        assert len(wa327) == 0

    def test_wa327_no_fire_no_lists_section(self):
        """Without a lists section at all, WA327 does not fire."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {
                        "RegexPatternSetReferenceStatement": {
                            "ARN": self._REGEX_EXTERNAL,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        }
                    },
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa327 = [r for r in ctx.results if r.rule_id == "WA327"]
        assert len(wa327) == 0

    def test_wa327_nested_in_and(self):
        """Regex set inside AndStatement is still checked."""
        ctx = LintContext()
        stmt = {
            "AndStatement": {
                "Statements": [
                    {
                        "RegexPatternSetReferenceStatement": {
                            "ARN": self._REGEX_EXTERNAL,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        }
                    },
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]
            }
        }
        rules_data = {
            "lists": [{"name": "bad-paths", "kind": "regex", "items": []}],
            "aws_waf_custom_rules": [self._make_rule("r1", 1, "m1", stmt)],
        }
        aws_lint(rules_data, ctx)
        wa327 = [r for r in ctx.results if r.rule_id == "WA327"]
        assert len(wa327) == 1
        assert "external-patterns" in wa327[0].message

    def test_wa327_ipset_arn_not_matched(self):
        """IP set ARNs are not checked by WA327."""
        ctx = LintContext()
        rules_data = {
            "lists": [{"name": "bad-paths", "kind": "regex", "items": []}],
            "aws_waf_custom_rules": [
                self._make_rule(
                    "r1",
                    1,
                    "m1",
                    {
                        "IPSetReferenceStatement": {
                            "ARN": "arn:aws:wafv2:us-east-1:123:regional/ipset/x/id"
                        }
                    },
                )
            ],
        }
        aws_lint(rules_data, ctx)
        wa327 = [r for r in ctx.results if r.rule_id == "WA327"]
        assert len(wa327) == 0


class TestListItemCounts:
    """WA158: IP set exceeds 10,000 address limit."""

    @staticmethod
    def _unique_ips(n: int) -> list[str]:
        """Generate *n* unique /32 addresses for testing."""
        return [f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}/32" for i in range(n)]

    def test_wa158_under_limit_no_warn(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "small-set", "kind": "ip", "items": self._unique_ips(100)},
            ],
        }
        aws_lint(rules_data, ctx)
        wa158 = [r for r in ctx.results if r.rule_id == "WA158"]
        assert len(wa158) == 0

    def test_wa158_exactly_10000_no_warn(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "big-set", "kind": "ip", "items": self._unique_ips(10_000)},
            ],
        }
        aws_lint(rules_data, ctx)
        wa158 = [r for r in ctx.results if r.rule_id == "WA158"]
        assert len(wa158) == 0

    def test_wa158_exceeds_limit(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "huge-set", "kind": "ip", "items": self._unique_ips(10_001)},
            ],
        }
        aws_lint(rules_data, ctx)
        wa158 = [r for r in ctx.results if r.rule_id == "WA158"]
        assert len(wa158) == 1
        assert "huge-set" in wa158[0].message

    def test_wa158_duplicates_not_counted(self):
        """Duplicated items should not inflate the count."""
        ctx = LintContext()
        # 10_001 raw items but only 1 unique -- should NOT trigger.
        rules_data = {
            "lists": [
                {"name": "dup-set", "kind": "ip", "items": ["10.0.0.1"] * 10_001},
            ],
        }
        aws_lint(rules_data, ctx)
        wa158 = [r for r in ctx.results if r.rule_id == "WA158"]
        assert len(wa158) == 0

    def test_wa158_no_lists_section_no_warn(self):
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [],
        }
        aws_lint(rules_data, ctx)
        wa158 = [r for r in ctx.results if r.rule_id == "WA158"]
        assert len(wa158) == 0

    def test_wa158_multiple_lists_one_over(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "ok-set", "kind": "ip", "items": self._unique_ips(100)},
                {"name": "bad-set", "kind": "ip", "items": self._unique_ips(10_001)},
            ],
        }
        aws_lint(rules_data, ctx)
        wa158 = [r for r in ctx.results if r.rule_id == "WA158"]
        assert len(wa158) == 1
        assert "bad-set" in wa158[0].message


class TestReservedIPInList:
    """WA162: Reserved/bogon IP address in IP set."""

    def test_wa162_private_rfc1918(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "bad-set", "kind": "ip", "items": ["10.0.0.0/8"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa162 = [r for r in ctx.results if r.rule_id == "WA162"]
        assert len(wa162) == 1
        assert "RFC 1918 private" in wa162[0].message

    def test_wa162_cgnat(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "bad-set", "kind": "ip", "items": ["100.64.1.0/24"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa162 = [r for r in ctx.results if r.rule_id == "WA162"]
        assert len(wa162) == 1
        assert "CGNAT" in wa162[0].message

    def test_wa162_documentation_rfc5737(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "bad-set", "kind": "ip", "items": ["192.0.2.0/24"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa162 = [r for r in ctx.results if r.rule_id == "WA162"]
        assert len(wa162) == 1
        assert "documentation" in wa162[0].message

    def test_wa162_public_ip_ok(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "ok-set", "kind": "ip", "items": ["8.8.8.0/24"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa162 = [r for r in ctx.results if r.rule_id == "WA162"]
        assert len(wa162) == 0

    def test_wa162_multiple_reserved(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {
                    "name": "mixed-set",
                    "kind": "ip",
                    "items": ["8.8.8.0/24", "10.0.0.0/8", "192.168.1.0/24"],
                },
            ],
        }
        aws_lint(rules_data, ctx)
        wa162 = [r for r in ctx.results if r.rule_id == "WA162"]
        assert len(wa162) == 2  # 10.0.0.0/8 and 192.168.1.0/24

    def test_wa162_ipv6_documentation(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "ipv6-set", "kind": "ip", "items": ["2001:db8::/32"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa162 = [r for r in ctx.results if r.rule_id == "WA162"]
        assert len(wa162) == 1
        assert "documentation" in wa162[0].message

    def test_wa162_non_ip_list_skipped(self):
        """Non-IP lists (e.g., regex) should not be checked."""
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "regex-set", "kind": "regex", "items": ["^foo.*"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa162 = [r for r in ctx.results if r.rule_id == "WA162"]
        assert len(wa162) == 0

    def test_wa162_invalid_ip_skipped(self):
        """Invalid IP strings should not trigger WA162 (handled elsewhere)."""
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "bad-set", "kind": "ip", "items": ["not-an-ip"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa162 = [r for r in ctx.results if r.rule_id == "WA162"]
        assert len(wa162) == 0


class TestCatchAllInList:
    """WA163: Catch-all CIDR (0.0.0.0/0 or ::/0) in IP set."""

    def test_wa163_ipv4_catch_all(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "catch-all-set", "kind": "ip", "items": ["0.0.0.0/0"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa163 = [r for r in ctx.results if r.rule_id == "WA163"]
        assert len(wa163) == 1
        assert "catch-all" in wa163[0].message

    def test_wa163_ipv6_catch_all(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "catch-all-v6", "kind": "ip", "items": ["::/0"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa163 = [r for r in ctx.results if r.rule_id == "WA163"]
        assert len(wa163) == 1

    def test_wa163_non_catch_all_not_flagged(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "ok-set", "kind": "ip", "items": ["10.0.0.0/8", "8.8.8.0/24"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa163 = [r for r in ctx.results if r.rule_id == "WA163"]
        assert len(wa163) == 0

    def test_wa163_mixed_catch_all_and_others(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {
                    "name": "mixed",
                    "kind": "ip",
                    "items": ["0.0.0.0/0", "8.8.8.0/24", "::/0"],
                },
            ],
        }
        aws_lint(rules_data, ctx)
        wa163 = [r for r in ctx.results if r.rule_id == "WA163"]
        assert len(wa163) == 2


class TestIPSetOverlap:
    """WA164: Overlapping IP/CIDR entries within a single IP set."""

    def test_wa164_subnet_of_a_broader_entry(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {
                    "name": "overlap",
                    "kind": "ip",
                    "items": ["10.0.0.0/8", "10.1.0.0/16"],
                },
            ],
        }
        aws_lint(rules_data, ctx)
        wa164 = [r for r in ctx.results if r.rule_id == "WA164"]
        assert len(wa164) == 1
        assert "10.1.0.0/16" in wa164[0].message
        assert "10.0.0.0/8" in wa164[0].message

    def test_wa164_no_overlap(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {
                    "name": "disjoint",
                    "kind": "ip",
                    "items": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                },
            ],
        }
        aws_lint(rules_data, ctx)
        wa164 = [r for r in ctx.results if r.rule_id == "WA164"]
        assert len(wa164) == 0

    def test_wa164_ipv6_overlap(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "v6", "kind": "ip", "items": ["fc00::/7", "fc00::/8"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa164 = [r for r in ctx.results if r.rule_id == "WA164"]
        assert len(wa164) == 1

    def test_wa164_ignores_catch_all(self):
        # 0.0.0.0/0 would nominally "overlap" every entry — handled by
        # WA163 separately. WA164 must skip it to avoid spam.
        ctx = LintContext()
        rules_data = {
            "lists": [
                {
                    "name": "with-catch-all",
                    "kind": "ip",
                    "items": ["0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16"],
                },
            ],
        }
        aws_lint(rules_data, ctx)
        wa164 = [r for r in ctx.results if r.rule_id == "WA164"]
        assert len(wa164) == 0

    def test_wa164_duplicates_suppressed(self):
        ctx = LintContext()
        rules_data = {
            "lists": [
                {"name": "dup", "kind": "ip", "items": ["10.0.0.0/8", "10.0.0.0/8"]},
            ],
        }
        aws_lint(rules_data, ctx)
        wa164 = [r for r in ctx.results if r.rule_id == "WA164"]
        # Exact duplicates are left to a future dedup rule; overlap between
        # identical entries is not flagged (matches CF478 behaviour).
        assert len(wa164) == 0

    def test_wa164_sweep_line_fast_on_large_input(self):
        # 1_000 disjoint /32s should complete well under a second on the
        # O(n log n) sweep-line algorithm. The original brute-force check
        # was O(n²) and took multiple seconds at 10k entries (CF478 was
        # rewritten for exactly this reason).
        items = [f"203.0.{i // 256}.{i % 256}/32" for i in range(1000)]
        ctx = LintContext()
        rules_data = {"lists": [{"name": "big", "kind": "ip", "items": items}]}
        import time

        start = time.monotonic()
        aws_lint(rules_data, ctx)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"sweep-line too slow: {elapsed:.2f}s for 1000 items"


class TestRuleCount:
    """WA601: Total rule count may exceed default Web ACL limit of 100."""

    @staticmethod
    def _make_rule(ref, priority, metric):
        return {
            "ref": ref,
            "Priority": priority,
            "Action": {"Block": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": metric,
            },
            "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
        }

    def test_wa601_under_limit_no_warn(self):
        """10 rules should not trigger WA601."""
        ctx = LintContext()
        rules = [self._make_rule(f"r{i}", i, f"m{i}") for i in range(10)]
        rules_data = {"aws_waf_custom_rules": rules}
        aws_lint(rules_data, ctx)
        wa601 = [r for r in ctx.results if r.rule_id == "WA601"]
        assert len(wa601) == 0

    def test_wa601_exactly_100_no_warn(self):
        """Exactly 100 rules should NOT trigger WA601."""
        ctx = LintContext()
        rules = [self._make_rule(f"r{i}", i, f"m{i}") for i in range(100)]
        rules_data = {"aws_waf_custom_rules": rules}
        aws_lint(rules_data, ctx)
        wa601 = [r for r in ctx.results if r.rule_id == "WA601"]
        assert len(wa601) == 0

    def test_wa601_exceeds_limit(self):
        """101 rules should trigger WA601."""
        ctx = LintContext()
        rules = [self._make_rule(f"r{i}", i, f"m{i}") for i in range(101)]
        rules_data = {"aws_waf_custom_rules": rules}
        aws_lint(rules_data, ctx)
        wa601 = [r for r in ctx.results if r.rule_id == "WA601"]
        assert len(wa601) == 1
        assert "101" in wa601[0].message
        assert "100" in wa601[0].message

    def test_wa601_cross_phase_sum(self):
        """Rules are summed across all AWS phases."""
        ctx = LintContext()
        rules_a = [self._make_rule(f"a{i}", i, f"ma{i}") for i in range(60)]
        rules_b = [self._make_rule(f"b{i}", i, f"mb{i}") for i in range(50)]
        rules_data = {
            "aws_waf_custom_rules": rules_a,
            "aws_waf_rate_rules": rules_b,
        }
        aws_lint(rules_data, ctx)
        wa601 = [r for r in ctx.results if r.rule_id == "WA601"]
        assert len(wa601) == 1
        assert "110" in wa601[0].message

    def test_wa601_respects_phase_filter(self):
        """WA601 should respect ctx.phase_filter."""
        ctx = LintContext(phase_filter=["aws_waf_custom_rules"])
        # Put 101 rules in rate_rules (filtered out)
        rules = [self._make_rule(f"r{i}", i, f"m{i}") for i in range(101)]
        rules_data = {"aws_waf_rate_rules": rules}
        aws_lint(rules_data, ctx)
        wa601 = [r for r in ctx.results if r.rule_id == "WA601"]
        assert len(wa601) == 0

    def test_wa601_skips_non_aws_phases(self):
        """Non-AWS phases should not count toward the limit."""
        ctx = LintContext()
        rules = [self._make_rule(f"r{i}", i, f"m{i}") for i in range(101)]
        rules_data = {"http_request_dynamic_redirect": rules}
        aws_lint(rules_data, ctx)
        wa601 = [r for r in ctx.results if r.rule_id == "WA601"]
        assert len(wa601) == 0

    def test_wa601_non_dict_rules_not_counted(self):
        """Non-dict entries in the rules list should not inflate the count.

        We test _check_rule_count directly because validate_rules (per-phase)
        does not tolerate non-dict entries.
        """
        from octorules_aws.linter._plugin import _check_rule_count

        ctx = LintContext()
        rules: list = [self._make_rule(f"r{i}", i, f"m{i}") for i in range(99)]
        # Add non-dict entries that should be ignored by the counter
        rules.extend(["string-entry", 42, None])
        rules_data = {"aws_waf_custom_rules": rules}
        _check_rule_count(rules_data, ctx)
        wa601 = [r for r in ctx.results if r.rule_id == "WA601"]
        assert len(wa601) == 0

    def test_wa601_non_list_phase_skipped(self):
        """Phase with non-list value should be silently skipped."""
        ctx = LintContext()
        rules_data = {"aws_waf_custom_rules": "not-a-list"}
        aws_lint(rules_data, ctx)
        wa601 = [r for r in ctx.results if r.rule_id == "WA601"]
        assert len(wa601) == 0


class TestWA603Unreachable:
    """WA603: Rule unreachable after likely-always-true terminating rule."""

    @staticmethod
    def _geo_catch_all(ref: str, action: str = "Block", *, priority: int = 0):
        return {
            "ref": ref,
            "Priority": priority,
            "Action": {action: {}},
            "Statement": {
                "GeoMatchStatement": {
                    "CountryCodes": [f"X{i:02d}" for i in range(200)],
                }
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": ref,
            },
        }

    @staticmethod
    def _normal_rule(ref: str, *, priority: int = 1):
        return {
            "ref": ref,
            "Priority": priority,
            "Action": {"Block": {}},
            "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": ref,
            },
        }

    def test_wa603_unreachable_after_catch_all_block(self):
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._geo_catch_all("catch-all", priority=0),
                self._normal_rule("after", priority=1),
            ]
        }
        aws_lint(rules_data, ctx)
        wa603 = [r for r in ctx.results if r.rule_id == "WA603"]
        assert len(wa603) == 1
        assert wa603[0].ref == "after"

    def test_wa603_no_flag_for_count_action(self):
        """Count doesn't terminate — subsequent rules should NOT be flagged."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._geo_catch_all("counter", action="Count", priority=0),
                self._normal_rule("after", priority=1),
            ]
        }
        aws_lint(rules_data, ctx)
        wa603 = [r for r in ctx.results if r.rule_id == "WA603"]
        assert len(wa603) == 0

    def test_wa603_no_flag_for_normal_rule(self):
        """A rule with few country codes is not catch-all."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._normal_rule("first", priority=0),
                self._normal_rule("second", priority=1),
            ]
        }
        aws_lint(rules_data, ctx)
        wa603 = [r for r in ctx.results if r.rule_id == "WA603"]
        assert len(wa603) == 0

    def test_wa603_disabled_catch_all_no_flag(self):
        """Disabled catch-all should not make subsequent rules unreachable."""
        ctx = LintContext()
        catch_all = self._geo_catch_all("disabled", priority=0)
        catch_all["enabled"] = False
        rules_data = {
            "aws_waf_custom_rules": [
                catch_all,
                self._normal_rule("after", priority=1),
            ]
        }
        aws_lint(rules_data, ctx)
        wa603 = [r for r in ctx.results if r.rule_id == "WA603"]
        assert len(wa603) == 0

    def test_wa603_multiple_unreachable(self):
        """Multiple rules after catch-all should all be flagged."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": [
                self._geo_catch_all("catch-all", priority=0),
                self._normal_rule("after1", priority=1),
                self._normal_rule("after2", priority=2),
            ]
        }
        aws_lint(rules_data, ctx)
        wa603 = [r for r in ctx.results if r.rule_id == "WA603"]
        assert len(wa603) == 2
