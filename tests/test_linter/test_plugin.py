"""Tests for the AWS WAF linter plugin."""

from __future__ import annotations

from octorules.linter.engine import LintContext, Severity
from octorules.linter.plugin import get_registered_plugins

from octorules_aws.linter._plugin import AWS_RULE_IDS, aws_lint


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

    def test_skips_non_list_rules(self):
        """aws_lint should skip phases whose value is not a list."""
        ctx = LintContext()
        rules_data = {
            "aws_waf_custom_rules": "not-a-list",
        }
        aws_lint(rules_data, ctx)
        assert len(ctx.results) == 0

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
