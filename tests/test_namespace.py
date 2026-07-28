"""Tests for AWS WAF namespace registration and zone file normalization."""

from octorules.config import normalize_zone_format
from octorules.phases import PROVIDER_NAMESPACES

from octorules_aws.provider import AwsWafProvider


def test_provider_namespace_attribute() -> None:
    """Test that AwsWafProvider has NAMESPACE class attribute."""
    assert AwsWafProvider.NAMESPACE == "aws"


def test_namespace_registered() -> None:
    """Test that AWS namespace is registered with all expected keys."""
    assert "aws" in PROVIDER_NAMESPACES

    aws_namespace = PROVIDER_NAMESPACES["aws"]

    # Check all phase keys
    assert aws_namespace["waf_custom_rules"] == "aws.waf_custom_rules"
    assert aws_namespace["waf_rate_rules"] == "aws.waf_rate_rules"
    assert aws_namespace["waf_managed_rules"] == "aws.waf_managed_rules"
    assert aws_namespace["waf_rule_group_rules"] == "aws.waf_rule_group_rules"

    # Check non-phase keys
    assert aws_namespace["custom_rulesets"] == "aws.custom_rulesets"
    assert aws_namespace["waf_settings"] == "aws.waf_settings"

    # Verify complete mapping
    expected_keys = {
        "waf_custom_rules",
        "waf_rate_rules",
        "waf_managed_rules",
        "waf_rule_group_rules",
        "custom_rulesets",
        "waf_settings",
    }
    assert set(aws_namespace.keys()) == expected_keys


def test_normalize_nested_zone_format() -> None:
    """Test that nested AWS zone format normalizes to flat keys."""
    nested_zone = {
        "aws": {
            "waf_custom_rules": [
                {
                    "ref": "test-rule",
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "Statement": {"IPSetReferenceStatement": {"ARN": "arn:..."}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "test-rule",
                    },
                }
            ],
            "waf_settings": {
                "DefaultAction": {"Allow": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "test-acl",
                },
            },
        }
    }

    normalized = normalize_zone_format(nested_zone)

    # Check that nested format is flattened to canonical keys
    assert "aws.waf_custom_rules" in normalized
    assert "aws.waf_settings" in normalized
    assert "aws" not in normalized

    # Verify the content is preserved
    assert len(normalized["aws.waf_custom_rules"]) == 1
    assert normalized["aws.waf_custom_rules"][0]["ref"] == "test-rule"
    assert normalized["aws.waf_settings"]["DefaultAction"] == {"Allow": {}}
