"""Tests for AWS WAF namespace registration and zone file normalization."""

import pytest
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
    assert aws_namespace["waf_custom_rules"] == "aws_waf_custom_rules"
    assert aws_namespace["waf_rate_rules"] == "aws_waf_rate_rules"
    assert aws_namespace["waf_managed_rules"] == "aws_waf_managed_rules"
    assert aws_namespace["waf_rule_group_rules"] == "aws_waf_rule_group_rules"

    # Check non-phase keys
    assert aws_namespace["custom_rulesets"] == "custom_rulesets"
    assert aws_namespace["waf_settings"] == "aws_waf_settings"

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
    assert "aws_waf_custom_rules" in normalized
    assert "aws_waf_settings" in normalized
    assert "aws" not in normalized

    # Verify the content is preserved
    assert len(normalized["aws_waf_custom_rules"]) == 1
    assert normalized["aws_waf_custom_rules"][0]["ref"] == "test-rule"
    assert normalized["aws_waf_settings"]["DefaultAction"] == {"Allow": {}}


def test_normalize_mixed_nested_and_flat() -> None:
    """Test normalization with both nested (aws:) and flat keys.

    The normalize function accepts both but logs a deprecation warning
    about the flat spelling.
    """
    mixed_zone = {
        "aws": {
            "waf_custom_rules": [
                {
                    "ref": "nested-rule",
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "Statement": {"IPSetReferenceStatement": {"ARN": "arn:..."}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "nested-rule",
                    },
                }
            ]
        },
        "aws_waf_rate_rules": [
            {
                "ref": "flat-rule",
                "Priority": 10,
                "Action": {"Block": {}},
                "Statement": {"RateBasedStatement": {"Limit": 2000, "AggregateKeyType": "IP"}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "flat-rule",
                },
            }
        ],
    }

    # Normalize should accept both and flatten them
    normalized = normalize_zone_format(mixed_zone)

    # Both should be in the result as flat keys
    assert "aws_waf_custom_rules" in normalized
    assert "aws_waf_rate_rules" in normalized
    assert "aws" not in normalized


def test_lists_in_nested_format() -> None:
    """Test that lists: can be nested under aws:."""
    nested_zone = {
        "aws": {
            "lists": [
                {
                    "name": "blocked-ips",
                    "kind": "ip",
                    "items": [
                        {"ip": "10.0.0.0/8"},
                        {"ip": "172.16.0.0/12"},
                    ],
                }
            ]
        }
    }

    normalized = normalize_zone_format(nested_zone)

    # Check that lists are preserved
    assert "lists" in normalized
    assert len(normalized["lists"]) == 1
    assert normalized["lists"][0]["name"] == "blocked-ips"


def test_custom_rulesets_in_nested_format() -> None:
    """Test that custom_rulesets can be nested under aws:."""
    nested_zone = {
        "aws": {
            "custom_rulesets": [
                {
                    "name": "bot-protection",
                    "capacity": 100,
                    "phase": "aws_waf_custom",
                    "rules": [
                        {
                            "ref": "block-bots",
                            "Priority": 1,
                            "Action": {"Block": {}},
                            "Statement": {
                                "ByteMatchStatement": {
                                    "FieldToMatch": {"SingleHeader": {"Name": "user-agent"}},
                                    "PositionalConstraint": "CONTAINS",
                                    "SearchString": "bot",
                                    "TextTransformations": [
                                        {"Priority": 0, "Type": "LOWERCASE"}
                                    ],
                                }
                            },
                            "VisibilityConfig": {
                                "SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": True,
                                "MetricName": "block-bots",
                            },
                        }
                    ],
                }
            ]
        }
    }

    normalized = normalize_zone_format(nested_zone)

    # Check that custom_rulesets are preserved
    assert "custom_rulesets" in normalized
    assert len(normalized["custom_rulesets"]) == 1
    assert normalized["custom_rulesets"][0]["name"] == "bot-protection"
