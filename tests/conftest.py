"""Shared fixtures for octorules-aws tests."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_waf_client():
    """Create a mock boto3 wafv2 client.

    Not spec'd against ``botocore.client.BaseClient`` — boto3 clients
    are dynamically generated at runtime so a BaseClient spec blocks
    the very WAFv2 methods tests need to mock (``list_regex_pattern_sets``,
    ``list_web_acls``, etc.).  A proper spec would require instantiating
    a real client (which we don't do in unit tests).
    """
    client = MagicMock()
    # Default to empty regex pattern set list so IP-Set-only tests
    # don't fail when list_lists/get_all_lists calls both APIs.
    client.list_regex_pattern_sets.return_value = {"RegexPatternSets": []}
    return client


@pytest.fixture
def web_acl():
    """A sample Web ACL response dict."""
    return {
        "Name": "my-acl",
        "Id": "acl-123",
        "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/acl-123",
        "DefaultAction": {"Allow": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "my-acl",
        },
        "Rules": [
            {
                "Name": "block-bad-ips",
                "Priority": 1,
                "Action": {"Block": {}},
                "Statement": {"IPSetReferenceStatement": {"ARN": "arn:aws:wafv2:ip-set"}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "block-bad-ips",
                },
            },
            {
                "Name": "rate-limit-api",
                "Priority": 2,
                "Action": {"Block": {}},
                "Statement": {
                    "RateBasedStatement": {
                        "Limit": 2000,
                        "AggregateKeyType": "IP",
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "rate-limit-api",
                },
            },
            {
                "Name": "aws-managed-common",
                "Priority": 3,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesCommonRuleSet",
                    }
                },
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "aws-managed-common",
                },
            },
            {
                "Name": "my-rule-group",
                "Priority": 4,
                "Statement": {
                    "RuleGroupReferenceStatement": {
                        "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/rg-id",
                    }
                },
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": "my-rule-group",
                },
            },
        ],
    }
