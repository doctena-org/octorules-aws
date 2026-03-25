"""Tests for the AWS WAF audit IP extractor."""

from __future__ import annotations

from octorules_aws.audit import _collect_ipset_arns, _extract_ips


class TestCollectIPSetARNs:
    def test_direct_ipset(self):
        stmt = {
            "IPSetReferenceStatement": {
                "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/my-ipset/abc123"
            }
        }
        arns = _collect_ipset_arns(stmt)
        assert len(arns) == 1
        assert "my-ipset" in arns[0]

    def test_nested_and(self):
        stmt = {
            "AndStatement": {
                "Statements": [
                    {
                        "IPSetReferenceStatement": {
                            "ARN": "arn:aws:wafv2:us-east-1:123:regional/ipset/set1/id1"
                        }
                    },
                    {
                        "IPSetReferenceStatement": {
                            "ARN": "arn:aws:wafv2:us-east-1:123:regional/ipset/set2/id2"
                        }
                    },
                ]
            }
        }
        arns = _collect_ipset_arns(stmt)
        assert len(arns) == 2

    def test_nested_not(self):
        stmt = {
            "NotStatement": {
                "Statement": {
                    "IPSetReferenceStatement": {
                        "ARN": "arn:aws:wafv2:us-east-1:123:regional/ipset/blocked/id"
                    }
                }
            }
        }
        arns = _collect_ipset_arns(stmt)
        assert len(arns) == 1

    def test_rate_based_scope_down(self):
        stmt = {
            "RateBasedStatement": {
                "ScopeDownStatement": {
                    "IPSetReferenceStatement": {
                        "ARN": "arn:aws:wafv2:us-east-1:123:regional/ipset/rateip/id"
                    }
                }
            }
        }
        arns = _collect_ipset_arns(stmt)
        assert len(arns) == 1

    def test_no_ipset(self):
        stmt = {"ByteMatchStatement": {"FieldToMatch": {"UriPath": {}}}}
        assert _collect_ipset_arns(stmt) == []


class TestAWSExtractIPs:
    def test_extracts_list_refs_from_ipset_reference(self):
        """IPSet name extracted from ARN and placed in list_refs."""
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "block-bad",
                    "Action": {"Block": {}},
                    "Statement": {
                        "IPSetReferenceStatement": {
                            "ARN": "arn:aws:wafv2:us-east-1:123:regional/ipset/bad-ips/id1"
                        }
                    },
                }
            ],
        }
        results = _extract_ips(rules_data, "aws_waf_custom_rules")
        assert len(results) == 1
        assert results[0].ref == "block-bad"
        assert results[0].action == "Block"
        assert results[0].list_refs == ["bad-ips"]
        assert results[0].ip_ranges == []  # IPs resolved by core, not here

    def test_multiple_ipset_refs(self):
        """Multiple IPSet references in nested statements."""
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "multi-ref",
                    "Action": {"Block": {}},
                    "Statement": {
                        "OrStatement": {
                            "Statements": [
                                {
                                    "IPSetReferenceStatement": {
                                        "ARN": (
                                            "arn:aws:wafv2:us-east-1:123:regional/ipset/set-a/id1"
                                        )
                                    }
                                },
                                {
                                    "IPSetReferenceStatement": {
                                        "ARN": (
                                            "arn:aws:wafv2:us-east-1:123:regional/ipset/set-b/id2"
                                        )
                                    }
                                },
                            ]
                        }
                    },
                }
            ],
        }
        results = _extract_ips(rules_data, "aws_waf_custom_rules")
        assert len(results) == 1
        assert set(results[0].list_refs) == {"set-a", "set-b"}

    def test_ignores_non_aws_phases(self):
        rules_data = {
            "waf_custom_rules": [
                {
                    "ref": "r1",
                    "Action": {"Block": {}},
                    "Statement": {"IPSetReferenceStatement": {"ARN": "arn:aws:..."}},
                }
            ],
        }
        assert _extract_ips(rules_data, "waf_custom_rules") == []

    def test_no_statement(self):
        rules_data = {"aws_waf_custom_rules": [{"ref": "r1", "Action": {"Block": {}}}]}
        assert _extract_ips(rules_data, "aws_waf_custom_rules") == []

    def test_no_ipset_in_statement(self):
        """Statement without IPSetReferenceStatement returns nothing."""
        rules_data = {
            "aws_waf_custom_rules": [
                {
                    "ref": "r1",
                    "Action": {"Block": {}},
                    "Statement": {"ByteMatchStatement": {"FieldToMatch": {"UriPath": {}}}},
                }
            ],
        }
        assert _extract_ips(rules_data, "aws_waf_custom_rules") == []
