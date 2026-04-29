"""Tests for the AWS WAF audit IP extractor.

The underlying ``collect_ipset_arns`` is shared with ``_statement_util`` and
fully covered there (``tests/test_statement_util.py``). This module focuses
on ``_extract_ips`` which composes ARN collection with rule-walking.
"""

from octorules_aws.audit import _extract_ips


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
