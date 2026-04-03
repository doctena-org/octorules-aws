"""Tests for the shared _statement_util module."""

from octorules_aws._statement_util import IPSET_ARN_RE, collect_ipset_arns


class TestIPSetARNRE:
    def test_matches_regional_arn(self):
        arn = "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/my-ipset/abc123"
        m = IPSET_ARN_RE.match(arn)
        assert m is not None
        assert m.group(1) == "my-ipset"

    def test_no_match_on_non_ipset(self):
        arn = "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/my-rg/abc123"
        assert IPSET_ARN_RE.match(arn) is None


class TestCollectIPSetArns:
    def test_direct_ipset(self):
        stmt = {
            "IPSetReferenceStatement": {
                "ARN": "arn:aws:wafv2:us-east-1:123:regional/ipset/my-set/id1"
            }
        }
        arns = collect_ipset_arns(stmt)
        assert len(arns) == 1
        assert "my-set" in arns[0]

    def test_nested_or(self):
        stmt = {
            "OrStatement": {
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
        arns = collect_ipset_arns(stmt)
        assert len(arns) == 2

    def test_no_ipset_returns_empty(self):
        stmt = {"ByteMatchStatement": {"FieldToMatch": {"UriPath": {}}}}
        assert collect_ipset_arns(stmt) == []

    def test_not_statement(self):
        stmt = {
            "NotStatement": {
                "Statement": {
                    "IPSetReferenceStatement": {
                        "ARN": "arn:aws:wafv2:us-east-1:123:regional/ipset/blocked/id"
                    }
                }
            }
        }
        assert len(collect_ipset_arns(stmt)) == 1

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
        assert len(collect_ipset_arns(stmt)) == 1
