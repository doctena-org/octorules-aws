"""Tests for the AWS WAF provider."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from octorules.provider.base import BaseProvider, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderConnectionError, ProviderError

from octorules_aws import AwsWafProvider


def _zs(zone_id: str = "acl-123", label: str = "") -> Scope:
    return Scope(zone_id=zone_id, label=label)


def _make_client_error(code: str, message: str = "error") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


class TestBaseProviderProtocol:
    def test_satisfies_protocol(self, mock_waf_client):
        instance = AwsWafProvider(client=mock_waf_client)
        assert isinstance(instance, BaseProvider)


class TestProperties:
    def test_max_workers(self, mock_waf_client):
        provider = AwsWafProvider(max_workers=4, client=mock_waf_client)
        assert provider.max_workers == 4

    def test_account_id_is_none(self, mock_waf_client):
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider.account_id is None

    def test_account_name_is_none(self, mock_waf_client):
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider.account_name is None

    def test_zone_plans_is_empty(self, mock_waf_client):
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider.zone_plans == {}


class TestResolveZoneId:
    def test_found(self, mock_waf_client):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [
                {"Name": "my-acl", "Id": "acl-123", "ARN": "arn:aws:wafv2:acl-123"},
            ]
        }
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider.resolve_zone_id("my-acl") == "acl-123"

    def test_not_found(self, mock_waf_client):
        mock_waf_client.list_web_acls.return_value = {"WebACLs": []}
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(Exception, match="No Web ACL found"):
            provider.resolve_zone_id("missing-acl")

    def test_multiple_matches(self, mock_waf_client):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [
                {"Name": "dup", "Id": "id-1", "ARN": "arn:1"},
                {"Name": "dup", "Id": "id-2", "ARN": "arn:2"},
            ]
        }
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(Exception, match="Multiple Web ACLs found"):
            provider.resolve_zone_id("dup")


class TestGetPhaseRules:
    def _setup(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        return provider

    def test_custom_rules(self, mock_waf_client, web_acl):
        provider = self._setup(mock_waf_client, web_acl)
        rules = provider.get_phase_rules(_zs(), "aws_waf_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == "block-bad-ips"

    def test_rate_rules(self, mock_waf_client, web_acl):
        provider = self._setup(mock_waf_client, web_acl)
        rules = provider.get_phase_rules(_zs(), "aws_waf_rate")
        assert len(rules) == 1
        assert rules[0]["ref"] == "rate-limit-api"

    def test_managed_rules(self, mock_waf_client, web_acl):
        provider = self._setup(mock_waf_client, web_acl)
        rules = provider.get_phase_rules(_zs(), "aws_waf_managed")
        assert len(rules) == 1
        assert rules[0]["ref"] == "aws-managed-common"

    def test_rule_group_rules(self, mock_waf_client, web_acl):
        provider = self._setup(mock_waf_client, web_acl)
        rules = provider.get_phase_rules(_zs(), "aws_waf_rule_group")
        assert len(rules) == 1
        assert rules[0]["ref"] == "my-rule-group"
        assert "RuleGroupReferenceStatement" in rules[0]["Statement"]

    def test_unknown_phase_returns_empty(self, mock_waf_client, web_acl):
        provider = self._setup(mock_waf_client, web_acl)
        assert provider.get_phase_rules(_zs(), "http_request_dynamic_redirect") == []

    def test_empty_acl(self, mock_waf_client):
        empty_acl = {
            "Name": "empty",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
            "Rules": [],
        }
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "empty", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": empty_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("empty")
        assert provider.get_phase_rules(_zs(), "aws_waf_custom") == []


class TestPutPhaseRules:
    def test_replaces_only_matching_phase(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")

        new_rules = [
            {
                "ref": "new-custom-rule",
                "Priority": 10,
                "Action": {"Count": {}},
                "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                "VisibilityConfig": {},
            }
        ]
        count = provider.put_phase_rules(_zs(), "aws_waf_custom", new_rules)
        assert count == 1

        # Verify update_web_acl was called with other phases preserved
        call_kwargs = mock_waf_client.update_web_acl.call_args[1]
        updated_rules = call_kwargs["Rules"]
        names = [r["Name"] for r in updated_rules]
        # Original rate + managed + rule group rules preserved, custom replaced
        assert "rate-limit-api" in names
        assert "aws-managed-common" in names
        assert "my-rule-group" in names
        assert "new-custom-rule" in names
        assert "block-bad-ips" not in names

    def test_returns_rule_count(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        count = provider.put_phase_rules(_zs(), "aws_waf_custom", [])
        assert count == 0

    @patch("octorules_aws.provider.time.sleep")
    def test_retries_on_stale_lock(self, _mock_sleep, mock_waf_client, web_acl):
        """WAFOptimisticLockException triggers re-GET and retry."""
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")

        # First update fails with stale lock, second succeeds
        mock_waf_client.update_web_acl.side_effect = [
            _make_client_error("WAFOptimisticLockException"),
            None,
        ]
        count = provider.put_phase_rules(_zs(), "aws_waf_custom", [])
        assert count == 0
        assert mock_waf_client.update_web_acl.call_count == 2
        # get_web_acl called once per attempt (re-GET on retry)
        assert mock_waf_client.get_web_acl.call_count == 2

    @patch("octorules_aws.provider.time.sleep")
    def test_stale_lock_exhausted_raises(self, _mock_sleep, mock_waf_client, web_acl):
        """After max retries, the exception propagates."""
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")

        mock_waf_client.update_web_acl.side_effect = _make_client_error(
            "WAFOptimisticLockException"
        )
        with pytest.raises(ProviderError, match="WAFOptimisticLockException"):
            provider.put_phase_rules(_zs(), "aws_waf_custom", [])

    def test_non_lock_error_not_retried(self, mock_waf_client, web_acl):
        """Other ClientErrors are not retried."""
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")

        mock_waf_client.update_web_acl.side_effect = _make_client_error("ValidationException")
        with pytest.raises(ProviderError, match="ValidationException"):
            provider.put_phase_rules(_zs(), "aws_waf_custom", [])
        assert mock_waf_client.update_web_acl.call_count == 1


class TestGetAllPhaseRules:
    def test_all_phases(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        result = provider.get_all_phase_rules(_zs())
        assert "aws_waf_custom" in result
        assert "aws_waf_rate" in result
        assert "aws_waf_managed" in result
        assert "aws_waf_rule_group" in result
        assert result.failed_phases == []

    def test_filtered_phases(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        result = provider.get_all_phase_rules(_zs(), provider_ids=["aws_waf_rate"])
        assert "aws_waf_rate" in result
        assert "aws_waf_custom" not in result

    def test_ignores_non_aws_phases(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        result = provider.get_all_phase_rules(_zs(), provider_ids=["http_request_dynamic_redirect"])
        assert dict(result) == {}


class TestRuleGroups:
    def test_list_custom_rulesets(self, mock_waf_client):
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [
                {"Id": "rg-1", "Name": "my-group", "Description": "test"},
            ]
        }
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.list_custom_rulesets(_zs())
        assert len(result) == 1
        assert result[0]["id"] == "rg-1"
        assert result[0]["name"] == "my-group"

    def test_get_custom_ruleset(self, mock_waf_client):
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-1", "Name": "my-group"}]
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {
                "Rules": [
                    {
                        "Name": "rule-1",
                        "Priority": 1,
                        "Statement": {"ByteMatchStatement": {}},
                    }
                ],
                "VisibilityConfig": {},
            },
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        rules = provider.get_custom_ruleset(_zs(), "rg-1")
        assert len(rules) == 1
        assert rules[0]["ref"] == "rule-1"

    def test_create_custom_ruleset_raises_on_missing_id(self, mock_waf_client):
        """create_custom_ruleset raises ProviderError when Summary.Id is missing."""
        mock_waf_client.create_rule_group.return_value = {"Summary": {}}
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match=r"missing Summary\.Id"):
            provider.create_custom_ruleset(_zs(), "rg-name", "phase", 100)

    def test_put_custom_ruleset(self, mock_waf_client):
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-1", "Name": "my-group"}]
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {"VisibilityConfig": {}},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        count = provider.put_custom_ruleset(_zs(), "rg-1", [{"ref": "r1", "Priority": 1}])
        assert count == 1
        call_kwargs = mock_waf_client.update_rule_group.call_args[1]
        assert call_kwargs["Rules"][0]["Name"] == "r1"


class TestIPSets:
    def test_list_lists(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [
                {"Id": "ip-1", "Name": "blocklist", "Description": "Bad IPs"},
            ]
        }
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.list_lists(_zs())
        assert len(result) == 1
        assert result[0]["name"] == "blocklist"
        assert result[0]["kind"] == "ip"

    def test_create_list(self, mock_waf_client):
        mock_waf_client.create_ip_set.return_value = {
            "Summary": {"Id": "ip-new", "Name": "new-set"}
        }
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.create_list(_zs(), "new-set", "ip", "A new set")
        assert result["id"] == "ip-new"
        call_kwargs = mock_waf_client.create_ip_set.call_args[1]
        assert call_kwargs["IPAddressVersion"] == "IPV4"

    def test_create_list_raises_on_missing_id(self, mock_waf_client):
        """create_list raises ProviderError when Summary.Id is missing."""
        mock_waf_client.create_ip_set.return_value = {"Summary": {}}
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match=r"missing Summary\.Id"):
            provider.create_list(_zs(), "new-set", "ip")

    def test_create_list_raises_on_empty_summary(self, mock_waf_client):
        """create_list raises ProviderError when Summary is absent."""
        mock_waf_client.create_ip_set.return_value = {}
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match=r"missing Summary\.Id"):
            provider.create_list(_zs(), "new-set", "ip")

    def test_create_list_ipv6(self, mock_waf_client):
        mock_waf_client.create_ip_set.return_value = {"Summary": {"Id": "ip-v6", "Name": "v6-set"}}
        provider = AwsWafProvider(client=mock_waf_client)
        provider.create_list(_zs(), "v6-set", "ipv6")
        call_kwargs = mock_waf_client.create_ip_set.call_args[1]
        assert call_kwargs["IPAddressVersion"] == "IPV6"

    def test_get_list_items(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [{"Id": "ip-1", "Name": "blocklist"}]
        }
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {"Addresses": ["1.1.1.1/32", "2.2.2.0/24"]},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        items = provider.get_list_items(_zs(), "ip-1")
        assert items == [{"ip": "1.1.1.1/32"}, {"ip": "2.2.2.0/24"}]

    def test_put_list_items(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [{"Id": "ip-1", "Name": "blocklist"}]
        }
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {"Addresses": []},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        op_id = provider.put_list_items(_zs(), "ip-1", [{"ip": "3.3.3.3/32"}, {"ip": "4.4.4.0/24"}])
        assert op_id.startswith("aws-sync-")
        call_kwargs = mock_waf_client.update_ip_set.call_args[1]
        assert call_kwargs["Addresses"] == ["3.3.3.3/32", "4.4.4.0/24"]

    def test_put_list_items_rejects_malformed_item(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [{"Id": "ip-1", "Name": "blocklist"}]
        }
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {"Addresses": []},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="List item 1 missing 'ip' or 'value' key"):
            provider.put_list_items(_zs(), "ip-1", [{"ip": "1.1.1.1/32"}, {"bogus": "data"}])
        mock_waf_client.update_ip_set.assert_not_called()

    def test_put_list_items_accepts_value_key(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [{"Id": "ip-1", "Name": "blocklist"}]
        }
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {"Addresses": []},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        op_id = provider.put_list_items(_zs(), "ip-1", [{"value": "10.0.0.0/8"}])
        assert op_id.startswith("aws-sync-")
        call_kwargs = mock_waf_client.update_ip_set.call_args[1]
        assert call_kwargs["Addresses"] == ["10.0.0.0/8"]

    def test_delete_list(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [{"Id": "ip-1", "Name": "blocklist"}]
        }
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.delete_list(_zs(), "ip-1")
        mock_waf_client.delete_ip_set.assert_called_once()

    def test_poll_bulk_operation_returns_completed(self, mock_waf_client):
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider.poll_bulk_operation(_zs(), "op-123") == "completed"

    def test_get_all_lists(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [
                {"Id": "ip-1", "Name": "blocklist", "Description": "Bad"},
                {"Id": "ip-2", "Name": "allowlist", "Description": "Good"},
            ]
        }
        mock_waf_client.get_ip_set.side_effect = [
            {"IPSet": {"Addresses": ["1.1.1.1/32"]}, "LockToken": "l1"},
            {"IPSet": {"Addresses": ["2.2.2.2/32"]}, "LockToken": "l2"},
        ]
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.get_all_lists(_zs())
        assert "blocklist" in result
        assert "allowlist" in result
        assert result["blocklist"]["items"] == [{"ip": "1.1.1.1/32"}]

    def test_get_all_lists_filtered(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [
                {"Id": "ip-1", "Name": "blocklist", "Description": "Bad"},
                {"Id": "ip-2", "Name": "allowlist", "Description": "Good"},
            ]
        }
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {"Addresses": ["1.1.1.1/32"]},
            "LockToken": "l1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.get_all_lists(_zs(), list_names=["blocklist"])
        assert "blocklist" in result
        assert "allowlist" not in result


class TestExceptionWrapping:
    def test_access_denied_becomes_provider_auth_error(self, mock_waf_client):
        mock_waf_client.list_web_acls.side_effect = _make_client_error("AccessDeniedException")
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.resolve_zone_id("my-acl")

    def test_no_credentials_becomes_provider_auth_error(self, mock_waf_client):
        mock_waf_client.list_web_acls.side_effect = NoCredentialsError()
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.resolve_zone_id("my-acl")

    def test_client_error_becomes_provider_error(self, mock_waf_client):
        mock_waf_client.list_web_acls.side_effect = _make_client_error(
            "WAFInternalErrorException", "Internal error"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError):
            provider.resolve_zone_id("my-acl")

    def test_connection_error_becomes_provider_connection_error(self, mock_waf_client):
        mock_waf_client.list_web_acls.side_effect = EndpointConnectionError(
            endpoint_url="https://wafv2.us-east-1.amazonaws.com"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderConnectionError):
            provider.resolve_zone_id("my-acl")

    def test_expired_token_becomes_auth_error(self, mock_waf_client):
        mock_waf_client.list_web_acls.side_effect = _make_client_error("ExpiredTokenException")
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.resolve_zone_id("my-acl")


class TestPagination:
    def test_paginate_web_acls(self, mock_waf_client):
        """list_web_acls pagination via NextMarker."""
        mock_waf_client.list_web_acls.side_effect = [
            {
                "WebACLs": [{"Name": "acl-1", "Id": "id-1", "ARN": "arn:1"}],
                "NextMarker": "page2",
            },
            {
                "WebACLs": [{"Name": "acl-2", "Id": "id-2", "ARN": "arn:2"}],
            },
        ]
        provider = AwsWafProvider(client=mock_waf_client)
        # resolve_zone_id uses _paginate_list internally — search both pages
        zone_id = provider.resolve_zone_id("acl-2")
        assert zone_id == "id-2"
        assert mock_waf_client.list_web_acls.call_count == 2

    def test_paginate_rule_groups(self, mock_waf_client):
        """list_rule_groups pagination via NextMarker."""
        mock_waf_client.list_rule_groups.side_effect = [
            {
                "RuleGroups": [{"Id": "rg-1", "Name": "group-1"}],
                "NextMarker": "page2",
            },
            {
                "RuleGroups": [{"Id": "rg-2", "Name": "group-2"}],
            },
        ]
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.list_custom_rulesets(_zs())
        assert len(result) == 2
        assert result[0]["id"] == "rg-1"
        assert result[1]["id"] == "rg-2"
        assert mock_waf_client.list_rule_groups.call_count == 2

    def test_paginate_ip_sets(self, mock_waf_client):
        """list_ip_sets pagination via NextMarker."""
        mock_waf_client.list_ip_sets.side_effect = [
            {
                "IPSets": [{"Id": "ip-1", "Name": "set-1", "Description": "first"}],
                "NextMarker": "page2",
            },
            {
                "IPSets": [{"Id": "ip-2", "Name": "set-2", "Description": "second"}],
            },
        ]
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.list_lists(_zs())
        assert len(result) == 2
        assert result[0]["id"] == "ip-1"
        assert result[1]["id"] == "ip-2"
        assert mock_waf_client.list_ip_sets.call_count == 2

    def test_repeated_marker_breaks_loop(self, mock_waf_client, caplog):
        """Repeated NextMarker triggers loop detection and breaks."""
        import logging

        mock_waf_client.list_web_acls.side_effect = [
            {
                "WebACLs": [{"Name": "acl-1", "Id": "id-1", "ARN": "arn:1"}],
                "NextMarker": "same-marker",
            },
            {
                "WebACLs": [{"Name": "acl-2", "Id": "id-2", "ARN": "arn:2"}],
                "NextMarker": "same-marker",  # Repeated!
            },
        ]
        provider = AwsWafProvider(client=mock_waf_client)
        with caplog.at_level(logging.WARNING):
            acls = provider._paginate_list(mock_waf_client.list_web_acls, "WebACLs")
        # Should have results from both pages (2nd page fetched before detecting repeat)
        assert len(acls) == 2
        assert "Pagination loop detected" in caplog.text
        # 2 calls: first page + second page (loop detected on 2nd marker)
        assert mock_waf_client.list_web_acls.call_count == 2

    def test_single_page_no_marker(self, mock_waf_client):
        """Single-page response (no NextMarker) works without looping."""
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-1", "ARN": "arn:1"}],
        }
        provider = AwsWafProvider(client=mock_waf_client)
        zone_id = provider.resolve_zone_id("my-acl")
        assert zone_id == "acl-1"
        assert mock_waf_client.list_web_acls.call_count == 1


class TestN1Elimination:
    def test_get_all_custom_rulesets_single_list_call(self, mock_waf_client):
        """get_all_custom_rulesets should call list_rule_groups only once."""
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [
                {"Id": "rg-1", "Name": "group-1"},
                {"Id": "rg-2", "Name": "group-2"},
            ],
        }
        mock_waf_client.get_rule_group.side_effect = [
            {
                "RuleGroup": {"Rules": [{"Name": "r1", "Priority": 1}], "VisibilityConfig": {}},
                "LockToken": "l1",
            },
            {
                "RuleGroup": {"Rules": [{"Name": "r2", "Priority": 2}], "VisibilityConfig": {}},
                "LockToken": "l2",
            },
        ]
        provider = AwsWafProvider(client=mock_waf_client)
        results = provider.get_all_custom_rulesets(_zs())
        assert len(results) == 2
        # list_rule_groups should have been called exactly once (not once per group)
        assert mock_waf_client.list_rule_groups.call_count == 1

    def test_get_all_lists_single_list_call(self, mock_waf_client):
        """get_all_lists should call list_ip_sets only once."""
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [
                {"Id": "ip-1", "Name": "blocklist", "Description": "Bad"},
                {"Id": "ip-2", "Name": "allowlist", "Description": "Good"},
            ],
        }
        mock_waf_client.get_ip_set.side_effect = [
            {"IPSet": {"Addresses": ["1.1.1.1/32"]}, "LockToken": "l1"},
            {"IPSet": {"Addresses": ["2.2.2.2/32"]}, "LockToken": "l2"},
        ]
        provider = AwsWafProvider(client=mock_waf_client)
        results = provider.get_all_lists(_zs())
        assert len(results) == 2
        # list_ip_sets should have been called exactly once (not once per set)
        assert mock_waf_client.list_ip_sets.call_count == 1


class TestUpdateListDescription:
    def test_update_list_description(self, mock_waf_client):
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [{"Id": "ip-1", "Name": "blocklist"}]
        }
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {"Addresses": ["1.1.1.1/32", "2.2.2.0/24"]},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.update_list_description(_zs(), "ip-1", "Updated description")

        mock_waf_client.update_ip_set.assert_called_once()
        call_kwargs = mock_waf_client.update_ip_set.call_args[1]
        assert call_kwargs["Description"] == "Updated description"
        assert call_kwargs["Addresses"] == ["1.1.1.1/32", "2.2.2.0/24"]
        assert call_kwargs["Name"] == "blocklist"
        assert call_kwargs["LockToken"] == "lock-1"


class TestGetAllCustomRulesets:
    def test_returns_rules_keyed_by_id(self, mock_waf_client):
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [
                {"Id": "rg-1", "Name": "group-1", "Description": "desc-1"},
            ],
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {
                "Rules": [{"Name": "r1", "Priority": 1, "Statement": {}}],
                "VisibilityConfig": {},
            },
            "LockToken": "l1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        results = provider.get_all_custom_rulesets(_zs())
        assert "rg-1" in results
        assert results["rg-1"]["name"] == "group-1"
        assert len(results["rg-1"]["rules"]) == 1
        assert results["rg-1"]["rules"][0]["ref"] == "r1"

    def test_empty_when_no_rule_groups(self, mock_waf_client):
        mock_waf_client.list_rule_groups.return_value = {"RuleGroups": []}
        provider = AwsWafProvider(client=mock_waf_client)
        results = provider.get_all_custom_rulesets(_zs())
        assert results == {}

    def test_filtered_by_ruleset_ids(self, mock_waf_client):
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [
                {"Id": "rg-1", "Name": "group-1"},
                {"Id": "rg-2", "Name": "group-2"},
            ],
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {"Rules": [], "VisibilityConfig": {}},
            "LockToken": "l1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        results = provider.get_all_custom_rulesets(_zs(), ruleset_ids=["rg-1"])
        assert "rg-1" in results
        assert "rg-2" not in results


class TestPhaseRegistration:
    def test_phases_registered(self):
        from octorules.phases import PHASE_BY_NAME, get_phase

        assert "aws_waf_custom_rules" in PHASE_BY_NAME
        assert "aws_waf_rate_rules" in PHASE_BY_NAME
        assert "aws_waf_managed_rules" in PHASE_BY_NAME
        assert "aws_waf_rule_group_rules" in PHASE_BY_NAME

        phase = get_phase("aws_waf_custom_rules")
        assert phase.provider_id == "aws_waf_custom"
        assert phase.zone_level is True
        assert phase.account_level is False

        rg_phase = get_phase("aws_waf_rule_group_rules")
        assert rg_phase.provider_id == "aws_waf_rule_group"

    def test_phase_ids_derived_from_phases(self):
        from octorules_aws._phases import AWS_PHASE_IDS, AWS_PHASE_NAMES, AWS_PHASES

        assert AWS_PHASE_IDS == {
            "aws_waf_custom",
            "aws_waf_rate",
            "aws_waf_managed",
            "aws_waf_rule_group",
        }
        assert AWS_PHASE_IDS == frozenset(p.provider_id for p in AWS_PHASES)
        assert AWS_PHASE_NAMES == frozenset(p.friendly_name for p in AWS_PHASES)


class TestAuthErrors:
    """Auth-related errors are wrapped as ProviderAuthError."""

    def _setup_provider(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        return provider

    def test_get_phase_rules_auth_error(self, mock_waf_client, web_acl):
        """AccessDeniedException during get_phase_rules → ProviderAuthError."""
        provider = self._setup_provider(mock_waf_client, web_acl)
        mock_waf_client.get_web_acl.side_effect = _make_client_error("AccessDeniedException")
        with pytest.raises(ProviderAuthError, match="AccessDeniedException"):
            provider.get_phase_rules(_zs(), "aws_waf_custom")

    def test_put_phase_rules_auth_error(self, mock_waf_client, web_acl):
        """AccessDeniedException during put_phase_rules → ProviderAuthError."""
        provider = self._setup_provider(mock_waf_client, web_acl)
        mock_waf_client.get_web_acl.side_effect = _make_client_error("AccessDeniedException")
        with pytest.raises(ProviderAuthError, match="AccessDeniedException"):
            provider.put_phase_rules(_zs(), "aws_waf_custom", [])

    def test_no_credentials_error(self, mock_waf_client):
        """NoCredentialsError → ProviderAuthError regardless of which method is called."""
        mock_waf_client.list_web_acls.side_effect = NoCredentialsError()
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.list_zones()


class TestConnectionErrors:
    """Connection-related errors are wrapped as ProviderConnectionError."""

    def _setup_provider(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        return provider

    def test_get_phase_rules_connection_error(self, mock_waf_client, web_acl):
        """EndpointConnectionError during get_phase_rules → ProviderConnectionError."""
        provider = self._setup_provider(mock_waf_client, web_acl)
        mock_waf_client.get_web_acl.side_effect = EndpointConnectionError(
            endpoint_url="https://wafv2.us-east-1.amazonaws.com"
        )
        with pytest.raises(ProviderConnectionError):
            provider.get_phase_rules(_zs(), "aws_waf_custom")

    def test_connection_error_wraps(self, mock_waf_client):
        """Plain ConnectionError → ProviderConnectionError."""
        mock_waf_client.list_web_acls.side_effect = ConnectionError("Connection refused")
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderConnectionError, match="Connection refused"):
            provider.resolve_zone_id("my-acl")


class TestLockRetry:
    """WAFOptimisticLockException retry behavior."""

    def _setup_provider(self, mock_waf_client, web_acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        return provider

    @patch("octorules_aws.provider.time.sleep")
    def test_lock_retry_succeeds_on_second_attempt(self, _mock_sleep, mock_waf_client, web_acl):
        """First attempt hits WAFOptimisticLockException, second succeeds."""
        provider = self._setup_provider(mock_waf_client, web_acl)
        mock_waf_client.update_web_acl.side_effect = [
            _make_client_error("WAFOptimisticLockException"),
            None,
        ]
        count = provider.put_phase_rules(_zs(), "aws_waf_custom", [])
        assert count == 0
        assert mock_waf_client.update_web_acl.call_count == 2
        # Re-fetches the Web ACL on retry to get fresh LockToken
        assert mock_waf_client.get_web_acl.call_count == 2

    @patch("octorules_aws.provider.time.sleep")
    def test_lock_retry_exhausted(self, _mock_sleep, mock_waf_client, web_acl):
        """All 3 attempts hit WAFOptimisticLockException → raises ProviderError."""
        provider = self._setup_provider(mock_waf_client, web_acl)
        mock_waf_client.update_web_acl.side_effect = _make_client_error(
            "WAFOptimisticLockException"
        )
        with pytest.raises(ProviderError, match="WAFOptimisticLockException"):
            provider.put_phase_rules(_zs(), "aws_waf_custom", [])
        # All 3 retry attempts exhausted
        assert mock_waf_client.update_web_acl.call_count == 3


class TestGenericErrors:
    """Non-auth ClientErrors are wrapped as ProviderError (not ProviderAuthError)."""

    def test_client_error_non_auth_code(self, mock_waf_client):
        """ThrottlingException → ProviderError, not ProviderAuthError."""
        mock_waf_client.list_web_acls.side_effect = _make_client_error("ThrottlingException")
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="ThrottlingException") as exc_info:
            provider.resolve_zone_id("my-acl")
        # Must NOT be a ProviderAuthError subclass
        assert type(exc_info.value) is ProviderError


class TestSupports:
    def test_supports_custom_rulesets_and_lists(self):
        assert "custom_rulesets" in AwsWafProvider.SUPPORTS
        assert "lists" in AwsWafProvider.SUPPORTS

    def test_supports_zone_discovery(self):
        assert "zone_discovery" in AwsWafProvider.SUPPORTS

    def test_provider_supports_helper(self):
        from octorules.provider.base import (
            SUPPORTS_CUSTOM_RULESETS,
            SUPPORTS_LISTS,
            SUPPORTS_ZONE_DISCOVERY,
            provider_supports,
        )

        prov = AwsWafProvider.__new__(AwsWafProvider)
        assert provider_supports(prov, SUPPORTS_CUSTOM_RULESETS)
        assert provider_supports(prov, SUPPORTS_LISTS)
        assert provider_supports(prov, SUPPORTS_ZONE_DISCOVERY)


class TestMalformedResponses:
    """Provider handles malformed or incomplete API responses gracefully."""

    def _setup(self, mock_waf_client, acl):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")
        return provider

    def test_get_phase_rules_empty_rules_list(self, mock_waf_client):
        """Provider handles empty Rules list in Web ACL response."""
        acl = {
            "Name": "empty",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
            "Rules": [],
        }
        provider = self._setup(mock_waf_client, acl)
        assert provider.get_phase_rules(_zs(), "aws_waf_custom") == []
        assert provider.get_phase_rules(_zs(), "aws_waf_rate") == []
        assert provider.get_phase_rules(_zs(), "aws_waf_managed") == []
        assert provider.get_phase_rules(_zs(), "aws_waf_rule_group") == []

    def test_get_phase_rules_missing_rules_key(self, mock_waf_client):
        """Provider handles Web ACL response with no Rules key at all."""
        acl = {
            "Name": "no-rules",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
        }
        provider = self._setup(mock_waf_client, acl)
        assert provider.get_phase_rules(_zs(), "aws_waf_custom") == []

    def test_get_phase_rules_rule_missing_name(self, mock_waf_client):
        """Rules without Name field don't crash the provider."""
        acl = {
            "Name": "bad-rules",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
            "Rules": [
                {
                    # No "Name" key
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "Statement": {"GeoMatchStatement": {"CountryCodes": ["XX"]}},
                    "VisibilityConfig": {},
                },
            ],
        }
        provider = self._setup(mock_waf_client, acl)
        rules = provider.get_phase_rules(_zs(), "aws_waf_custom")
        assert len(rules) == 1
        # _normalize_rule uses .pop("Name", "") so missing Name -> empty ref
        assert rules[0]["ref"] == ""

    def test_get_phase_rules_rule_missing_statement(self, mock_waf_client):
        """Rules without Statement field classify as custom and don't crash."""
        acl = {
            "Name": "no-stmt",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
            "Rules": [
                {
                    "Name": "bare-rule",
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "VisibilityConfig": {},
                    # No "Statement" key
                },
            ],
        }
        provider = self._setup(mock_waf_client, acl)
        # Missing Statement -> _classify_phase falls through to "aws_waf_custom"
        rules = provider.get_phase_rules(_zs(), "aws_waf_custom")
        assert len(rules) == 1
        assert rules[0]["ref"] == "bare-rule"

    def test_get_all_phase_rules_empty_acl(self, mock_waf_client):
        """get_all_phase_rules returns empty result for an ACL with no rules."""
        acl = {
            "Name": "empty",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
            "Rules": [],
        }
        provider = self._setup(mock_waf_client, acl)
        result = provider.get_all_phase_rules(_zs())
        assert dict(result) == {}
        assert result.failed_phases == []

    def test_get_all_phase_rules_missing_rules_key(self, mock_waf_client):
        """get_all_phase_rules handles ACL with no Rules key."""
        acl = {
            "Name": "no-rules",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
        }
        provider = self._setup(mock_waf_client, acl)
        result = provider.get_all_phase_rules(_zs())
        assert dict(result) == {}
        assert result.failed_phases == []

    def test_list_rule_groups_empty(self, mock_waf_client):
        """Empty rule group list returns empty dict."""
        mock_waf_client.list_rule_groups.return_value = {"RuleGroups": []}
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider.get_all_custom_rulesets(_zs()) == {}

    def test_list_rule_groups_missing_key(self, mock_waf_client):
        """Response with no RuleGroups key returns empty list."""
        mock_waf_client.list_rule_groups.return_value = {}
        provider = AwsWafProvider(client=mock_waf_client)
        # _paginate_list uses .get("RuleGroups", []) so this should be empty
        result = provider.list_custom_rulesets(_zs())
        assert result == []

    def test_get_custom_ruleset_empty_rules(self, mock_waf_client):
        """Rule Group with empty Rules list returns empty list."""
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-1", "Name": "empty-group"}]
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {"Rules": [], "VisibilityConfig": {}},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        rules = provider.get_custom_ruleset(_zs(), "rg-1")
        assert rules == []

    def test_get_custom_ruleset_missing_rules_key(self, mock_waf_client):
        """Rule Group response with no Rules key returns empty list."""
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-1", "Name": "no-rules-group"}]
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {"VisibilityConfig": {}},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        rules = provider.get_custom_ruleset(_zs(), "rg-1")
        assert rules == []

    def test_list_ip_sets_empty(self, mock_waf_client):
        """Empty IP set list returns empty list."""
        mock_waf_client.list_ip_sets.return_value = {"IPSets": []}
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.list_lists(_zs())
        assert result == []

    def test_get_list_items_empty_addresses(self, mock_waf_client):
        """IP Set with empty Addresses returns empty list."""
        mock_waf_client.list_ip_sets.return_value = {
            "IPSets": [{"Id": "ip-1", "Name": "empty-set"}]
        }
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {"Addresses": []},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        items = provider.get_list_items(_zs(), "ip-1")
        assert items == []

    def test_get_list_items_missing_addresses_key(self, mock_waf_client):
        """IP Set response with no Addresses key returns empty list."""
        mock_waf_client.list_ip_sets.return_value = {"IPSets": [{"Id": "ip-1", "Name": "no-addrs"}]}
        mock_waf_client.get_ip_set.return_value = {
            "IPSet": {},
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        items = provider.get_list_items(_zs(), "ip-1")
        assert items == []

    def test_decode_bytes_in_rule(self, mock_waf_client):
        """Rules with bytes SearchString are decoded to str."""
        acl = {
            "Name": "bytes-acl",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
            "Rules": [
                {
                    "Name": "byte-match",
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": b"bad-bot",
                            "FieldToMatch": {"UriPath": {}},
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "VisibilityConfig": {},
                },
            ],
        }
        provider = self._setup(mock_waf_client, acl)
        rules = provider.get_phase_rules(_zs(), "aws_waf_custom")
        assert len(rules) == 1
        search_str = rules[0]["Statement"]["ByteMatchStatement"]["SearchString"]
        assert isinstance(search_str, str)
        assert search_str == "bad-bot"


class TestConcurrentWorkers:
    """Tests for concurrent/parallel usage with max_workers > 1."""

    def _setup_provider(self, mock_waf_client, web_acl, *, max_workers=4):
        """Create a provider with multiple Web ACLs resolved."""
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [
                {"Name": "acl-a", "Id": "id-a", "ARN": "arn:a"},
                {"Name": "acl-b", "Id": "id-b", "ARN": "arn:b"},
                {"Name": "acl-c", "Id": "id-c", "ARN": "arn:c"},
            ]
        }
        provider = AwsWafProvider(client=mock_waf_client, max_workers=max_workers)
        provider.resolve_zone_id("acl-a")
        provider.resolve_zone_id("acl-b")
        provider.resolve_zone_id("acl-c")
        return provider

    def test_concurrent_get_phase_rules_success(self, mock_waf_client, web_acl):
        """Multiple concurrent get_phase_rules calls all return correct results."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        provider = self._setup_provider(mock_waf_client, web_acl)
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": web_acl,
            "LockToken": "lock-1",
        }

        zone_ids = ["id-a", "id-b", "id-c"]
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    Scope(zone_id=zid, label=""),
                    "aws_waf_custom",
                ): zid
                for zid in zone_ids
            }
            results = {}
            for future in as_completed(futures):
                zid = futures[future]
                results[zid] = future.result()

        # All three zones got results
        assert len(results) == 3
        for zid in zone_ids:
            assert len(results[zid]) == 1
            assert results[zid][0]["ref"] == "block-bad-ips"

    def test_concurrent_partial_failure(self, mock_waf_client, web_acl):
        """Some zones succeed while others raise ProviderError."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        provider = self._setup_provider(mock_waf_client, web_acl)

        call_count = 0

        def mock_get_web_acl(**kwargs):
            nonlocal call_count
            call_count += 1
            acl_id = kwargs.get("Id", "")
            if acl_id == "id-b":
                raise _make_client_error("WAFInternalErrorException", "Internal error")
            return {"WebACL": web_acl, "LockToken": "lock-1"}

        mock_waf_client.get_web_acl.side_effect = mock_get_web_acl

        zone_ids = ["id-a", "id-b", "id-c"]
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    Scope(zone_id=zid, label=""),
                    "aws_waf_custom",
                ): zid
                for zid in zone_ids
            }
            results = {}
            errors = {}
            for future in as_completed(futures):
                zid = futures[future]
                try:
                    results[zid] = future.result()
                except ProviderError as e:
                    errors[zid] = e

        # id-a and id-c succeed, id-b fails
        assert "id-a" in results
        assert "id-c" in results
        assert "id-b" in errors
        assert len(results) == 2
        assert len(errors) == 1

    def test_concurrent_auth_error_propagates(self, mock_waf_client, web_acl):
        """ProviderAuthError propagates from concurrent execution."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        provider = self._setup_provider(mock_waf_client, web_acl)

        def mock_get_web_acl(**kwargs):
            acl_id = kwargs.get("Id", "")
            if acl_id == "id-a":
                raise _make_client_error("AccessDeniedException", "Forbidden")
            return {"WebACL": web_acl, "LockToken": "lock-1"}

        mock_waf_client.get_web_acl.side_effect = mock_get_web_acl

        zone_ids = ["id-a", "id-b", "id-c"]
        auth_errors = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    provider.get_phase_rules,
                    Scope(zone_id=zid, label=""),
                    "aws_waf_custom",
                ): zid
                for zid in zone_ids
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except ProviderAuthError as e:
                    auth_errors.append(e)

        # At least one ProviderAuthError surfaced
        assert len(auth_errors) >= 1

    def test_concurrent_resolve_zone_id_populates_all_metadata(self, mock_waf_client):
        """Concurrent resolve_zone_id calls populate _web_acl_meta for all ACLs."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        acl_names = [f"acl-{i}" for i in range(10)]

        def mock_list_web_acls(**kwargs):
            return {
                "WebACLs": [
                    {"Name": name, "Id": f"id-{name}", "ARN": f"arn:{name}"} for name in acl_names
                ]
            }

        mock_waf_client.list_web_acls.side_effect = mock_list_web_acls
        provider = AwsWafProvider(client=mock_waf_client, max_workers=4)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(provider.resolve_zone_id, name): name for name in acl_names}
            results = {}
            for future in as_completed(futures):
                name = futures[future]
                results[name] = future.result()

        # All 10 ACLs resolved
        assert len(results) == 10
        for name in acl_names:
            assert results[name] == f"id-{name}"
        # All metadata populated (accessed under lock)
        assert len(provider._web_acl_meta) == 10


class TestCreateListErrorWrapping:
    """boto3 ClientError from create_ip_set is wrapped by _wrap_provider_errors."""

    def test_client_error_wrapped(self, mock_waf_client):
        """ClientError from create_ip_set is wrapped as ProviderError."""
        mock_waf_client.create_ip_set.side_effect = _make_client_error(
            "WAFInternalErrorException", "Internal error"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="Internal error"):
            provider.create_list(_zs(), "test", "ip")

    def test_auth_error_wrapped(self, mock_waf_client):
        """AccessDeniedException from create_ip_set is wrapped as ProviderAuthError."""
        mock_waf_client.create_ip_set.side_effect = _make_client_error(
            "AccessDeniedException", "Access denied"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.create_list(_zs(), "test", "ip")

    def test_duplicate_name_error(self, mock_waf_client):
        """WAFDuplicateItemException is wrapped as ProviderError."""
        mock_waf_client.create_ip_set.side_effect = _make_client_error(
            "WAFDuplicateItemException", "already exists"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="already exists"):
            provider.create_list(_zs(), "test", "ip")

    def test_limit_exceeded(self, mock_waf_client):
        """WAFLimitsExceededException is wrapped as ProviderError."""
        mock_waf_client.create_ip_set.side_effect = _make_client_error(
            "WAFLimitsExceededException", "Quota exceeded"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="Quota exceeded"):
            provider.create_list(_zs(), "test", "ip")

    def test_expired_token_wrapped(self, mock_waf_client):
        """ExpiredTokenException from create_ip_set is wrapped as ProviderAuthError."""
        mock_waf_client.create_ip_set.side_effect = _make_client_error(
            "ExpiredTokenException", "Token expired"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.create_list(_zs(), "test", "ip")

    def test_no_credentials_wrapped(self, mock_waf_client):
        """NoCredentialsError from create_ip_set is wrapped as ProviderAuthError."""
        mock_waf_client.create_ip_set.side_effect = NoCredentialsError()
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.create_list(_zs(), "test", "ip")


class TestCreateCustomRulesetErrorWrapping:
    """boto3 ClientError from create_rule_group is wrapped by _wrap_provider_errors."""

    def test_client_error_wrapped(self, mock_waf_client):
        """ClientError from create_rule_group is wrapped as ProviderError."""
        mock_waf_client.create_rule_group.side_effect = _make_client_error(
            "WAFInternalErrorException", "Internal error"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="Internal error"):
            provider.create_custom_ruleset(_zs(), "rg-name", "phase", 100)

    def test_auth_error_wrapped(self, mock_waf_client):
        """AccessDeniedException from create_rule_group is wrapped as ProviderAuthError."""
        mock_waf_client.create_rule_group.side_effect = _make_client_error(
            "AccessDeniedException", "Access denied"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.create_custom_ruleset(_zs(), "rg-name", "phase", 100)

    def test_duplicate_name_error(self, mock_waf_client):
        """WAFDuplicateItemException is wrapped as ProviderError."""
        mock_waf_client.create_rule_group.side_effect = _make_client_error(
            "WAFDuplicateItemException", "already exists"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="already exists"):
            provider.create_custom_ruleset(_zs(), "rg-name", "phase", 100)

    def test_limit_exceeded(self, mock_waf_client):
        """WAFLimitsExceededException is wrapped as ProviderError."""
        mock_waf_client.create_rule_group.side_effect = _make_client_error(
            "WAFLimitsExceededException", "Quota exceeded"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="Quota exceeded"):
            provider.create_custom_ruleset(_zs(), "rg-name", "phase", 100)

    def test_no_credentials_wrapped(self, mock_waf_client):
        """NoCredentialsError from create_rule_group is wrapped as ProviderAuthError."""
        mock_waf_client.create_rule_group.side_effect = NoCredentialsError()
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.create_custom_ruleset(_zs(), "rg-name", "phase", 100)


class TestCreateCustomRulesetSuccess:
    """Success-path tests for create_custom_ruleset."""

    def test_success_returns_id_and_name(self, mock_waf_client):
        """Successful create returns dict with id and name from Summary."""
        mock_waf_client.create_rule_group.return_value = {
            "Summary": {"Id": "rg-new-123", "Name": "my-new-group"}
        }
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.create_custom_ruleset(
            _zs(), "my-new-group", "phase", 200, "A description"
        )
        assert result == {"id": "rg-new-123", "name": "my-new-group"}

    def test_correct_create_rule_group_args(self, mock_waf_client):
        """Verify the correct arguments are passed to create_rule_group."""
        mock_waf_client.create_rule_group.return_value = {
            "Summary": {"Id": "rg-abc", "Name": "test-group"}
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.create_custom_ruleset(_zs(), "test-group", "phase", 150, "Test desc")

        mock_waf_client.create_rule_group.assert_called_once()
        call_kwargs = mock_waf_client.create_rule_group.call_args[1]
        assert call_kwargs["Name"] == "test-group"
        assert call_kwargs["Scope"] == "REGIONAL"
        assert call_kwargs["Capacity"] == 150
        assert call_kwargs["Description"] == "Test desc"
        assert call_kwargs["Rules"] == []
        assert call_kwargs["VisibilityConfig"]["MetricName"] == "test-group"
        assert call_kwargs["VisibilityConfig"]["SampledRequestsEnabled"] is True
        assert call_kwargs["VisibilityConfig"]["CloudWatchMetricsEnabled"] is True

    def test_name_fallback_when_summary_name_missing(self, mock_waf_client):
        """If Summary.Name is missing, the requested name is used as fallback."""
        mock_waf_client.create_rule_group.return_value = {"Summary": {"Id": "rg-fallback"}}
        provider = AwsWafProvider(client=mock_waf_client)
        result = provider.create_custom_ruleset(_zs(), "requested-name", "phase", 100)
        assert result["name"] == "requested-name"


class TestDeleteCustomRuleset:
    """Tests for delete_custom_ruleset."""

    def test_success(self, mock_waf_client):
        """Successful delete calls get_rule_group for LockToken then delete_rule_group."""
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-1", "Name": "my-group"}]
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {"Rules": [], "VisibilityConfig": {}},
            "LockToken": "lock-del-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.delete_custom_ruleset(_zs(), "rg-1")

        # Verify get_rule_group was called to fetch the lock token
        mock_waf_client.get_rule_group.assert_called_once_with(
            Name="my-group", Scope="REGIONAL", Id="rg-1"
        )
        # Verify delete_rule_group was called with correct args
        mock_waf_client.delete_rule_group.assert_called_once_with(
            Name="my-group", Scope="REGIONAL", Id="rg-1", LockToken="lock-del-1"
        )

    def test_error_wrapping(self, mock_waf_client):
        """ClientError from delete_rule_group is wrapped as ProviderError."""
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-1", "Name": "my-group"}]
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {"Rules": [], "VisibilityConfig": {}},
            "LockToken": "lock-1",
        }
        mock_waf_client.delete_rule_group.side_effect = _make_client_error(
            "WAFInternalErrorException", "Internal error"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderError, match="Internal error"):
            provider.delete_custom_ruleset(_zs(), "rg-1")

    def test_auth_error_wrapping(self, mock_waf_client):
        """AccessDeniedException from delete_rule_group is wrapped as ProviderAuthError."""
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-1", "Name": "my-group"}]
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {"Rules": [], "VisibilityConfig": {}},
            "LockToken": "lock-1",
        }
        mock_waf_client.delete_rule_group.side_effect = _make_client_error(
            "AccessDeniedException", "Access denied"
        )
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(ProviderAuthError):
            provider.delete_custom_ruleset(_zs(), "rg-1")

    def test_find_rule_group_failure(self, mock_waf_client):
        """delete_custom_ruleset raises when rule group ID not found."""
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-other", "Name": "other-group"}]
        }
        provider = AwsWafProvider(client=mock_waf_client)
        with pytest.raises(Exception, match=r"Rule Group.*not found"):
            provider.delete_custom_ruleset(_zs(), "rg-missing")
        # delete_rule_group should never be called
        mock_waf_client.delete_rule_group.assert_not_called()

    @patch("octorules_aws.provider.time.sleep")
    def test_lock_retry_on_stale_token(self, _mock_sleep, mock_waf_client):
        """WAFOptimisticLockException triggers retry for delete_custom_ruleset."""
        mock_waf_client.list_rule_groups.return_value = {
            "RuleGroups": [{"Id": "rg-1", "Name": "my-group"}]
        }
        mock_waf_client.get_rule_group.return_value = {
            "RuleGroup": {"Rules": [], "VisibilityConfig": {}},
            "LockToken": "lock-1",
        }
        mock_waf_client.delete_rule_group.side_effect = [
            _make_client_error("WAFOptimisticLockException"),
            None,
        ]
        provider = AwsWafProvider(client=mock_waf_client)
        provider.delete_custom_ruleset(_zs(), "rg-1")
        assert mock_waf_client.delete_rule_group.call_count == 2
        # get_rule_group called once per attempt (re-fetch for fresh LockToken)
        assert mock_waf_client.get_rule_group.call_count == 2


class TestCloudFrontScope:
    """Tests for CLOUDFRONT scope configuration."""

    def test_explicit_cloudfront_scope(self, mock_waf_client):
        """waf_scope='CLOUDFRONT' is stored and passed to API calls."""
        provider = AwsWafProvider(client=mock_waf_client, waf_scope="CLOUDFRONT")
        assert provider._waf_scope == "CLOUDFRONT"

    def test_cloudfront_scope_in_list_web_acls(self, mock_waf_client):
        """CLOUDFRONT scope is passed through to list_web_acls pagination."""
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "cf-acl", "Id": "cf-id", "ARN": "arn:cf"}]
        }
        provider = AwsWafProvider(client=mock_waf_client, waf_scope="CLOUDFRONT")
        provider.resolve_zone_id("cf-acl")
        call_kwargs = mock_waf_client.list_web_acls.call_args[1]
        assert call_kwargs["Scope"] == "CLOUDFRONT"

    def test_cloudfront_scope_in_get_web_acl(self, mock_waf_client):
        """CLOUDFRONT scope is passed through to get_web_acl."""
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "cf-acl", "Id": "cf-id", "ARN": "arn:cf"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": {
                "Name": "cf-acl",
                "Id": "cf-id",
                "DefaultAction": {"Allow": {}},
                "VisibilityConfig": {},
                "Rules": [],
            },
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client, waf_scope="CLOUDFRONT")
        provider.resolve_zone_id("cf-acl")
        provider.get_phase_rules(Scope(zone_id="cf-id", label=""), "aws_waf_custom")
        call_kwargs = mock_waf_client.get_web_acl.call_args[1]
        assert call_kwargs["Scope"] == "CLOUDFRONT"

    def test_cloudfront_scope_in_create_rule_group(self, mock_waf_client):
        """CLOUDFRONT scope is passed through to create_rule_group."""
        mock_waf_client.create_rule_group.return_value = {
            "Summary": {"Id": "rg-cf", "Name": "cf-group"}
        }
        provider = AwsWafProvider(client=mock_waf_client, waf_scope="CLOUDFRONT")
        provider.create_custom_ruleset(_zs(), "cf-group", "phase", 100)
        call_kwargs = mock_waf_client.create_rule_group.call_args[1]
        assert call_kwargs["Scope"] == "CLOUDFRONT"

    def test_env_var_fallback(self, mock_waf_client, monkeypatch):
        """AWS_WAF_SCOPE env var is used when waf_scope is not provided."""
        monkeypatch.setenv("AWS_WAF_SCOPE", "CLOUDFRONT")
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider._waf_scope == "CLOUDFRONT"

    def test_env_var_fallback_regional(self, mock_waf_client, monkeypatch):
        """AWS_WAF_SCOPE=REGIONAL env var works correctly."""
        monkeypatch.setenv("AWS_WAF_SCOPE", "REGIONAL")
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider._waf_scope == "REGIONAL"

    def test_invalid_scope_raises(self, mock_waf_client):
        """Invalid waf_scope raises ConfigError."""
        from octorules.config import ConfigError

        with pytest.raises(ConfigError, match="Invalid waf_scope"):
            AwsWafProvider(client=mock_waf_client, waf_scope="INVALID")

    def test_invalid_env_var_scope_raises(self, mock_waf_client, monkeypatch):
        """Invalid AWS_WAF_SCOPE env var raises ConfigError."""
        from octorules.config import ConfigError

        monkeypatch.setenv("AWS_WAF_SCOPE", "GLOBAL")
        with pytest.raises(ConfigError, match="Invalid waf_scope"):
            AwsWafProvider(client=mock_waf_client)

    def test_default_scope_is_regional(self, mock_waf_client, monkeypatch):
        """Default scope is REGIONAL when neither kwarg nor env var is set."""
        monkeypatch.delenv("AWS_WAF_SCOPE", raising=False)
        provider = AwsWafProvider(client=mock_waf_client)
        assert provider._waf_scope == "REGIONAL"
