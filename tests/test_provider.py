"""Tests for the AWS WAF provider."""

from __future__ import annotations

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

    def test_retries_on_stale_lock(self, mock_waf_client, web_acl):
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

    def test_stale_lock_exhausted_raises(self, mock_waf_client, web_acl):
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
