"""Tests for the AWS WAF ACL settings extension."""

from unittest.mock import MagicMock, patch

import pytest
from octorules.provider.base import Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

from octorules_aws import AwsWafProvider
from octorules_aws._acl_settings import (
    AclSettingsChange,
    AclSettingsFormatter,
    AclSettingsPlan,
    _apply_acl_settings,
    _dump_acl_settings,
    _finalize_acl_settings,
    _prefetch_acl_settings,
    _validate_acl_settings,
    denormalize_acl_settings,
    diff_acl_settings,
    normalize_acl_settings,
    register_acl_settings,
)


def _zs(zone_id: str = "acl-123", label: str = "") -> Scope:
    return Scope(zone_id=zone_id, label=label)


def _make_client_error(code: str, message: str = "error"):
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": code, "Message": message}}, "TestOp")


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------
class TestAclSettingsChange:
    def test_has_changes_true(self):
        c = AclSettingsChange(field="DefaultAction", current={"Allow": {}}, desired={"Block": {}})
        assert c.has_changes is True

    def test_has_changes_false(self):
        c = AclSettingsChange(field="DefaultAction", current={"Allow": {}}, desired={"Allow": {}})
        assert c.has_changes is False


class TestAclSettingsPlan:
    def test_empty_plan(self):
        plan = AclSettingsPlan()
        assert plan.has_changes is False
        assert plan.total_changes == 0

    def test_plan_with_changes(self):
        plan = AclSettingsPlan(
            changes=[
                AclSettingsChange("DefaultAction", {"Allow": {}}, {"Block": {}}),
                AclSettingsChange("TokenDomains", ["a.com"], ["a.com", "b.com"]),
            ]
        )
        assert plan.has_changes is True
        assert plan.total_changes == 2

    def test_plan_with_no_real_changes(self):
        plan = AclSettingsPlan(
            changes=[
                AclSettingsChange("DefaultAction", {"Allow": {}}, {"Allow": {}}),
            ]
        )
        assert plan.has_changes is False
        assert plan.total_changes == 0


# ---------------------------------------------------------------------------
# Normalization tests
# ---------------------------------------------------------------------------
class TestNormalizeAclSettings:
    def test_empty_acl(self):
        assert normalize_acl_settings({}) == {}

    def test_extracts_managed_fields(self):
        acl = {
            "Name": "my-acl",
            "Id": "acl-123",
            "ARN": "arn:aws:...",
            "Rules": [],
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {"SampledRequestsEnabled": True},
            "ChallengeConfig": {"ImmunityTimeProperty": {"ImmunityTime": 300}},
            "CaptchaConfig": {"ImmunityTimeProperty": {"ImmunityTime": 120}},
            "TokenDomains": ["example.com"],
            "AssociationConfig": {"RequestBody": {}},
            "CustomResponseBodies": {"blocked": {"ContentType": "TEXT_HTML"}},
        }
        result = normalize_acl_settings(acl)
        assert "DefaultAction" in result
        assert "VisibilityConfig" in result
        assert "ChallengeConfig" in result
        assert "CaptchaConfig" in result
        assert "TokenDomains" in result
        assert "AssociationConfig" in result
        assert "CustomResponseBodies" in result
        # Non-managed fields excluded
        assert "Name" not in result
        assert "Id" not in result
        assert "ARN" not in result
        assert "Rules" not in result

    def test_partial_fields(self):
        acl = {"DefaultAction": {"Block": {}}}
        result = normalize_acl_settings(acl)
        assert result == {"DefaultAction": {"Block": {}}}

    def test_none_input(self):
        assert normalize_acl_settings(None) == {}


class TestNormalizeDenormalizeRoundTrip:
    def test_round_trip_all_fields(self):
        """normalize -> denormalize preserves all 7 managed fields."""
        settings = {
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "my-acl",
            },
            "ChallengeConfig": {"ImmunityTimeProperty": {"ImmunityTime": 300}},
            "CaptchaConfig": {"ImmunityTimeProperty": {"ImmunityTime": 120}},
            "TokenDomains": ["example.com", "cdn.example.com"],
            "AssociationConfig": {
                "RequestBody": {
                    "DefaultSizeInspectionLimit": "KB_16",
                }
            },
            "CustomResponseBodies": {
                "blocked": {
                    "ContentType": "TEXT_HTML",
                    "Content": "<h1>Blocked</h1>",
                }
            },
        }
        # Wrap in a full ACL dict with non-managed fields
        acl = {
            "Name": "my-acl",
            "Id": "acl-123",
            "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl",
            "Rules": [{"Name": "rule-1"}],
            **settings,
        }
        normalized = normalize_acl_settings(acl)
        denormalized = denormalize_acl_settings(normalized)
        assert denormalized == settings


# ---------------------------------------------------------------------------
# Denormalization tests
# ---------------------------------------------------------------------------
class TestDenormalizeAclSettings:
    def test_empty(self):
        assert denormalize_acl_settings({}) == {}

    def test_none(self):
        assert denormalize_acl_settings(None) == {}

    def test_passes_through_managed_fields(self):
        settings = {
            "DefaultAction": {"Block": {}},
            "TokenDomains": ["a.com"],
        }
        result = denormalize_acl_settings(settings)
        assert result == settings

    def test_ignores_unknown_fields(self):
        settings = {"DefaultAction": {"Allow": {}}, "SomeUnknown": "value"}
        result = denormalize_acl_settings(settings)
        assert result == {"DefaultAction": {"Allow": {}}}


# ---------------------------------------------------------------------------
# Diff tests
# ---------------------------------------------------------------------------
class TestDiffAclSettings:
    def test_no_diff(self):
        current = {"DefaultAction": {"Allow": {}}}
        desired = {"DefaultAction": {"Allow": {}}}
        plan = diff_acl_settings(current, desired)
        assert plan.has_changes is False

    def test_changed_default_action(self):
        current = {"DefaultAction": {"Allow": {}}}
        desired = {"DefaultAction": {"Block": {}}}
        plan = diff_acl_settings(current, desired)
        assert plan.has_changes is True
        assert plan.total_changes == 1
        assert plan.changes[0].field == "DefaultAction"
        assert plan.changes[0].current == {"Allow": {}}
        assert plan.changes[0].desired == {"Block": {}}

    def test_new_field_added(self):
        current = {"DefaultAction": {"Allow": {}}}
        desired = {"DefaultAction": {"Allow": {}}, "TokenDomains": ["a.com"]}
        plan = diff_acl_settings(current, desired)
        assert plan.has_changes is True
        assert plan.total_changes == 1
        assert plan.changes[0].field == "TokenDomains"
        assert plan.changes[0].current is None

    def test_multiple_changes(self):
        current = {
            "DefaultAction": {"Allow": {}},
            "TokenDomains": ["a.com"],
        }
        desired = {
            "DefaultAction": {"Block": {}},
            "TokenDomains": ["a.com", "b.com"],
        }
        plan = diff_acl_settings(current, desired)
        assert plan.total_changes == 2

    def test_partial_desired_only_diffs_present_keys(self):
        """Only desired keys are diffed -- current-only keys are ignored."""
        current = {"DefaultAction": {"Allow": {}}, "TokenDomains": ["a.com"]}
        desired = {"DefaultAction": {"Allow": {}}}
        plan = diff_acl_settings(current, desired)
        assert plan.has_changes is False


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------
class TestValidateAclSettings:
    def test_valid_settings(self):
        errors = []
        desired = {
            "aws_waf_settings": {
                "DefaultAction": {"Allow": {}},
                "VisibilityConfig": {"SampledRequestsEnabled": True},
                "ChallengeConfig": {"ImmunityTimeProperty": {"ImmunityTime": 300}},
                "CaptchaConfig": {"ImmunityTimeProperty": {"ImmunityTime": 120}},
                "TokenDomains": ["example.com"],
                "AssociationConfig": {"RequestBody": {}},
                "CustomResponseBodies": {"blocked": {}},
            }
        }
        _validate_acl_settings(desired, "my-acl", errors, [])
        assert errors == []

    def test_no_settings_key(self):
        errors = []
        _validate_acl_settings({}, "my-acl", errors, [])
        assert errors == []

    def test_non_dict_settings(self):
        errors = []
        _validate_acl_settings({"aws_waf_settings": "bad"}, "my-acl", errors, [])
        assert errors == []  # Non-dict is silently ignored

    def test_invalid_default_action_not_dict(self):
        errors = []
        _validate_acl_settings(
            {"aws_waf_settings": {"DefaultAction": "Allow"}}, "my-acl", errors, []
        )
        assert len(errors) == 1
        assert "DefaultAction must be a dict" in errors[0]

    def test_invalid_default_action_wrong_key(self):
        errors = []
        _validate_acl_settings(
            {"aws_waf_settings": {"DefaultAction": {"Challenge": {}}}}, "my-acl", errors, []
        )
        assert len(errors) == 1
        assert "exactly one key from" in errors[0]

    def test_invalid_default_action_multiple_keys(self):
        errors = []
        _validate_acl_settings(
            {"aws_waf_settings": {"DefaultAction": {"Allow": {}, "Block": {}}}},
            "my-acl",
            errors,
            [],
        )
        assert len(errors) == 1

    def test_invalid_visibility_config(self):
        errors = []
        _validate_acl_settings(
            {"aws_waf_settings": {"VisibilityConfig": "bad"}}, "my-acl", errors, []
        )
        assert len(errors) == 1
        assert "VisibilityConfig must be a dict" in errors[0]

    def test_invalid_challenge_config(self):
        errors = []
        _validate_acl_settings({"aws_waf_settings": {"ChallengeConfig": 42}}, "my-acl", errors, [])
        assert len(errors) == 1
        assert "ChallengeConfig must be a dict" in errors[0]

    def test_invalid_captcha_config(self):
        errors = []
        _validate_acl_settings({"aws_waf_settings": {"CaptchaConfig": True}}, "my-acl", errors, [])
        assert len(errors) == 1
        assert "CaptchaConfig must be a dict" in errors[0]

    def test_invalid_token_domains_not_list(self):
        errors = []
        _validate_acl_settings(
            {"aws_waf_settings": {"TokenDomains": "example.com"}}, "my-acl", errors, []
        )
        assert len(errors) == 1
        assert "TokenDomains must be a list" in errors[0]

    def test_invalid_token_domains_not_strings(self):
        errors = []
        _validate_acl_settings({"aws_waf_settings": {"TokenDomains": [123]}}, "my-acl", errors, [])
        assert len(errors) == 1
        assert "list of strings" in errors[0]

    def test_invalid_association_config(self):
        errors = []
        _validate_acl_settings(
            {"aws_waf_settings": {"AssociationConfig": []}}, "my-acl", errors, []
        )
        assert len(errors) == 1
        assert "AssociationConfig must be a dict" in errors[0]

    def test_invalid_custom_response_bodies(self):
        errors = []
        _validate_acl_settings(
            {"aws_waf_settings": {"CustomResponseBodies": []}}, "my-acl", errors, []
        )
        assert len(errors) == 1
        assert "CustomResponseBodies must be a dict" in errors[0]


# ---------------------------------------------------------------------------
# Provider method tests
# ---------------------------------------------------------------------------
class TestGetAclSettings:
    def test_fetches_settings(self, mock_waf_client):
        acl = {
            "Name": "my-acl",
            "Id": "acl-123",
            "ARN": "arn:aws:wafv2:...",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {"MetricName": "my-acl"},
            "Rules": [],
            "TokenDomains": ["example.com"],
        }
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")

        settings = provider.get_acl_settings(_zs())
        assert settings["DefaultAction"] == {"Allow": {}}
        assert settings["VisibilityConfig"] == {"MetricName": "my-acl"}
        assert settings["TokenDomains"] == ["example.com"]
        # Non-settings fields excluded
        assert "Name" not in settings
        assert "Rules" not in settings
        assert "ARN" not in settings


class TestUpdateAclSettings:
    def test_updates_settings(self, mock_waf_client):
        acl = {
            "Name": "my-acl",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {"MetricName": "my-acl"},
            "Rules": [{"Name": "r1"}],
        }
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")

        provider.update_acl_settings(_zs(), {"DefaultAction": {"Block": {}}})

        call_kwargs = mock_waf_client.update_web_acl.call_args[1]
        assert call_kwargs["DefaultAction"] == {"Block": {}}
        # Rules are preserved
        assert call_kwargs["Rules"] == [{"Name": "r1"}]
        assert call_kwargs["LockToken"] == "lock-1"

    def test_empty_settings_is_noop(self, mock_waf_client):
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")

        provider.update_acl_settings(_zs(), {})
        mock_waf_client.update_web_acl.assert_not_called()

    @patch("octorules.retry.time.sleep")
    def test_retries_on_stale_lock(self, _mock_sleep, mock_waf_client):
        acl = {
            "Name": "my-acl",
            "Id": "acl-123",
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": {},
            "Rules": [],
        }
        mock_waf_client.list_web_acls.return_value = {
            "WebACLs": [{"Name": "my-acl", "Id": "acl-123", "ARN": "arn:acl"}]
        }
        mock_waf_client.get_web_acl.return_value = {
            "WebACL": acl,
            "LockToken": "lock-1",
        }
        provider = AwsWafProvider(client=mock_waf_client)
        provider.resolve_zone_id("my-acl")

        mock_waf_client.update_web_acl.side_effect = [
            _make_client_error("WAFOptimisticLockException"),
            None,
        ]
        provider.update_acl_settings(_zs(), {"DefaultAction": {"Block": {}}})
        assert mock_waf_client.update_web_acl.call_count == 2


# ---------------------------------------------------------------------------
# Hook tests
# ---------------------------------------------------------------------------
class TestPrefetchHook:
    def test_returns_none_when_no_settings(self):
        result = _prefetch_acl_settings({}, _zs(), MagicMock())
        assert result is None

    def test_fetches_current_settings(self):
        provider = MagicMock(spec=AwsWafProvider)
        provider.get_acl_settings.return_value = {"DefaultAction": {"Allow": {}}}
        desired = {"DefaultAction": {"Block": {}}}

        result = _prefetch_acl_settings({"aws_waf_settings": desired}, _zs(), provider)
        assert result == ({"DefaultAction": {"Allow": {}}}, desired)

    def test_handles_provider_error(self):
        provider = MagicMock(spec=AwsWafProvider)
        provider.get_acl_settings.side_effect = ProviderError("fail")
        desired = {"DefaultAction": {"Block": {}}}

        result = _prefetch_acl_settings({"aws_waf_settings": desired}, _zs(), provider)
        assert result == ({}, desired)

    def test_reraises_auth_error(self):
        provider = MagicMock(spec=AwsWafProvider)
        provider.get_acl_settings.side_effect = ProviderAuthError("denied")

        with pytest.raises(ProviderAuthError):
            _prefetch_acl_settings(
                {"aws_waf_settings": {"DefaultAction": {"Block": {}}}}, _zs(), provider
            )


class TestFinalizeHook:
    def test_noop_when_ctx_none(self):
        zp = MagicMock()
        _finalize_acl_settings(zp, {}, _zs(), MagicMock(spec=AwsWafProvider), None)
        # No exception, no changes

    def test_adds_plan_when_changes_exist(self):
        zp = MagicMock()
        zp.extension_plans = {}
        current = {"DefaultAction": {"Allow": {}}}
        desired = {"DefaultAction": {"Block": {}}}
        _finalize_acl_settings(zp, {}, _zs(), MagicMock(spec=AwsWafProvider), (current, desired))
        assert "aws_waf_settings" in zp.extension_plans
        assert len(zp.extension_plans["aws_waf_settings"]) == 1

    def test_skips_when_no_changes(self):
        zp = MagicMock()
        zp.extension_plans = {}
        current = {"DefaultAction": {"Allow": {}}}
        desired = {"DefaultAction": {"Allow": {}}}
        _finalize_acl_settings(zp, {}, _zs(), MagicMock(spec=AwsWafProvider), (current, desired))
        assert "aws_waf_settings" not in zp.extension_plans


class TestApplyHook:
    def test_applies_changes(self):
        provider = MagicMock(spec=AwsWafProvider)
        plan = AclSettingsPlan(
            changes=[AclSettingsChange("DefaultAction", {"Allow": {}}, {"Block": {}})]
        )
        zp = MagicMock()
        synced, _ = _apply_acl_settings(zp, [plan], _zs(), provider)
        assert synced == ["aws_waf_settings"]
        provider.update_acl_settings.assert_called_once_with(
            _zs(), {"DefaultAction": {"Block": {}}}
        )

    def test_skips_no_change_plan(self):
        provider = MagicMock(spec=AwsWafProvider)
        plan = AclSettingsPlan()
        synced, _ = _apply_acl_settings(MagicMock(), [plan], _zs(), provider)
        assert synced == []
        provider.update_acl_settings.assert_not_called()


class TestDumpHook:
    def test_dumps_settings(self):
        provider = MagicMock(spec=AwsWafProvider)
        provider.get_acl_settings.return_value = {"DefaultAction": {"Allow": {}}}
        result = _dump_acl_settings(_zs(), provider, "/tmp")
        assert result == {"aws_waf_settings": {"DefaultAction": {"Allow": {}}}}

    def test_returns_none_on_error(self):
        provider = MagicMock(spec=AwsWafProvider)
        provider.get_acl_settings.side_effect = ProviderError("fail")
        result = _dump_acl_settings(_zs(), provider, "/tmp")
        assert result is None

    def test_returns_none_on_empty(self):
        provider = MagicMock(spec=AwsWafProvider)
        provider.get_acl_settings.return_value = {}
        result = _dump_acl_settings(_zs(), provider, "/tmp")
        assert result is None

    def test_reraises_auth_error(self):
        provider = MagicMock(spec=AwsWafProvider)
        provider.get_acl_settings.side_effect = ProviderAuthError("denied")
        with pytest.raises(ProviderAuthError):
            _dump_acl_settings(_zs(), provider, "/tmp")


# ---------------------------------------------------------------------------
# Formatter tests
# ---------------------------------------------------------------------------
class TestAclSettingsFormatter:
    def _make_plan(self, field="DefaultAction", current=None, desired=None):
        return AclSettingsPlan(
            changes=[AclSettingsChange(field, current or {"Allow": {}}, desired or {"Block": {}})]
        )

    def test_format_plan(self):
        fmt = AclSettingsFormatter()
        plan = self._make_plan()
        lines = fmt.format_plan([plan], "my-acl")
        assert len(lines) == 1
        assert "acl_settings.DefaultAction" in lines[0]
        assert "my-acl" in lines[0]

    def test_count_changes(self):
        fmt = AclSettingsFormatter()
        plan = self._make_plan()
        assert fmt.count_changes([plan]) == 1

    def test_count_changes_empty(self):
        fmt = AclSettingsFormatter()
        assert fmt.count_changes([AclSettingsPlan()]) == 0

    def test_format_text(self):
        fmt = AclSettingsFormatter()
        plan = self._make_plan()
        lines = fmt.format_text([plan], use_color=False)
        assert len(lines) == 1
        assert "~" in lines[0]
        assert "acl_settings.DefaultAction" in lines[0]

    def test_format_json(self):
        fmt = AclSettingsFormatter()
        plan = self._make_plan()
        result = fmt.format_json([plan])
        assert len(result) == 1
        assert result[0]["changes"][0]["field"] == "DefaultAction"

    def test_format_markdown(self):
        fmt = AclSettingsFormatter()
        plan = self._make_plan()
        lines = fmt.format_markdown([plan], [])
        assert len(lines) == 1
        assert "| ~ |" in lines[0]

    def test_format_html(self):
        fmt = AclSettingsFormatter()
        plan = self._make_plan()
        lines: list[str] = []
        adds, removes, modifies, _reorders = fmt.format_html([plan], lines)
        assert modifies == 1
        assert adds == 0
        assert removes == 0

    def test_format_report_drift(self):
        fmt = AclSettingsFormatter()
        plan = self._make_plan()
        phases_data: list[dict] = []
        result = fmt.format_report([plan], False, phases_data)
        assert result is True
        assert len(phases_data) == 1
        assert phases_data[0]["provider_id"] == "aws_waf_settings"
        assert phases_data[0]["modifies"] == 1

    def test_format_report_no_drift(self):
        fmt = AclSettingsFormatter()
        phases_data: list[dict] = []
        result = fmt.format_report([AclSettingsPlan()], False, phases_data)
        assert result is False
        assert phases_data == []


# ---------------------------------------------------------------------------
# Registration test
# ---------------------------------------------------------------------------
class TestRegistration:
    def test_non_phase_key_registered(self):
        from octorules.phases import KNOWN_NON_PHASE_KEYS

        assert "aws_waf_settings" in KNOWN_NON_PHASE_KEYS

    def test_register_idempotent(self):
        """Calling register_acl_settings() twice does not raise."""
        register_acl_settings()
        register_acl_settings()
