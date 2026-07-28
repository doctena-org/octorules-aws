"""Web ACL settings management for AWS WAF.

These are non-phase YAML sections handled via extension hooks:
- ``aws_waf_settings`` -- default action, visibility config, challenge/captcha
  config, token domains, association config, and custom response bodies

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension -- same pattern as Azure's policy
settings in ``octorules_azure/_policy_settings.py``.

The Change and Plan classes inherit from octorules.extensions for API
compatibility with the shared settings framework.
"""

import logging

from octorules.extensions import ProviderExtension, SettingsChange, SettingsFormatter, SettingsPlan

log = logging.getLogger(__name__)

# Fields managed by this extension.
_MANAGED_FIELDS = frozenset(
    {
        "DefaultAction",
        "VisibilityConfig",
        "ChallengeConfig",
        "CaptchaConfig",
        "TokenDomains",
        "AssociationConfig",
        "CustomResponseBodies",
    }
)

# Valid DefaultAction top-level keys.
_VALID_DEFAULT_ACTIONS = frozenset({"Allow", "Block"})


# ---------------------------------------------------------------------------
# Data model for ACL settings diffs (subclass core framework for isinstance gating)
# ---------------------------------------------------------------------------
class AclSettingsChange(SettingsChange):
    """A single field change in ACL settings (concrete subclass for AWS WAF)."""

    pass


class AclSettingsPlan(SettingsPlan):
    """Plan for all ACL settings changes in a zone (concrete subclass for AWS WAF)."""

    pass


# ---------------------------------------------------------------------------
# Normalization: raw AWS dict -> YAML-friendly canonical form
# ---------------------------------------------------------------------------
def normalize_acl_settings(acl: dict) -> dict:
    """Extract managed settings from a Web ACL dict.

    Passes through raw AWS PascalCase structure since octorules-aws uses
    AWS-native field names throughout.
    """
    if not acl:
        return {}

    result: dict = {}
    for key in sorted(_MANAGED_FIELDS):
        val = acl.get(key)
        if val is not None:
            result[key] = val
    return result


# ---------------------------------------------------------------------------
# Denormalization: YAML canonical form -> AWS format
# ---------------------------------------------------------------------------
def denormalize_acl_settings(settings: dict) -> dict:
    """Convert YAML form back to AWS API format.

    Only includes keys present in *settings* so that partial updates
    don't reset unspecified fields to defaults.
    """
    if not settings:
        return {}

    result: dict = {}
    for key in sorted(_MANAGED_FIELDS):
        if key in settings:
            result[key] = settings[key]
    return result


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------
def diff_acl_settings(current: dict, desired: dict) -> AclSettingsPlan:
    """Diff current vs desired ACL settings.

    Only diffs keys present in *desired* (partial update semantics).
    """
    changes: list[AclSettingsChange] = []
    for key in sorted(desired.keys()):
        cur = current.get(key)
        des = desired.get(key)
        if cur != des:
            changes.append(AclSettingsChange(field=key, current=cur, desired=des))
    return AclSettingsPlan(changes=changes)


# ---------------------------------------------------------------------------
# Extension hooks
# ---------------------------------------------------------------------------
def _prefetch_acl_settings(all_desired, scope, provider):
    """Prefetch: fetch current ACL settings."""
    desired = all_desired.get("aws_waf_settings")
    if desired is None:
        return None

    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        current = provider.get_acl_settings(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        log.warning("Failed to fetch ACL settings for %s", scope.label)
        current = {}

    return (current, desired)


def _finalize_acl_settings(zp, all_desired, scope, provider, ctx):
    """Finalize: compute diff and add to zone plan."""
    if ctx is None:
        return

    current, desired = ctx
    plan = diff_acl_settings(current, desired)
    if plan.has_changes:
        zp.extension_plans.setdefault("aws_waf_settings", []).append(plan)


def _apply_acl_settings(zp, plans, scope, provider):
    """Apply ACL settings changes."""
    synced: list[str] = []

    for plan in plans:
        if not isinstance(plan, AclSettingsPlan) or not plan.has_changes:
            continue

        desired_values = {c.field: c.desired for c in plan.changes if c.has_changes}
        if desired_values:
            provider.update_acl_settings(scope, desired_values)
            synced.append("aws_waf_settings")

    return synced, None


def _assert_dict_type(value: object, field_name: str, zone_name: str, errors: list[str]) -> bool:
    """Check if value is a dict; append error if not. Return True if valid."""
    if value is not None and not isinstance(value, dict):
        errors.append(f"  {zone_name}/aws_waf_settings: {field_name} must be a dict")
        return False
    return True


def _validate_acl_settings(desired, zone_name, errors, lines):
    """Validate aws_waf_settings offline."""
    settings = desired.get("aws_waf_settings")
    if not isinstance(settings, dict):
        return

    default_action = settings.get("DefaultAction")
    if default_action is not None:
        if _assert_dict_type(default_action, "DefaultAction", zone_name, errors):
            keys = set(default_action.keys())
            if len(keys) != 1 or not keys & _VALID_DEFAULT_ACTIONS:
                errors.append(
                    f"  {zone_name}/aws_waf_settings: DefaultAction must have"
                    f" exactly one key from {sorted(_VALID_DEFAULT_ACTIONS)}"
                )

    _assert_dict_type(settings.get("VisibilityConfig"), "VisibilityConfig", zone_name, errors)

    for config_name in ("ChallengeConfig", "CaptchaConfig"):
        _assert_dict_type(settings.get(config_name), config_name, zone_name, errors)

    token_domains = settings.get("TokenDomains")
    if token_domains is not None:
        if not isinstance(token_domains, list):
            errors.append(f"  {zone_name}/aws_waf_settings: TokenDomains must be a list")
        elif not all(isinstance(d, str) for d in token_domains):
            errors.append(f"  {zone_name}/aws_waf_settings: TokenDomains must be a list of strings")

    assoc = settings.get("AssociationConfig")
    if assoc is not None and not isinstance(assoc, dict):
        errors.append(f"  {zone_name}/aws_waf_settings: AssociationConfig must be a dict")

    crb = settings.get("CustomResponseBodies")
    if crb is not None and not isinstance(crb, dict):
        errors.append(f"  {zone_name}/aws_waf_settings: CustomResponseBodies must be a dict")


def _dump_acl_settings(scope, provider):
    """Export current ACL settings to dump output."""
    from octorules.provider.exceptions import ProviderAuthError, ProviderError

    try:
        settings = provider.get_acl_settings(scope)
    except ProviderAuthError:
        raise
    except ProviderError:
        return None

    if settings:
        return {"aws_waf_settings": settings}
    return None


# ---------------------------------------------------------------------------
# Format extension (inherits from core SettingsFormatter)
# ---------------------------------------------------------------------------
class AclSettingsFormatter(SettingsFormatter):
    """Formats ACL settings diffs for plan output.

    Inherits standard format methods (format_text, format_json, format_markdown,
    format_html) from octorules.extensions.SettingsFormatter,
    parameterized with AWS WAF-specific prefix and provider identifiers.
    """

    def __init__(self) -> None:
        """Initialize with AWS WAF settings parameters.

        - plan_type: AclSettingsPlan (for isinstance checks)
        - prefix: "acl_settings" (YAML label prefix)
        - phase: "acl_settings" (report phase name)
        - provider_id: "aws_waf_settings" (report provider identifier)
        """
        super().__init__(
            plan_type=AclSettingsPlan,
            prefix="acl_settings",
        )

    def format_plan(self, plans: list, zone_name: str) -> list[str]:
        """Format changes for plan output (AWS WAF-specific method)."""
        lines: list[str] = []
        for plan in self._active_plans(plans):
            for change in plan.changes:
                if not change.has_changes:
                    continue
                lines.append(
                    f"  {zone_name}/acl_settings.{change.field}:"
                    f" {change.current!r} -> {change.desired!r}"
                )
        return lines

    def count_changes(self, plans: list) -> int:
        """Count total changes across all plans (AWS WAF-specific method)."""
        count = 0
        for plan in plans:
            if isinstance(plan, AclSettingsPlan):
                count += sum(1 for c in plan.changes if c.has_changes)
        return count


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------
class AclSettingsExtension(ProviderExtension):
    """Web ACL-level settings."""

    section = "aws_waf_settings"
    formatter = AclSettingsFormatter()

    def prefetch(self, desired, scope, provider):
        return _prefetch_acl_settings(desired, scope, provider)

    def finalize(self, zp, desired, scope, provider, ctx):
        return _finalize_acl_settings(zp, desired, scope, provider, ctx)

    def apply(self, zp, plans, scope, provider):
        return _apply_acl_settings(zp, plans, scope, provider)

    def dump(self, scope, provider):
        return _dump_acl_settings(scope, provider)

    def validate(self, desired, zone_name, errors, lines):
        return _validate_acl_settings(desired, zone_name, errors, lines)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
_registered = False


def register_acl_settings() -> None:
    """Register all ACL settings hooks with the core extension system."""
    global _registered
    if _registered:
        return
    _registered = True

    from octorules.extensions import (
        register_apply_extension,
        register_format_extension,
        register_plan_zone_hook,
        register_validate_extension,
    )

    register_plan_zone_hook(_prefetch_acl_settings, _finalize_acl_settings)
    register_apply_extension("aws_waf_settings", _apply_acl_settings)
    register_format_extension("aws_waf_settings", AclSettingsFormatter())
    register_validate_extension(_validate_acl_settings)
