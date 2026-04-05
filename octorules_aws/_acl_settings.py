"""Web ACL settings management for AWS WAF.

These are non-phase YAML sections handled via extension hooks:
- ``aws_waf_settings`` -- default action, visibility config, challenge/captcha
  config, token domains, association config, and custom response bodies

Uses plan_zone_hook (prefetch + finalize), apply_extension, format_extension,
validate_extension, and dump_extension -- same pattern as Azure's policy
settings in ``octorules_azure/_policy_settings.py``.
"""

import logging
from dataclasses import dataclass, field

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
# Data model for ACL settings diffs
# ---------------------------------------------------------------------------
@dataclass
class AclSettingsChange:
    """A single field change in ACL settings."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class AclSettingsPlan:
    """Plan for all ACL settings changes in a zone."""

    changes: list[AclSettingsChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


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


def _validate_acl_settings(desired, zone_name, errors, lines):
    """Validate aws_waf_settings offline."""
    settings = desired.get("aws_waf_settings")
    if not isinstance(settings, dict):
        return

    default_action = settings.get("DefaultAction")
    if default_action is not None:
        if not isinstance(default_action, dict):
            errors.append(f"  {zone_name}/aws_waf_settings: DefaultAction must be a dict")
        else:
            keys = set(default_action.keys())
            if len(keys) != 1 or not keys & _VALID_DEFAULT_ACTIONS:
                errors.append(
                    f"  {zone_name}/aws_waf_settings: DefaultAction must have"
                    f" exactly one key from {sorted(_VALID_DEFAULT_ACTIONS)}"
                )

    vis = settings.get("VisibilityConfig")
    if vis is not None and not isinstance(vis, dict):
        errors.append(f"  {zone_name}/aws_waf_settings: VisibilityConfig must be a dict")

    for config_name in ("ChallengeConfig", "CaptchaConfig"):
        config = settings.get(config_name)
        if config is not None and not isinstance(config, dict):
            errors.append(f"  {zone_name}/aws_waf_settings: {config_name} must be a dict")

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


def _dump_acl_settings(scope, provider, out_dir):
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
# Format extension
# ---------------------------------------------------------------------------
class AclSettingsFormatter:
    """Formats ACL settings diffs for plan output."""

    def format_plan(self, plans: list, zone_name: str) -> list[str]:
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, AclSettingsPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                lines.append(
                    f"  {zone_name}/acl_settings.{change.field}:"
                    f" {change.current!r} -> {change.desired!r}"
                )
        return lines

    def count_changes(self, plans: list) -> int:
        count = 0
        for plan in plans:
            if isinstance(plan, AclSettingsPlan):
                count += sum(1 for c in plan.changes if c.has_changes)
        return count

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, AclSettingsPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = f"acl_settings.{change.field}"
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in plans:
            if not isinstance(plan, AclSettingsPlan) or not plan.has_changes:
                continue
            changes = []
            for change in plan.changes:
                if not change.has_changes:
                    continue
                changes.append(
                    {
                        "field": change.field,
                        "current": change.current,
                        "desired": change.desired,
                    }
                )
            if changes:
                result.append({"changes": changes})
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import _md_escape

        lines: list[str] = []
        for plan in plans:
            if not isinstance(plan, AclSettingsPlan) or not plan.has_changes:
                continue
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = _md_escape(f"acl_settings.{change.field}")
                cur = _md_escape(repr(change.current))
                des = _md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import _HTML_TABLE_HEADER, _html_summary_row

        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, AclSettingsPlan) or not plan.has_changes:
                continue
            lines.extend(_HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(f"acl_settings.{change.field}")
                cur = html_escape(repr(change.current))
                des = html_escape(repr(change.desired))
                lines.append("  <tr>")
                lines.append("    <td>Modify</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append(f"    <td>{cur} &rarr; {des}</td>")
                lines.append("  </tr>")
            lines.extend(_html_summary_row(0, 0, plan_modifies, 0))
            lines.append("</table>")
            total_modifies += plan_modifies
        return 0, 0, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, AclSettingsPlan) or not plan.has_changes:
                continue
            total_modifies += sum(1 for c in plan.changes if c.has_changes)
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": "acl_settings",
                    "provider_id": "aws_waf_settings",
                    "status": "drifted",
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": 0,
                    "removes": 0,
                    "modifies": total_modifies,
                }
            )
        return zone_has_drift


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
        register_dump_extension,
        register_format_extension,
        register_plan_zone_hook,
        register_validate_extension,
    )

    register_plan_zone_hook(_prefetch_acl_settings, _finalize_acl_settings)
    register_apply_extension("aws_waf_settings", _apply_acl_settings)
    register_format_extension("aws_waf_settings", AclSettingsFormatter())
    register_validate_extension(_validate_acl_settings)
    register_dump_extension(_dump_acl_settings)
