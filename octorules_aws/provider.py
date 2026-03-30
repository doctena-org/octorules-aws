"""AWS WAF v2 provider for octorules."""

from __future__ import annotations

import logging
import os
import threading
import time

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from octorules.config import ConfigError
from octorules.provider.base import PhaseRulesResult, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError
from octorules.provider.utils import make_error_wrapper

log = logging.getLogger(__name__)

# AWS WAF error codes that indicate auth/permission problems.
_AUTH_ERROR_CODES = frozenset(
    {
        "AccessDeniedException",
        "UnauthorizedAccess",
        "AccessDenied",
        "ExpiredTokenException",
        "InvalidIdentityToken",
    }
)

# Maximum retry attempts for WAFOptimisticLockException (stale LockToken).
_LOCK_RETRIES = 3

# Default VisibilityConfig for newly created Rule Groups.
_DEFAULT_VISIBILITY_CONFIG = {
    "SampledRequestsEnabled": True,
    "CloudWatchMetricsEnabled": True,
    "MetricName": "",  # will be set per-call
}

# Phase identifiers registered by this provider.
_AWS_PHASE_IDS = frozenset(
    {
        "aws_waf_custom",
        "aws_waf_rate",
        "aws_waf_managed",
        "aws_waf_rule_group",
    }
)


def _classify_client_error(e: Exception) -> type[ProviderAuthError] | None:
    """Check boto3 ClientError code to determine if it's an auth error."""
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "")
        if code in _AUTH_ERROR_CODES:
            return ProviderAuthError
    return None


_wrap_provider_errors = make_error_wrapper(
    auth_errors=(NoCredentialsError,),
    connection_errors=(EndpointConnectionError, ConnectionError),
    generic_errors=(ClientError,),
    classify=_classify_client_error,
)


# ---------------------------------------------------------------------------
# Rule classification helpers
# ---------------------------------------------------------------------------


def _is_rate_rule(rule: dict) -> bool:
    """True if the rule uses a RateBasedStatement."""
    stmt = rule.get("Statement", {})
    return "RateBasedStatement" in stmt


def _is_managed_rule(rule: dict) -> bool:
    """True if the rule references a managed rule group."""
    stmt = rule.get("Statement", {})
    return "ManagedRuleGroupStatement" in stmt


def _is_rule_group_rule(rule: dict) -> bool:
    """True if the rule references a customer-created rule group."""
    stmt = rule.get("Statement", {})
    return "RuleGroupReferenceStatement" in stmt


def _classify_phase(rule: dict) -> str:
    """Return the AWS phase id for a rule."""
    if _is_rate_rule(rule):
        return "aws_waf_rate"
    if _is_managed_rule(rule):
        return "aws_waf_managed"
    if _is_rule_group_rule(rule):
        return "aws_waf_rule_group"
    return "aws_waf_custom"


# ---------------------------------------------------------------------------
# Rule normalization (AWS format <-> octorules format)
# ---------------------------------------------------------------------------


def _decode_bytes(obj: object) -> object:
    """Recursively decode bytes values to UTF-8 strings.

    The AWS WAF API returns ``SearchString`` as ``bytes``.  We decode to
    ``str`` so the planner can diff against the YAML (which is always str).
    """
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _decode_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decode_bytes(v) for v in obj]
    return obj


def _normalize_rule(rule: dict) -> dict:
    """Convert AWS WAF rule to octorules format (Name -> ref, bytes -> str)."""
    d = _decode_bytes(dict(rule))
    d["ref"] = d.pop("Name", "")
    return d


def _denormalize_rule(rule: dict) -> dict:
    """Convert octorules format back to AWS WAF rule (ref -> Name)."""
    d = dict(rule)
    d["Name"] = d.pop("ref", "")
    return d


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class AwsWafProvider:
    """AWS WAF v2 provider for octorules.

    Maps octorules concepts to AWS WAF v2:
      - Zones → Web ACLs (resolve_zone_id looks up by name)
      - Phases → Rule types within a Web ACL (custom / rate / managed)
      - Custom rulesets → Rule Groups
      - Lists → IP Sets

    Authentication uses the standard boto3 credential chain (env vars,
    ~/.aws/credentials, IAM roles).  The ``token`` parameter is accepted
    for BaseProvider compatibility but not used for auth.
    """

    SUPPORTS = frozenset({"custom_rulesets", "lists", "zone_discovery"})

    def __init__(
        self,
        *,
        max_retries: int = 2,
        timeout: float | None = None,
        max_workers: int = 1,
        client: object = None,
        region: str | None = None,
        waf_scope: str | None = None,
        **_extra: object,
    ) -> None:
        self._waf_scope = waf_scope or os.environ.get("AWS_WAF_SCOPE", "REGIONAL")
        if self._waf_scope not in ("REGIONAL", "CLOUDFRONT"):
            raise ConfigError(
                f"Invalid waf_scope: {self._waf_scope!r} (must be 'REGIONAL' or 'CLOUDFRONT')"
            )
        region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

        if client is not None:
            self._client = client
        else:
            config = boto3.session.Config(
                retries={"max_attempts": max_retries, "mode": "adaptive"},
                connect_timeout=timeout or 30,
                read_timeout=timeout or 30,
            )
            self._client = boto3.client("wafv2", region_name=region, config=config)

        self._max_workers = max_workers
        self._lock = threading.Lock()
        # web_acl_id -> {Name, Id, ARN}
        self._web_acl_meta: dict[str, dict] = {}

    # -- Properties --

    @property
    def max_workers(self) -> int:
        """Maximum number of concurrent workers for parallel operations."""
        return self._max_workers

    @property
    def account_id(self) -> str | None:
        """Return None; AWS WAF does not use account-level identifiers."""
        return None

    @property
    def account_name(self) -> str | None:
        """Return None; AWS WAF does not use account-level names."""
        return None

    @property
    def zone_plans(self) -> dict[str, str]:
        """Return empty dict; AWS WAF has no zone-level plan tiers."""
        return {}

    # -- Pagination helper --

    def _paginate_list(self, api_method, response_key: str) -> list[dict]:
        """Paginate a list_* API call using NextMarker."""
        results: list[dict] = []
        kwargs: dict[str, str] = {"Scope": self._waf_scope}
        seen_markers: set[str] = set()
        while True:
            response = api_method(**kwargs)
            results.extend(response.get(response_key, []))
            marker = response.get("NextMarker")
            if not marker:
                break
            if marker in seen_markers:
                log.warning(
                    "Pagination loop detected for %s: marker %r repeated",
                    response_key,
                    marker,
                )
                break
            seen_markers.add(marker)
            kwargs["NextMarker"] = marker
        return results

    # -- Web ACL helpers --

    def _get_web_acl(self, scope: Scope) -> tuple[dict, str]:
        """Fetch a Web ACL and its lock token."""
        with self._lock:
            meta = self._web_acl_meta.get(scope.zone_id)
        if meta is None:
            raise ConfigError(
                f"Web ACL {scope.zone_id!r} not resolved (call resolve_zone_id first)"
            )
        response = self._client.get_web_acl(
            Name=meta["Name"],
            Scope=self._waf_scope,
            Id=scope.zone_id,
        )
        return response["WebACL"], response["LockToken"]

    def _with_lock_retry(self, operation: object, label: str) -> object:
        """Run *operation()* with optimistic-lock retry and linear backoff.

        Retries up to ``_LOCK_RETRIES`` times on
        ``WAFOptimisticLockException``, sleeping ``0.5s * attempt`` between
        retries so concurrent writers have time to settle.
        """
        for attempt in range(_LOCK_RETRIES):
            try:
                return operation()
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code == "WAFOptimisticLockException" and attempt < _LOCK_RETRIES - 1:
                    delay = 0.5 * (attempt + 1)
                    log.debug(
                        "Stale LockToken for %s, retrying in %.1fs",
                        label,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                raise
        raise ProviderError("Lock retry exhausted")  # pragma: no cover

    # -- Zone resolution --

    @_wrap_provider_errors
    def resolve_zone_id(self, zone_name: str) -> str:
        """Resolve a Web ACL name to its ID.

        Raises ConfigError if zero or more than one Web ACL matches.
        """
        all_acls = self._paginate_list(self._client.list_web_acls, "WebACLs")
        matches = [acl for acl in all_acls if acl["Name"] == zone_name]
        if len(matches) == 0:
            raise ConfigError(f"No Web ACL found for {zone_name!r}")
        if len(matches) > 1:
            raise ConfigError(f"Multiple Web ACLs found for {zone_name!r}")
        acl = matches[0]
        with self._lock:
            self._web_acl_meta[acl["Id"]] = {
                "Name": acl["Name"],
                "Id": acl["Id"],
                "ARN": acl.get("ARN", ""),
            }
        return acl["Id"]

    @_wrap_provider_errors
    def list_zones(self) -> list[str]:
        """List all Web ACL names available in this region/scope."""
        all_acls = self._paginate_list(self._client.list_web_acls, "WebACLs")
        return [acl["Name"] for acl in all_acls]

    # -- Phase rules --

    @_wrap_provider_errors
    def get_phase_rules(self, scope: Scope, provider_id: str) -> list[dict]:
        """Get rules from a Web ACL filtered by phase type."""
        if provider_id not in _AWS_PHASE_IDS:
            return []
        acl, _ = self._get_web_acl(scope)
        rules = acl.get("Rules", [])
        return [_normalize_rule(r) for r in rules if _classify_phase(r) == provider_id]

    @_wrap_provider_errors
    def put_phase_rules(self, scope: Scope, provider_id: str, rules: list[dict]) -> int:
        """Replace rules of a specific phase type in a Web ACL.

        AWS WAF requires updating the entire rule list atomically. This method
        preserves rules belonging to other phases and replaces only those
        matching ``provider_id``.

        Retries on ``WAFOptimisticLockException`` (stale LockToken) by
        re-fetching and re-merging.
        """
        new_rules = [_denormalize_rule(r) for r in rules]
        with self._lock:
            meta = self._web_acl_meta[scope.zone_id]

        def _op() -> int:
            acl, lock_token = self._get_web_acl(scope)
            other_rules = [r for r in acl.get("Rules", []) if _classify_phase(r) != provider_id]
            self._client.update_web_acl(
                Name=meta["Name"],
                Scope=self._waf_scope,
                Id=scope.zone_id,
                DefaultAction=acl["DefaultAction"],
                Rules=other_rules + new_rules,
                VisibilityConfig=acl["VisibilityConfig"],
                LockToken=lock_token,
            )
            return len(new_rules)

        return self._with_lock_retry(_op, f"WebACL {scope.zone_id}")

    @_wrap_provider_errors
    def get_all_phase_rules(
        self, scope: Scope, *, provider_ids: list[str] | None = None
    ) -> PhaseRulesResult:
        """Fetch rules for all AWS phases from a Web ACL."""
        phases_to_fetch = provider_ids if provider_ids is not None else list(_AWS_PHASE_IDS)
        # Only fetch phases this provider owns
        phases_to_fetch = [p for p in phases_to_fetch if p in _AWS_PHASE_IDS]

        if not phases_to_fetch:
            return PhaseRulesResult({}, failed_phases=[])

        acl, _ = self._get_web_acl(scope)
        all_rules = acl.get("Rules", [])

        result: dict[str, list[dict]] = {}
        for phase_id in phases_to_fetch:
            phase_rules = [_normalize_rule(r) for r in all_rules if _classify_phase(r) == phase_id]
            if phase_rules:
                result[phase_id] = phase_rules

        return PhaseRulesResult(result, failed_phases=[])

    # -- Rule Groups (custom rulesets) --

    @_wrap_provider_errors
    def list_custom_rulesets(self, scope: Scope) -> list[dict]:
        """List Rule Groups."""
        all_rgs = self._paginate_list(self._client.list_rule_groups, "RuleGroups")
        return [
            {
                "id": rg.get("Id", ""),
                "name": rg.get("Name", ""),
                "phase": "",
                "description": rg.get("Description", ""),
            }
            for rg in all_rgs
        ]

    @_wrap_provider_errors
    def get_custom_ruleset(
        self, scope: Scope, ruleset_id: str, *, _rg_cache: list[dict] | None = None
    ) -> list[dict]:
        """Fetch rules from a Rule Group."""
        # Need to find the name for this ID
        rg_meta = self._find_rule_group(ruleset_id, _cache=_rg_cache)
        response = self._client.get_rule_group(
            Name=rg_meta["Name"],
            Scope=self._waf_scope,
            Id=ruleset_id,
        )
        rules = response.get("RuleGroup", {}).get("Rules", [])
        return [_normalize_rule(r) for r in rules]

    @_wrap_provider_errors
    def put_custom_ruleset(self, scope: Scope, ruleset_id: str, rules: list[dict]) -> int:
        """Replace all rules in a Rule Group.

        Retries on ``WAFOptimisticLockException`` (stale LockToken).
        """
        rg_meta = self._find_rule_group(ruleset_id)
        new_rules = [_denormalize_rule(r) for r in rules]

        def _op() -> int:
            response = self._client.get_rule_group(
                Name=rg_meta["Name"],
                Scope=self._waf_scope,
                Id=ruleset_id,
            )
            self._client.update_rule_group(
                Name=rg_meta["Name"],
                Scope=self._waf_scope,
                Id=ruleset_id,
                Rules=new_rules,
                VisibilityConfig=response["RuleGroup"]["VisibilityConfig"],
                LockToken=response["LockToken"],
            )
            return len(rules)

        return self._with_lock_retry(_op, f"RuleGroup {ruleset_id}")

    @_wrap_provider_errors
    def create_custom_ruleset(
        self, scope: Scope, name: str, phase: str, capacity: int, description: str = ""
    ) -> dict:
        """Create a new Rule Group."""
        vis = {**_DEFAULT_VISIBILITY_CONFIG, "MetricName": name}
        response = self._client.create_rule_group(
            Name=name,
            Scope=self._waf_scope,
            Capacity=capacity,
            Description=description,
            Rules=[],
            VisibilityConfig=vis,
        )
        summary = response.get("Summary", {})
        return {"id": summary.get("Id", ""), "name": summary.get("Name", "")}

    @_wrap_provider_errors
    def delete_custom_ruleset(self, scope: Scope, ruleset_id: str) -> None:
        """Delete a Rule Group. Retries on stale LockToken."""
        rg_meta = self._find_rule_group(ruleset_id)

        def _op() -> None:
            response = self._client.get_rule_group(
                Name=rg_meta["Name"], Scope=self._waf_scope, Id=ruleset_id
            )
            self._client.delete_rule_group(
                Name=rg_meta["Name"],
                Scope=self._waf_scope,
                Id=ruleset_id,
                LockToken=response["LockToken"],
            )

        self._with_lock_retry(_op, f"RuleGroup {ruleset_id} delete")

    @_wrap_provider_errors
    def get_all_custom_rulesets(
        self, scope: Scope, *, ruleset_ids: list[str] | None = None
    ) -> dict[str, dict]:
        """Fetch all Rule Groups and their rules.

        Pre-fetches the rule group list once so that individual
        ``get_custom_ruleset`` calls don't each hit the list API.
        """
        rg_list = self._paginate_list(self._client.list_rule_groups, "RuleGroups")
        if ruleset_ids is None:
            meta_list = [
                {
                    "id": rg.get("Id", ""),
                    "name": rg.get("Name", ""),
                    "phase": "",
                    "description": rg.get("Description", ""),
                }
                for rg in rg_list
            ]
        else:
            meta_list = [{"id": rid, "name": "", "phase": ""} for rid in ruleset_ids]

        if not meta_list:
            return {}

        results: dict[str, dict] = {}
        for meta in meta_list:
            rid = meta["id"]
            rules = self.get_custom_ruleset(scope, rid, _rg_cache=rg_list)
            results[rid] = {
                "name": meta.get("name", ""),
                "phase": meta.get("phase", ""),
                "rules": rules,
            }
        return results

    def _find_resource(
        self,
        resource_id: str,
        api_method,
        response_key: str,
        label: str,
        *,
        _cache: list[dict] | None = None,
    ) -> dict:
        """Look up a resource by ID. Raises ConfigError if not found.

        When ``_cache`` is provided, the list API call is skipped and the
        cached metadata is searched instead.
        """
        items = _cache if _cache is not None else self._paginate_list(api_method, response_key)
        for item in items:
            if item.get("Id") == resource_id:
                return item
        raise ConfigError(f"{label} {resource_id!r} not found")

    def _find_rule_group(self, ruleset_id: str, *, _cache: list[dict] | None = None) -> dict:
        """Look up rule group metadata by ID. Raises ConfigError if not found."""
        return self._find_resource(
            ruleset_id, self._client.list_rule_groups, "RuleGroups", "Rule Group", _cache=_cache
        )

    # -- IP Sets (lists) --

    @_wrap_provider_errors
    def list_lists(self, scope: Scope) -> list[dict]:
        """List all IP Sets."""
        all_ips = self._paginate_list(self._client.list_ip_sets, "IPSets")
        return [
            {
                "id": ip_set.get("Id", ""),
                "name": ip_set.get("Name", ""),
                "kind": "ip",
                "description": ip_set.get("Description", ""),
            }
            for ip_set in all_ips
        ]

    @_wrap_provider_errors
    def create_list(self, scope: Scope, name: str, kind: str, description: str = "") -> dict:
        """Create a new IP Set."""
        ip_version = "IPV6" if kind == "ipv6" else "IPV4"
        response = self._client.create_ip_set(
            Name=name,
            Scope=self._waf_scope,
            IPAddressVersion=ip_version,
            Addresses=[],
            Description=description,
        )
        summary = response.get("Summary", {})
        return {
            "id": summary.get("Id", ""),
            "name": summary.get("Name", name),
        }

    @_wrap_provider_errors
    def delete_list(self, scope: Scope, list_id: str) -> None:
        """Delete an IP Set. Retries on stale LockToken."""
        meta = self._find_ip_set(list_id)

        def _op() -> None:
            response = self._client.get_ip_set(Name=meta["Name"], Scope=self._waf_scope, Id=list_id)
            self._client.delete_ip_set(
                Name=meta["Name"],
                Scope=self._waf_scope,
                Id=list_id,
                LockToken=response["LockToken"],
            )

        self._with_lock_retry(_op, f"IPSet {list_id} delete")

    @_wrap_provider_errors
    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None:
        """Update an IP Set's description. Retries on stale LockToken.

        AWS WAF v2 does not support updating only the description — a full
        ``update_ip_set`` call is required, preserving existing addresses.
        """
        meta = self._find_ip_set(list_id)

        def _op() -> None:
            response = self._client.get_ip_set(Name=meta["Name"], Scope=self._waf_scope, Id=list_id)
            self._client.update_ip_set(
                Name=meta["Name"],
                Scope=self._waf_scope,
                Id=list_id,
                Addresses=response["IPSet"].get("Addresses", []),
                Description=description,
                LockToken=response["LockToken"],
            )

        self._with_lock_retry(_op, f"IPSet {list_id} description")

    @_wrap_provider_errors
    def get_list_items(
        self, scope: Scope, list_id: str, *, _ip_cache: list[dict] | None = None
    ) -> list[dict]:
        """Fetch all addresses from an IP Set."""
        meta = self._find_ip_set(list_id, _cache=_ip_cache)
        response = self._client.get_ip_set(Name=meta["Name"], Scope=self._waf_scope, Id=list_id)
        addresses = response.get("IPSet", {}).get("Addresses", [])
        return [{"ip": addr} for addr in addresses]

    @_wrap_provider_errors
    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str:
        """Replace all addresses in an IP Set. Returns a synthetic operation ID.

        Retries on ``WAFOptimisticLockException`` (stale LockToken).
        """
        meta = self._find_ip_set(list_id)
        addresses: list[str] = []
        for i, item in enumerate(items):
            if "ip" in item:
                addresses.append(item["ip"])
            elif "value" in item:
                addresses.append(item["value"])
            else:
                raise ProviderError(f"List item {i} missing 'ip' or 'value' key")

        def _op() -> str:
            response = self._client.get_ip_set(Name=meta["Name"], Scope=self._waf_scope, Id=list_id)
            self._client.update_ip_set(
                Name=meta["Name"],
                Scope=self._waf_scope,
                Id=list_id,
                Addresses=addresses,
                LockToken=response["LockToken"],
            )
            return f"aws-sync-{list_id}"

        return self._with_lock_retry(_op, f"IPSet {list_id}")

    @_wrap_provider_errors
    def poll_bulk_operation(
        self, scope: Scope, operation_id: str, *, timeout: float = 120.0
    ) -> str:
        """AWS WAF operations are synchronous — always returns 'completed'."""
        return "completed"

    @_wrap_provider_errors
    def get_all_lists(
        self, scope: Scope, *, list_names: list[str] | None = None
    ) -> dict[str, dict]:
        """Fetch all IP Sets and their addresses.

        Pre-fetches the IP set list once so that individual
        ``get_list_items`` calls don't each hit the list API.
        """
        ip_list = self._paginate_list(self._client.list_ip_sets, "IPSets")
        all_meta = [
            {
                "id": ip_set.get("Id", ""),
                "name": ip_set.get("Name", ""),
                "kind": "ip",
                "description": ip_set.get("Description", ""),
            }
            for ip_set in ip_list
        ]
        if list_names is not None:
            name_set = set(list_names)
            all_meta = [m for m in all_meta if m["name"] in name_set]

        if not all_meta:
            return {}

        results: dict[str, dict] = {}
        for meta in all_meta:
            items = self.get_list_items(scope, meta["id"], _ip_cache=ip_list)
            results[meta["name"]] = {
                "id": meta["id"],
                "kind": meta["kind"],
                "description": meta["description"],
                "items": items,
            }
        return results

    def _find_ip_set(self, list_id: str, *, _cache: list[dict] | None = None) -> dict:
        """Look up IP Set metadata by ID. Raises ConfigError if not found."""
        return self._find_resource(
            list_id, self._client.list_ip_sets, "IPSets", "IP Set", _cache=_cache
        )
