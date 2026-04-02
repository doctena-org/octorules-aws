# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.6.0] - 2026-04-02

### Added
- `wcu_limit` provider config option to override the default 1,500 WCU limit
  for accounts with custom capacity (up to 5,000 via AWS support).
- WA102: Non-contiguous rule priorities (INFO).
- WA154: Reserved label namespace validation — ``aws:``/``awswaf:`` prefixes
  rejected (ERROR).
- WA156: Managed rule group version not pinned (WARNING).
- WA158: IP set item count exceeds 10,000 address limit (WARNING).
- WA330: Statement nesting depth guard — errors when nesting exceeds 20 levels.
- WA354: CustomResponse body exceeds 4,096 bytes (ERROR).
- WA355: CustomResponse exceeds 10 custom headers (ERROR).
- WA356: CustomResponse header name validation — RFC 7230 (ERROR).
- WA357: CustomResponseBodyKey is empty (WARNING).
- WA602: Count action on ManagedRuleGroupStatement logs all traffic (INFO).
- Pagination safety cap (1,000 pages) to prevent infinite loops on malformed
  API responses.

### Changed
- WA310 now also rejects `AndStatement`/`OrStatement` with more than 10 nested
  statements (AWS WAF limit).
- `SearchString` bytes with invalid UTF-8 are now decoded with replacement
  characters and a logged warning, instead of silent replacement.
- Removed CI `concurrency` blocks from lint and test workflows.
- Removed redundant `pip install yamllint` from lint workflow (now in dev deps).

### Fixed
- WA307: ``SearchString`` byte limit corrected from 8,192 to 200 bytes
  (matches AWS WAF API documentation).
- WA323: ``GeoMatchStatement`` country code limit corrected from 25 to 50
  (matches AWS WAF quotas).
- WA355: ``CustomResponse`` header limit corrected from 5 to 10
  (matches AWS WAF quotas).

## [0.5.4] - 2026-03-31

### Changed
- Phase IDs and names are now derived from a single source of truth (`_phases.py`) instead of hand-maintained frozensets.

### Added
- Tests for `create_custom_ruleset` (success path, arguments verification, name fallback) and `delete_custom_ruleset` (success, error wrapping, lock retry).
- Tests for `CLOUDFRONT` scope (API parameter passthrough, env var fallback, invalid scope rejection).

## [0.5.3] - 2026-03-30

### Added
- Response validation for `create_list()` and `create_custom_ruleset()` —
  raises `ProviderError` if API response lacks expected ID.

### Changed
- IPSet ARN collection extracted to shared `_statement_util` module (removes
  duplication between audit and linter).
- Boolean-as-int validation uses `_is_strict_int()` helper for consistency.

## [0.5.2] - 2026-03-30

### Changed
- Extract `_result()` factory helper in `validate.py` to reduce
  `LintResult` boilerplate across 72 call sites.

## [0.5.1] - 2026-03-30

### Changed
- `_paginate_list()` now guards against infinite loops by tracking seen
  `NextMarker` values and breaking with a warning on repetition.
- Extract `_find_resource()` helper from `_find_rule_group()` /
  `_find_ip_set()` to eliminate DRY violation.

### Added
- Ruff `B` (bugbear) and `RUF` lint rule categories to `pyproject.toml`.
- `yamllint` step in lint CI workflow (parity with core/cloudflare).
- Pre-commit hook (`scripts/hooks/pre-commit`) for ruff lint + format.
- Test for pagination loop detection (repeated `NextMarker`).
- `Topic` classifiers and `Issues` URL in `pyproject.toml`.
- Comprehensive `.gitignore` (aligned with core).

## [0.5.0] - 2026-03-25

### Added
- Audit IP extractor: extracts IPSet names from `IPSetReferenceStatement` ARNs
  as `list_refs` for use by `octorules audit`.
- Export `AWS_PHASE_NAMES` frozenset from package root.

## [0.4.1] - 2026-03-24

### Added
- `TestConcurrentWorkers` tests: concurrent `get_phase_rules` success, partial
  failure, auth error propagation, and thread-safe metadata population.

## [0.4.0] - 2026-03-23

### Added
- **WA326** (INFO): IPSetReferenceStatement references an IP Set name not
  found in the `lists` section. Suggests adding it for full lifecycle
  management.
- **WA340** (WARNING): Estimated total WCU across all phases exceeds the
  Web ACL default limit of 1,500. Includes per-statement-type WCU cost
  estimation with recursive compound statement support.
- **WA341** (WARNING): GeoMatchStatement with >= 200 country codes is
  likely always true (covers nearly all countries).
- **WA342** (WARNING): AndStatement contains GeoMatchStatements with
  non-overlapping country code sets — no request can satisfy both
  conditions simultaneously.
- **WA343** (WARNING): SizeConstraintStatement with `Size=0` and
  `ComparisonOperator=LT` is always false (size cannot be negative).
- **WA307** (ERROR): SearchString exceeds 8,192-byte AWS WAF limit.
- **WA308** (ERROR): RegexString exceeds 512-byte AWS WAF limit.
- **WA309** (WARNING): RateBasedStatement without ScopeDownStatement
  rate-limits all traffic.
- **WA320** (WARNING): FieldToMatch type incompatible with statement type
  (e.g., JsonBody on LabelMatchStatement).
- **WA323** (ERROR): GeoMatchStatement exceeds maximum of 25 country codes.
- **WA324** (ERROR): RateBasedStatement.CustomKeys exceeds maximum of 5.
- **WA325** (ERROR): FieldToMatch Headers/Cookies MatchPattern exceeds
  maximum of 5 patterns.
- **WA331** (ERROR): TextTransformations exceeds maximum of 10 per statement.
- **WA332** (ERROR): Duplicate TextTransformation Priority values.
- **WA334** (ERROR): SizeConstraintStatement.Size must be non-negative.
- **WA335** (ERROR): JsonBody.MatchScope must be ALL, KEY, or VALUE.
- **WA336** (ERROR): JsonBody.InvalidFallbackBehavior must be MATCH,
  NO_MATCH, or EVALUATE_AS_STRING.
- **Rule Group lifecycle management.** octorules can now create and delete
  AWS WAF Rule Groups declaratively. New rulesets without an `id` field
  (but with a `capacity` field) are created automatically. Rulesets removed
  from YAML are deleted from AWS.
- `create_custom_ruleset()` and `delete_custom_ruleset()` provider methods.
- Lock retry with linear backoff for all optimistic-lock operations
  (`_with_lock_retry` helper replaces 5 duplicated retry loops).

### Changed
- Requires `octorules>=0.18.0`.

## [0.3.0] - 2026-03-20

### Added
- **WA319** (ERROR): Invalid regex pattern in `RegexMatchStatement.RegexString`.
- **WA321** (WARNING): Redundant double negation (`NotStatement` wrapping
  `NotStatement`).
- **WA600** (INFO): Disabled rules (`enabled: false`).
- `enabled` is now a recognized top-level rule field (no longer triggers WA020).
- Lint rule reference: `docs/lint.md`.

## [0.2.0] - 2026-03-19

### Changed
- Error wrapping uses `make_error_wrapper` from `octorules.provider.utils`
  instead of a hand-rolled decorator.
- Requires `octorules>=0.17.0`.

### Removed
- Page Shield stub methods removed from `AwsWafProvider`. The `BaseProvider`
  protocol no longer requires them.

## [0.1.0] - 2026-03-17

### Added

- Initial release: AwsWafProvider for octorules.
- Document `octorules:` rule-level metadata support (`ignored`, `included`,
  `excluded`) — inherited from octorules core.
- Validate `waf_scope` on init (must be `REGIONAL` or `CLOUDFRONT`).
- **WA501**: cross-phase MetricName uniqueness check. AWS WAF requires
  MetricName to be unique across all rules in a Web ACL, not just within a
  single phase.
- **Deep statement validation** (WA314-WA318): required fields per statement
  type (ByteMatch, GeoMatch, IPSet, Regex, Size, Sqli, Xss, Label, etc.),
  enum validation (PositionalConstraint, ComparisonOperator, etc.),
  FieldToMatch nesting, TextTransformation types, RateBasedStatement
  conditional requirements.
- **Action parameter validation** (WA350-WA353): Action must have exactly one
  key, unknown action types, OverrideAction only on group statements,
  CustomResponse status code range.
- **YAML structure validation** (WA020-WA021): unknown top-level rule fields,
  Action/OverrideAction type checks.
- **WA520**: duplicate Statement detection across rules in the same phase.
- Linter plugin: registers 38 AWS lint rules (WA*) with octorules core lint
  engine.
- Pagination support for all list API calls (Web ACLs, Rule Groups, IP Sets).

### Changed

- N+1 API calls eliminated: bulk operations (`get_all_custom_rulesets`,
  `get_all_lists`) pre-fetch metadata once.
- Logger uses `__name__` instead of hardcoded `"octorules"`.

### Fixed

- Thread safety: `_web_acl_meta` reads now acquire the lock, preventing
  races when `max_workers > 1`.
- Optimistic locking: all mutating operations (`put_phase_rules`,
  `put_custom_ruleset`, `put_list_items`, `delete_list`,
  `update_list_description`) retry up to 3 times on
  `WAFOptimisticLockException` instead of failing immediately.
- Entry point `octorules.providers: aws` for auto-discovery by octorules core.
- Register `OverrideAction` as an API field to strip from rules.
- Register `custom_rulesets` as a non-phase key.
- Phase mapping: `aws_waf_custom_rules`, `aws_waf_rate_rules`, `aws_waf_managed_rules`.
- Custom rulesets mapped to AWS WAF Rule Groups.
- Lists mapped to AWS WAF IP Sets.
- Exception wrapping: boto3 errors mapped to ProviderError/ProviderAuthError.
