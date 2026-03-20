# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
