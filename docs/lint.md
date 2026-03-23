# Lint Rule Reference

`octorules lint` performs offline static analysis of your AWS WAF rules files. **59 rules** with the `WA` prefix cover structure, actions, statements, visibility config, priority, cross-rule analysis, and best practices.

These rules are registered automatically when `octorules-aws` is installed. They run alongside any core and other provider rules during `octorules lint`.

### Suppressing rules

Add a `# octorules:disable=RULE` comment immediately before a rule to suppress a specific finding. Multiple rule IDs can be comma-separated.

```yaml
aws_waf_custom_rules:
  # octorules:disable=WA001
  - Priority: 10
    Action:
      Block: {}
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN", "RU"]
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockGeo
```

**Multiple rules:**

```yaml
  # octorules:disable=WA020,WA313
  - ref: legacy-rule
    Priority: 10
    CustomField: something
    ...
```

Suppressed findings are excluded from the report but counted in the summary line (e.g., `Total: 0 error(s), 0 warning(s), 0 info (1 suppressed)`).

### Severity levels

| Level | Meaning |
|-------|---------|
| **ERROR** | Invalid config that will fail at AWS WAF API |
| **WARNING** | Likely mistake or suboptimal pattern |
| **INFO** | Style suggestion |

---

## Rule ID Quick Reference

| ID | Description | Severity |
|----|-------------|----------|
| [WA001](#wa001--rule-missing-ref) | Rule missing 'ref' | ERROR |
| [WA002](#wa002--rule-missing-priority) | Rule missing 'Priority' | ERROR |
| [WA003](#wa003--rule-missing-visibilityconfig) | Rule missing 'VisibilityConfig' | ERROR |
| [WA004](#wa004--rule-missing-both-action-and-overrideaction) | Rule missing both Action and OverrideAction | ERROR |
| [WA005](#wa005--rule-has-both-action-and-overrideaction) | Rule has both Action and OverrideAction | ERROR |
| [WA010](#wa010--invalid-ref-format) | Invalid ref format | ERROR |
| [WA020](#wa020--unknown-top-level-rule-field) | Unknown top-level rule field | WARNING |
| [WA021](#wa021--actionoverrideaction-must-be-dict) | Action/OverrideAction must be dict | ERROR |
| [WA022](#wa022--duplicate-ref-within-phase) | Duplicate ref within phase | ERROR |
| [WA100](#wa100--priority-must-be-a-non-negative-integer) | Priority must be a non-negative integer | ERROR |
| [WA101](#wa101--duplicate-priority-across-rules) | Duplicate Priority across rules | ERROR |
| [WA200](#wa200--invalid-action-type) | Invalid Action type | ERROR |
| [WA201](#wa201--invalid-overrideaction-type) | Invalid OverrideAction type | ERROR |
| [WA300](#wa300--statement-must-have-exactly-one-type) | Statement must have exactly one type | ERROR |
| [WA301](#wa301--unknown-statement-type) | Unknown statement type | WARNING |
| [WA302](#wa302--arn-format-mismatch) | ARN format mismatch | WARNING |
| [WA303](#wa303--ratebasedstatementlimit-invalid) | RateBasedStatement.Limit invalid | ERROR |
| [WA304](#wa304--ratebasedstatement-missing-aggregatekeytype) | RateBasedStatement missing AggregateKeyType | ERROR |
| [WA305](#wa305--invalid-aggregatekeytype) | Invalid AggregateKeyType | ERROR |
| [WA306](#wa306--ratebasedstatementlimit-exceeds-maximum) | RateBasedStatement.Limit exceeds maximum | ERROR |
| [WA307](#wa307--searchstring-exceeds-8192-byte-limit) | SearchString exceeds 8192-byte limit | ERROR |
| [WA308](#wa308--regexstring-exceeds-512-byte-limit) | RegexString exceeds 512-byte limit | ERROR |
| [WA309](#wa309--ratebasedstatement-without-scopedownstatement) | RateBasedStatement without ScopeDownStatement rate-limits all traffic | WARNING |
| [WA310](#wa310--andorstatement-must-have-at-least-2-nested-statements) | And/OrStatement must have at least 2 nested statements | ERROR |
| [WA311](#wa311--notstatement-missing-required-statement-field) | NotStatement missing required 'Statement' field | ERROR |
| [WA312](#wa312--bytematchstatement-missing-required-field) | ByteMatchStatement missing required field | ERROR |
| [WA313](#wa313--invalid-country-code-format) | Invalid country code format | WARNING |
| [WA314](#wa314--missing-required-field-in-statement-type) | Missing required field in statement type | ERROR |
| [WA315](#wa315--invalid-enum-value-in-statement) | Invalid enum value in statement | ERROR |
| [WA316](#wa316--fieldtomatch-validation-error) | FieldToMatch validation error | ERROR |
| [WA317](#wa317--texttransformations-validation-error) | TextTransformations validation error | ERROR |
| [WA318](#wa318--ratebasedstatement-conditional-requirement) | RateBasedStatement conditional requirement | ERROR |
| [WA319](#wa319--invalid-regex-pattern-in-regexmatchstatement) | Invalid regex pattern in RegexMatchStatement | ERROR |
| [WA320](#wa320--fieldtomatch-type-incompatible-with-statement-type) | FieldToMatch type incompatible with statement type | WARNING |
| [WA321](#wa321--redundant-double-negation-notstatement-wrapping-notstatement) | Redundant double negation (NotStatement wrapping NotStatement) | WARNING |
| [WA323](#wa323--geomatchstatement-exceeds-25-country-codes) | GeoMatchStatement exceeds 25 country codes | ERROR |
| [WA324](#wa324--ratebasedstatementcustomkeys-exceeds-maximum-of-5) | RateBasedStatement.CustomKeys exceeds maximum of 5 | ERROR |
| [WA325](#wa325--fieldtomatch-headerscookies-matchpattern-exceeds-maximum-of-5-patterns) | FieldToMatch Headers/Cookies MatchPattern exceeds maximum of 5 patterns | ERROR |
| [WA331](#wa331--texttransformations-exceeds-maximum-of-10-per-statement) | TextTransformations exceeds maximum of 10 per statement | ERROR |
| [WA332](#wa332--duplicate-texttransformation-priority) | Duplicate TextTransformation Priority | ERROR |
| [WA334](#wa334--sizeconstraintstatementssize-must-be-non-negative) | SizeConstraintStatement.Size must be non-negative | ERROR |
| [WA335](#wa335--jsonbodymatchscope-invalid) | JsonBody.MatchScope invalid | ERROR |
| [WA336](#wa336--jsonbodyinvalidfallbackbehavior-invalid) | JsonBody.InvalidFallbackBehavior invalid | ERROR |
| [WA350](#wa350--action-must-have-exactly-one-key) | Action must have exactly one key | ERROR |
| [WA351](#wa351--unknown-action-type) | Unknown action type | ERROR |
| [WA352](#wa352--overrideaction-on-non-group-statement) | OverrideAction on non-group statement | WARNING |
| [WA353](#wa353--customresponse-status-code-invalid) | CustomResponse status code invalid | ERROR |
| [WA400](#wa400--visibilityconfig-missing-required-field) | VisibilityConfig missing required field | ERROR |
| [WA401](#wa401--visibilityconfig-field-wrong-type) | VisibilityConfig field wrong type | ERROR |
| [WA402](#wa402--metricname-exceeds-128-characters) | MetricName exceeds 128 characters | ERROR |
| [WA500](#wa500--duplicate-metricname-across-rules) | Duplicate MetricName across rules | ERROR |
| [WA501](#wa501--duplicate-metricname-across-phases) | Duplicate MetricName across phases | ERROR |
| [WA520](#wa520--duplicate-statement-across-rules-in-phase) | Duplicate statement across rules in phase | WARNING |
| [WA326](#wa326--ipsetreferencestatement-references-ip-set-not-in-lists-section) | IPSetReferenceStatement references IP Set not in lists section | INFO |
| [WA340](#wa340--estimated-total-wcu-exceeds-web-acl-limit) | Estimated total WCU exceeds Web ACL limit | WARNING |
| [WA341](#wa341--geomatchstatement-likely-always-true) | GeoMatchStatement likely always true | WARNING |
| [WA342](#wa342--contradictory-and-conditions-non-overlapping-geomatch-sets) | Contradictory AND conditions (non-overlapping GeoMatch sets) | WARNING |
| [WA343](#wa343--always-false-pattern-sizeconstraint-size--0-is-impossible) | Always-false pattern (SizeConstraint size < 0 is impossible) | WARNING |
| [WA600](#wa600--rule-is-disabled-enabled-false) | Rule is disabled (enabled: false) | INFO |

---

## Categories

| WA Range | Category | Rules |
|----------|----------|-------|
| WA001-WA005, WA010, WA020-WA022 | Structure & YAML | 9 |
| WA100-WA101 | Priority | 2 |
| WA200-WA201 | Action type | 2 |
| WA300-WA343 | Statement validation | 33 |
| WA350-WA353 | Action parameters | 4 |
| WA400-WA402 | VisibilityConfig | 3 |
| WA326, WA340, WA500-WA501, WA520 | Cross-rule | 5 |
| WA600 | Best practice | 1 |

---

## Structure & YAML

### WA001 -- Rule missing 'ref'

**Severity:** ERROR

Every rule must have a `ref` field that serves as the rule's unique identifier (maps to the AWS WAF rule `Name`).

**Triggers on:**

```yaml
aws_waf_custom_rules:
  - Priority: 10
    Action:
      Block: {}
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockChina
```

**Fix:** Add a `ref` field:

```yaml
  - ref: block-china
    Priority: 10
    ...
```

### WA010 -- Invalid ref format

**Severity:** ERROR

The `ref` value must be 1-128 characters and contain only alphanumeric characters, underscores, and hyphens (`A-Z`, `a-z`, `0-9`, `_`, `-`). This matches the AWS WAF rule name constraints.

**Triggers on:**

```yaml
  - ref: "my rule with spaces!"
    ...
```

**Fix:** Use only allowed characters:

```yaml
  - ref: my-rule-with-spaces
    ...
```

### WA002 -- Rule missing 'Priority'

**Severity:** ERROR

Every rule must have a `Priority` field. AWS WAF uses priority to determine rule evaluation order within a Web ACL.

**Triggers on:**

```yaml
  - ref: block-bad-ips
    Action:
      Block: {}
    Statement:
      IPSetReferenceStatement:
        ARN: arn:aws:wafv2:us-east-1:123456789012:regional/ipset/bad-ips/abc123
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockBadIPs
```

**Fix:** Add a `Priority` field:

```yaml
  - ref: block-bad-ips
    Priority: 10
    ...
```

### WA003 -- Rule missing 'VisibilityConfig'

**Severity:** ERROR

Every rule must have a `VisibilityConfig` section. AWS WAF requires this for CloudWatch metrics and request sampling.

**Triggers on:**

```yaml
  - ref: block-bad-ips
    Priority: 10
    Action:
      Block: {}
    Statement:
      IPSetReferenceStatement:
        ARN: arn:aws:wafv2:us-east-1:123456789012:regional/ipset/bad-ips/abc123
```

**Fix:** Add a `VisibilityConfig`:

```yaml
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockBadIPs
```

### WA004 -- Rule missing both Action and OverrideAction

**Severity:** ERROR

Every rule must specify either `Action` (for custom rules) or `OverrideAction` (for managed rule group / rule group references). Omitting both means the rule has no effect.

**Triggers on:**

```yaml
  - ref: no-action-rule
    Priority: 10
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: NoAction
```

**Fix:** Add an `Action`:

```yaml
    Action:
      Block: {}
```

### WA005 -- Rule has both Action and OverrideAction

**Severity:** ERROR

A rule must have either `Action` or `OverrideAction`, not both. `Action` is for custom rules; `OverrideAction` is for managed rule group and rule group references.

**Triggers on:**

```yaml
  - ref: conflicting-actions
    Priority: 10
    Action:
      Block: {}
    OverrideAction:
      Count: {}
    Statement:
      ManagedRuleGroupStatement:
        VendorName: AWS
        Name: AWSManagedRulesCommonRuleSet
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: Conflicting
```

**Fix:** Remove one. For managed rule groups, use `OverrideAction`:

```yaml
  - ref: aws-common-rules
    Priority: 10
    OverrideAction:
      Count: {}
    Statement:
      ManagedRuleGroupStatement:
        VendorName: AWS
        Name: AWSManagedRulesCommonRuleSet
    ...
```

### WA020 -- Unknown top-level rule field

**Severity:** WARNING

Warns when a rule contains a field not in the recognized set: `ref`, `Priority`, `Action`, `OverrideAction`, `Statement`, `VisibilityConfig`, `RuleLabels`. Unknown fields are silently ignored by the provider and usually indicate a typo.

**Triggers on:**

```yaml
  - ref: typo-rule
    Priority: 10
    Acton:              # typo: should be "Action"
      Block: {}
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: TypoRule
```

**Fix:** Correct the field name to `Action`.

### WA021 -- Action/OverrideAction must be dict

**Severity:** ERROR

The `Action` and `OverrideAction` fields must be dictionaries mapping an action type to its configuration. Scalar values (strings, integers) are not valid.

**Triggers on:**

```yaml
  - ref: bad-action-type
    Priority: 10
    Action: Block       # should be a dict
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BadAction
```

**Fix:** Use the dict form:

```yaml
    Action:
      Block: {}
```

### WA022 -- Duplicate ref within phase

**Severity:** ERROR

Two rules in the same phase must not share the same `ref` value. The `ref` maps to the AWS WAF rule name and must be unique within a Web ACL.

**Triggers on:**

```yaml
aws_waf_custom_rules:
  - ref: block-china
    Priority: 10
    ...
  - ref: block-china      # duplicate
    Priority: 20
    ...
```

**Fix:** Give each rule a unique `ref`.

---

## Priority

### WA100 -- Priority must be a non-negative integer

**Severity:** ERROR

The `Priority` field must be a non-negative integer (0 or greater). Strings, floats, booleans, and negative values are rejected.

**Triggers on:**

```yaml
  - ref: bad-priority
    Priority: "high"
    ...
```

**Fix:** Use a non-negative integer:

```yaml
    Priority: 10
```

### WA101 -- Duplicate Priority across rules

**Severity:** ERROR

Two or more rules within the same phase share the same `Priority` value. AWS WAF requires unique priorities within a Web ACL.

**Triggers on:**

```yaml
aws_waf_custom_rules:
  - ref: rule-a
    Priority: 10
    ...
  - ref: rule-b
    Priority: 10     # same as rule-a
    ...
```

**Fix:** Assign distinct priority values:

```yaml
  - ref: rule-a
    Priority: 10
    ...
  - ref: rule-b
    Priority: 20
    ...
```

---

## Action Type

### WA200 -- Invalid Action type

**Severity:** ERROR

The `Action` dict contains a key that is not a valid AWS WAF action. Valid action types are: `Allow`, `Block`, `Captcha`, `Challenge`, `Count`.

**Triggers on:**

```yaml
    Action:
      Deny: {}        # not a valid AWS WAF action
```

**Fix:** Use a valid action type:

```yaml
    Action:
      Block: {}
```

### WA201 -- Invalid OverrideAction type

**Severity:** ERROR

The `OverrideAction` dict contains a key that is not valid. Valid override action types are: `Count`, `None`.

**Triggers on:**

```yaml
    OverrideAction:
      Block: {}        # not valid for OverrideAction
```

**Fix:** Use a valid override action:

```yaml
    OverrideAction:
      None: {}         # pass through the managed group's actions
```

---

## Statement Validation

### WA300 -- Statement must have exactly one type

**Severity:** ERROR

Each `Statement` dict must contain exactly one key identifying its type. Multiple statement types at the same level are not valid -- use `AndStatement` or `OrStatement` to combine conditions.

**Triggers on:**

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
      IPSetReferenceStatement:           # two types in one Statement
        ARN: arn:aws:wafv2:...
```

**Fix:** Wrap in an `AndStatement`:

```yaml
    Statement:
      AndStatement:
        Statements:
          - GeoMatchStatement:
              CountryCodes: ["CN"]
          - IPSetReferenceStatement:
              ARN: arn:aws:wafv2:...
```

### WA301 -- Unknown statement type

**Severity:** WARNING

The statement type key is not in the recognized set of AWS WAF statement types. This may indicate a typo or an unsupported statement type. Recognized types: `AndStatement`, `ByteMatchStatement`, `GeoMatchStatement`, `IPSetReferenceStatement`, `LabelMatchStatement`, `ManagedRuleGroupStatement`, `NotStatement`, `OrStatement`, `RateBasedStatement`, `RegexMatchStatement`, `RegexPatternSetReferenceStatement`, `RuleGroupReferenceStatement`, `SizeConstraintStatement`, `SqliMatchStatement`, `XssMatchStatement`.

**Triggers on:**

```yaml
    Statement:
      GeoBlockStatement:     # not a real type
        CountryCodes: ["CN"]
```

**Fix:** Use the correct type name:

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
```

### WA302 -- ARN format mismatch

**Severity:** WARNING

An ARN string was found that starts with `arn:` but does not match the expected `arn:aws*:wafv2:` pattern. This often means an ARN from another service was pasted by mistake.

**Triggers on:**

```yaml
    Statement:
      IPSetReferenceStatement:
        ARN: arn:aws:s3:::my-bucket      # not a wafv2 ARN
```

**Fix:** Use the correct WAFv2 ARN:

```yaml
        ARN: arn:aws:wafv2:us-east-1:123456789012:regional/ipset/my-set/abc123
```

### WA303 -- RateBasedStatement.Limit invalid

**Severity:** ERROR

The `Limit` field in a `RateBasedStatement` must be an integer >= 10. AWS WAF requires the rate limit to be at least 10 requests per 5-minute window.

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 5               # below minimum of 10
        AggregateKeyType: IP
```

**Fix:** Set `Limit` to at least 10:

```yaml
        Limit: 100
```

### WA304 -- RateBasedStatement missing AggregateKeyType

**Severity:** ERROR

A `RateBasedStatement` must include an `AggregateKeyType` field to specify how requests are grouped for counting.

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 100
        # AggregateKeyType is missing
```

**Fix:** Add an `AggregateKeyType`:

```yaml
    Statement:
      RateBasedStatement:
        Limit: 100
        AggregateKeyType: IP
```

### WA305 -- Invalid AggregateKeyType

**Severity:** ERROR

The `AggregateKeyType` value is not one of the valid options: `CONSTANT`, `CUSTOM_KEYS`, `FORWARDED_IP`, `IP`.

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 100
        AggregateKeyType: SOURCE_IP    # not valid
```

**Fix:** Use a valid value:

```yaml
        AggregateKeyType: IP
```

### WA306 -- RateBasedStatement.Limit exceeds maximum

**Severity:** ERROR

The `Limit` value exceeds the AWS WAF maximum of 2,000,000,000 requests per 5-minute window.

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 3000000000
        AggregateKeyType: IP
```

**Fix:** Set `Limit` to at most 2,000,000,000:

```yaml
        Limit: 2000000000
```

### WA307 -- SearchString exceeds 8192-byte limit

**Severity:** ERROR

The `SearchString` in a `ByteMatchStatement` must not exceed 8,192 bytes when encoded as UTF-8. AWS WAF rejects longer values at the API level.

**Triggers on:**

```yaml
    Statement:
      ByteMatchStatement:
        SearchString: "<very long string exceeding 8192 bytes>"
        FieldToMatch:
          UriPath: {}
        TextTransformations:
          - Priority: 0
            Type: NONE
        PositionalConstraint: CONTAINS
```

**Fix:** Shorten the `SearchString` to fit within 8,192 bytes. For multi-byte characters (e.g., accented letters, emoji), note that the byte count may exceed the character count.

> **Note:** The limit is measured in bytes (UTF-8), not characters. A string of 8,192 ASCII characters is exactly at the limit, but 4,097 two-byte characters (8,194 bytes) exceeds it.

### WA308 -- RegexString exceeds 512-byte limit

**Severity:** ERROR

The `RegexString` in a `RegexMatchStatement` must not exceed 512 bytes when encoded as UTF-8. AWS WAF rejects longer patterns at the API level.

**Triggers on:**

```yaml
    Statement:
      RegexMatchStatement:
        RegexString: "<very long regex exceeding 512 bytes>"
        FieldToMatch:
          UriPath: {}
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Simplify the regex pattern to fit within 512 bytes. Consider using a `RegexPatternSetReferenceStatement` with multiple shorter patterns if the logic requires a long expression.

> **Note:** This check only fires when `RegexString` is present and is a string. If `RegexString` is missing entirely, [WA314](#wa314--missing-required-field-in-statement-type) catches it.

### WA309 -- RateBasedStatement without ScopeDownStatement

**Severity:** WARNING

A `RateBasedStatement` without a `ScopeDownStatement` applies the rate limit to **all** incoming traffic. This is usually unintentional -- most rate-limiting rules should target a specific subset of requests (e.g., login endpoints, API paths).

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 200
        AggregateKeyType: IP
```

**Fix:** Add a `ScopeDownStatement` to limit which requests are counted:

```yaml
    Statement:
      RateBasedStatement:
        Limit: 200
        AggregateKeyType: IP
        ScopeDownStatement:
          ByteMatchStatement:
            SearchString: "/api/login"
            FieldToMatch:
              UriPath: {}
            TextTransformations:
              - Priority: 0
                Type: NONE
            PositionalConstraint: STARTS_WITH
```

> **Note:** This is a warning, not an error. A blanket rate limit on all traffic is valid AWS WAF configuration -- it is just rarely the intended behavior. Suppress with `# octorules:disable=WA309` if intentional.

### WA310 -- And/OrStatement must have at least 2 nested statements

**Severity:** ERROR

`AndStatement` and `OrStatement` require a `Statements` list with at least 2 entries. A compound statement with 0 or 1 nested statements is pointless and rejected by the API.

**Triggers on:**

```yaml
    Statement:
      AndStatement:
        Statements:
          - GeoMatchStatement:
              CountryCodes: ["CN"]
          # only 1 statement -- needs at least 2
```

**Fix:** Add a second statement or remove the `AndStatement` wrapper:

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
```

### WA311 -- NotStatement missing required 'Statement' field

**Severity:** ERROR

A `NotStatement` must contain a `Statement` field with exactly one nested statement to negate.

**Triggers on:**

```yaml
    Statement:
      NotStatement:
        CountryCodes: ["CN"]    # wrong -- should be wrapped in Statement
```

**Fix:** Wrap in a `Statement` field:

```yaml
    Statement:
      NotStatement:
        Statement:
          GeoMatchStatement:
            CountryCodes: ["CN"]
```

### WA312 -- ByteMatchStatement missing required field

**Severity:** ERROR

A `ByteMatchStatement` requires four fields: `FieldToMatch`, `TextTransformations`, `PositionalConstraint`, and `SearchString`. This rule fires when any of them is missing.

**Triggers on:**

```yaml
    Statement:
      ByteMatchStatement:
        SearchString: "/admin"
        PositionalConstraint: STARTS_WITH
        # missing FieldToMatch and TextTransformations
```

**Fix:** Add all required fields:

```yaml
    Statement:
      ByteMatchStatement:
        SearchString: "/admin"
        PositionalConstraint: STARTS_WITH
        FieldToMatch:
          UriPath: {}
        TextTransformations:
          - Priority: 0
            Type: NONE
```

### WA313 -- Invalid country code format

**Severity:** WARNING

Country codes in `GeoMatchStatement.CountryCodes` must be ISO 3166-1 alpha-2 format -- exactly two uppercase ASCII letters.

**Triggers on:**

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["china", "123"]
```

**Fix:** Use two-letter uppercase codes:

```yaml
        CountryCodes: ["CN", "RU"]
```

### WA314 -- Missing required field in statement type

**Severity:** ERROR

A statement type is missing one or more required fields. Each statement type has its own set of required fields. For example, `IPSetReferenceStatement` requires `ARN`; `RegexMatchStatement` requires `RegexString`, `FieldToMatch`, and `TextTransformations`.

**Triggers on:**

```yaml
    Statement:
      IPSetReferenceStatement: {}
      # missing ARN
```

**Fix:** Add the required fields:

```yaml
    Statement:
      IPSetReferenceStatement:
        ARN: arn:aws:wafv2:us-east-1:123456789012:regional/ipset/my-set/abc123
```

Required fields by statement type:

| Statement type | Required fields |
|----------------|----------------|
| `IPSetReferenceStatement` | `ARN` |
| `RegexMatchStatement` | `RegexString`, `FieldToMatch`, `TextTransformations` |
| `RegexPatternSetReferenceStatement` | `ARN`, `FieldToMatch`, `TextTransformations` |
| `SizeConstraintStatement` | `FieldToMatch`, `ComparisonOperator`, `Size`, `TextTransformations` |
| `SqliMatchStatement` | `FieldToMatch`, `TextTransformations` |
| `XssMatchStatement` | `FieldToMatch`, `TextTransformations` |
| `LabelMatchStatement` | `Scope`, `Key` |
| `ManagedRuleGroupStatement` | `VendorName`, `Name` |
| `RuleGroupReferenceStatement` | `ARN` |

### WA315 -- Invalid enum value in statement

**Severity:** ERROR

A field that expects a fixed set of values received an unrecognized value. This covers `PositionalConstraint`, `ComparisonOperator`, `LabelMatchStatement.Scope`, and `SqliMatchStatement.SensitivityLevel`.

**Triggers on:**

```yaml
    Statement:
      ByteMatchStatement:
        SearchString: "/admin"
        PositionalConstraint: BEGINS_WITH    # not valid
        FieldToMatch:
          UriPath: {}
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Use a valid enum value. Valid `PositionalConstraint` values: `CONTAINS`, `CONTAINS_WORD`, `ENDS_WITH`, `EXACTLY`, `STARTS_WITH`.

Valid values by field:

| Field | Valid values |
|-------|-------------|
| `PositionalConstraint` | `CONTAINS`, `CONTAINS_WORD`, `ENDS_WITH`, `EXACTLY`, `STARTS_WITH` |
| `ComparisonOperator` | `EQ`, `GE`, `GT`, `LE`, `LT`, `NE` |
| `LabelMatchStatement.Scope` | `LABEL`, `NAMESPACE` |
| `SensitivityLevel` | `HIGH`, `LOW` |

### WA316 -- FieldToMatch validation error

**Severity:** ERROR

The `FieldToMatch` object is invalid. It must contain exactly one key from the valid set: `AllQueryArguments`, `Body`, `Cookies`, `Headers`, `JsonBody`, `Method`, `QueryString`, `SingleHeader`, `SingleQueryArgument`, `UriPath`. Additionally, `SingleHeader` and `SingleQueryArgument` require a nested `Name` field, and `JsonBody` requires `MatchScope` and `InvalidFallbackBehavior`.

**Triggers on:**

```yaml
        FieldToMatch:
          RequestBody: {}        # not a valid key
```

**Fix:** Use a valid `FieldToMatch` key:

```yaml
        FieldToMatch:
          Body: {}
```

### WA317 -- TextTransformations validation error

**Severity:** ERROR

The `TextTransformations` field must be a non-empty list of objects, each with an integer `Priority` and a string `Type` from the valid set. This rule fires for structural problems (wrong type, empty list, missing fields) and for unrecognized transformation types.

Valid transformation types: `BASE64_DECODE`, `BASE64_DECODE_EXT`, `CMD_LINE`, `COMPRESS_WHITE_SPACE`, `CSS_DECODE`, `ESCAPE_SEQ_DECODE`, `HEX_DECODE`, `HTML_ENTITY_DECODE`, `JS_DECODE`, `LOWERCASE`, `MD5`, `NONE`, `NORMALIZE_PATH`, `NORMALIZE_PATH_WIN`, `REMOVE_NULLS`, `REPLACE_COMMENTS`, `REPLACE_NULLS`, `SQL_HEX_DECODE`, `URL_DECODE`, `URL_DECODE_UNI`, `UTF8_TO_UNICODE`.

**Triggers on:**

```yaml
        TextTransformations: "NONE"    # must be a list
```

**Fix:** Use the correct list structure:

```yaml
        TextTransformations:
          - Priority: 0
            Type: NONE
```

### WA318 -- RateBasedStatement conditional requirement

**Severity:** ERROR

Certain `AggregateKeyType` values have conditional requirements:
- `CUSTOM_KEYS` requires a non-empty `CustomKeys` list.
- `FORWARDED_IP` requires a `ForwardedIPConfig` object.

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 100
        AggregateKeyType: CUSTOM_KEYS
        # missing CustomKeys
```

**Fix:** Add the required conditional field:

```yaml
    Statement:
      RateBasedStatement:
        Limit: 100
        AggregateKeyType: CUSTOM_KEYS
        CustomKeys:
          - Header:
              Name: x-api-key
              TextTransformations:
                - Priority: 0
                  Type: NONE
```

### WA319 -- Invalid regex pattern in RegexMatchStatement

**Severity:** ERROR

The `RegexString` in a `RegexMatchStatement` must be a valid regular expression. This rule compiles the pattern at lint time to catch syntax errors before they reach the AWS WAF API.

**Triggers on:**

```yaml
    Statement:
      RegexMatchStatement:
        RegexString: "(unclosed"
        FieldToMatch:
          UriPath: {}
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Correct the regex syntax:

```yaml
        RegexString: "\\(unclosed\\)"
```

> **Note:** This check only fires when `RegexString` is present and is a string. If `RegexString` is missing entirely, [WA314](#wa314--missing-required-field-in-statement-type) catches it instead. AWS WAF uses a regex dialect similar to PCRE; Python's `re` module catches most common syntax errors but may not flag every incompatibility.

### WA320 -- FieldToMatch type incompatible with statement type

**Severity:** WARNING

A `FieldToMatch` type is used with a statement type that does not inspect request content at that level. Specifically, `JsonBody` is only meaningful with statement types that inspect the request body: `ByteMatchStatement`, `RegexMatchStatement`, `RegexPatternSetReferenceStatement`, `SizeConstraintStatement`, `SqliMatchStatement`, and `XssMatchStatement`.

**Triggers on:**

```yaml
    Statement:
      LabelMatchStatement:
        Scope: LABEL
        Key: awswaf:managed:test
        FieldToMatch:
          JsonBody:
            MatchScope: ALL
            InvalidFallbackBehavior: MATCH
```

**Fix:** Remove the `FieldToMatch` field or use a compatible statement type:

```yaml
    Statement:
      LabelMatchStatement:
        Scope: LABEL
        Key: awswaf:managed:test
```

> **Note:** This rule currently only checks `JsonBody` compatibility. Other `FieldToMatch` types (e.g., `UriPath`, `Headers`) are broadly applicable across statement types.

### WA321 -- Redundant double negation (NotStatement wrapping NotStatement)

**Severity:** WARNING

A `NotStatement` whose inner `Statement` is itself a `NotStatement` is a redundant double negation. The two negations cancel out, making the rule harder to read without changing its effect.

**Triggers on:**

```yaml
    Statement:
      NotStatement:
        Statement:
          NotStatement:
            Statement:
              GeoMatchStatement:
                CountryCodes: ["CN"]
```

**Fix:** Remove both `NotStatement` wrappers to simplify:

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
```

### WA323 -- GeoMatchStatement exceeds 25 country codes

**Severity:** ERROR

The `CountryCodes` list in a `GeoMatchStatement` must not exceed 25 entries. AWS WAF enforces this limit at the API level.

**Triggers on:**

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["US", "DE", "FR", "GB", "JP", "CN", "RU", "BR", "IN", "AU", "CA", "MX", "KR", "IT", "ES", "NL", "SE", "NO", "DK", "FI", "PL", "CZ", "AT", "CH", "BE", "IE"]
```

**Fix:** Reduce the list to 25 or fewer country codes. If you need to match more countries, use an `OrStatement` with multiple `GeoMatchStatement` blocks.

### WA324 -- RateBasedStatement.CustomKeys exceeds maximum of 5

**Severity:** ERROR

The `CustomKeys` list in a `RateBasedStatement` must not exceed 5 entries. AWS WAF enforces this limit at the API level.

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 200
        AggregateKeyType: CUSTOM_KEYS
        CustomKeys:
          - Header: { Name: x-key-1 }
          - Header: { Name: x-key-2 }
          - Header: { Name: x-key-3 }
          - Header: { Name: x-key-4 }
          - Header: { Name: x-key-5 }
          - Header: { Name: x-key-6 }    # exceeds limit
```

**Fix:** Reduce the `CustomKeys` list to at most 5 entries.

### WA325 -- FieldToMatch Headers/Cookies MatchPattern exceeds maximum of 5 patterns

**Severity:** ERROR

The `MatchPattern` in a `Headers` or `Cookies` `FieldToMatch` must not exceed 5 entries in any of its inclusion/exclusion lists (`IncludedHeaders`, `ExcludedHeaders`, `IncludedCookies`, `ExcludedCookies`). AWS WAF enforces this limit at the API level.

**Triggers on:**

```yaml
        FieldToMatch:
          Headers:
            MatchPattern:
              IncludedHeaders: ["a", "b", "c", "d", "e", "f"]    # 6 > 5
            MatchScope: ALL
            OversizeHandling: MATCH
```

**Fix:** Reduce the list to 5 or fewer patterns.

### WA331 -- TextTransformations exceeds maximum of 10 per statement

**Severity:** ERROR

The `TextTransformations` list in a statement must not exceed 10 entries. AWS WAF enforces this limit at the API level.

**Triggers on:**

```yaml
        TextTransformations:
          - Priority: 0
            Type: URL_DECODE
          - Priority: 1
            Type: LOWERCASE
          # ... (11 or more entries)
```

**Fix:** Reduce the list to 10 or fewer transformations. Consider whether all transformations are necessary.

### WA332 -- Duplicate TextTransformation Priority

**Severity:** ERROR

Each entry in a `TextTransformations` list must have a unique `Priority` value. Duplicate priorities are rejected by the AWS WAF API.

**Triggers on:**

```yaml
        TextTransformations:
          - Priority: 0
            Type: URL_DECODE
          - Priority: 0          # duplicate Priority
            Type: LOWERCASE
```

**Fix:** Assign unique `Priority` values to each transformation:

```yaml
        TextTransformations:
          - Priority: 0
            Type: URL_DECODE
          - Priority: 1
            Type: LOWERCASE
```

### WA334 -- SizeConstraintStatement.Size must be non-negative

**Severity:** ERROR

The `Size` field in a `SizeConstraintStatement` must be a non-negative integer (0 or greater). Negative values are not valid.

**Triggers on:**

```yaml
    Statement:
      SizeConstraintStatement:
        FieldToMatch:
          Body: {}
        ComparisonOperator: GT
        Size: -1
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Use a non-negative value:

```yaml
        Size: 0
```

### WA335 -- JsonBody.MatchScope invalid

**Severity:** ERROR

The `MatchScope` field in a `JsonBody` `FieldToMatch` must be one of the valid values: `ALL`, `KEY`, `VALUE`.

**Triggers on:**

```yaml
        FieldToMatch:
          JsonBody:
            MatchScope: KEYS         # not valid
            InvalidFallbackBehavior: MATCH
```

**Fix:** Use a valid `MatchScope` value:

```yaml
            MatchScope: ALL
```

### WA336 -- JsonBody.InvalidFallbackBehavior invalid

**Severity:** ERROR

The `InvalidFallbackBehavior` field in a `JsonBody` `FieldToMatch` must be one of the valid values: `EVALUATE_AS_STRING`, `MATCH`, `NO_MATCH`.

**Triggers on:**

```yaml
        FieldToMatch:
          JsonBody:
            MatchScope: ALL
            InvalidFallbackBehavior: IGNORE    # not valid
```

**Fix:** Use a valid `InvalidFallbackBehavior` value:

```yaml
            InvalidFallbackBehavior: MATCH
```

---

## Action Parameters

### WA350 -- Action must have exactly one key

**Severity:** ERROR

Both `Action` and `OverrideAction` must contain exactly one key specifying the action type. Multiple keys or an empty dict are not valid.

**Triggers on:**

```yaml
    Action:
      Block: {}
      Count: {}       # two action types
```

**Fix:** Keep only one action type:

```yaml
    Action:
      Block: {}
```

### WA351 -- Unknown action type

**Severity:** ERROR

The action key is not a recognized AWS WAF action. Valid action types are: `Allow`, `Block`, `Captcha`, `Challenge`, `Count`.

**Triggers on:**

```yaml
    Action:
      Deny: {}
```

**Fix:** Use a valid action type:

```yaml
    Action:
      Block: {}
```

### WA352 -- OverrideAction on non-group statement

**Severity:** WARNING

`OverrideAction` is only meaningful with `ManagedRuleGroupStatement` or `RuleGroupReferenceStatement`. Using it with other statement types (e.g., `GeoMatchStatement`, `ByteMatchStatement`) is a likely misconfiguration -- use `Action` instead.

**Triggers on:**

```yaml
  - ref: override-on-custom
    Priority: 10
    OverrideAction:
      Count: {}
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: OverrideOnCustom
```

**Fix:** Use `Action` for non-group statements:

```yaml
    Action:
      Count: {}
```

### WA353 -- CustomResponse status code invalid

**Severity:** ERROR

The `CustomResponse.ResponseCode` in a `Block` action must be an integer between 200 and 599 inclusive.

**Triggers on:**

```yaml
    Action:
      Block:
        CustomResponse:
          ResponseCode: 999     # out of range
```

**Fix:** Use a valid HTTP status code:

```yaml
    Action:
      Block:
        CustomResponse:
          ResponseCode: 403
```

---

## VisibilityConfig

### WA400 -- VisibilityConfig missing required field

**Severity:** ERROR

`VisibilityConfig` must contain all three required fields: `SampledRequestsEnabled` (bool), `CloudWatchMetricsEnabled` (bool), and `MetricName` (str).

**Triggers on:**

```yaml
    VisibilityConfig:
      MetricName: MyRule
      # missing SampledRequestsEnabled and CloudWatchMetricsEnabled
```

**Fix:** Include all three fields:

```yaml
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: MyRule
```

### WA401 -- VisibilityConfig field wrong type

**Severity:** ERROR

A `VisibilityConfig` field has the wrong type. `SampledRequestsEnabled` and `CloudWatchMetricsEnabled` must be booleans; `MetricName` must be a string. Note that bare integers (e.g., `0`, `1`) are rejected for boolean fields.

**Triggers on:**

```yaml
    VisibilityConfig:
      SampledRequestsEnabled: 1        # must be true/false, not an integer
      CloudWatchMetricsEnabled: true
      MetricName: MyRule
```

**Fix:** Use boolean values:

```yaml
      SampledRequestsEnabled: true
```

### WA402 -- MetricName exceeds 128 characters

**Severity:** ERROR

The `MetricName` value in `VisibilityConfig` must not exceed 128 characters. AWS WAF enforces this limit for CloudWatch metric names.

**Triggers on:**

```yaml
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: ThisIsAnExtremelyLongMetricNameThatExceedsTheMaximumAllowedLengthOfOneHundredAndTwentyEightCharactersAndWillBeRejectedByTheAWSWAFAPI
```

**Fix:** Shorten the metric name to 128 characters or fewer.

---

## Cross-rule

### WA500 -- Duplicate MetricName across rules

**Severity:** ERROR

Two or more rules within the same phase have the same `MetricName` in their `VisibilityConfig`. AWS WAF requires metric names to be unique.

**Triggers on:**

```yaml
aws_waf_custom_rules:
  - ref: rule-a
    Priority: 10
    ...
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockBadTraffic
  - ref: rule-b
    Priority: 20
    ...
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockBadTraffic    # same as rule-a
```

**Fix:** Give each rule a unique `MetricName`.

### WA501 -- Duplicate MetricName across phases

**Severity:** ERROR

The same `MetricName` appears in rules across different AWS phases. AWS WAF requires `MetricName` to be unique across **all** rules in a Web ACL, not just within a single phase.

**Triggers on:**

```yaml
aws_waf_custom_rules:
  - ref: custom-block
    Priority: 10
    ...
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockTraffic

aws_waf_rate_rules:
  - ref: rate-limit
    Priority: 10
    ...
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockTraffic       # same metric, different phase
```

**Fix:** Use distinct `MetricName` values across all phases:

```yaml
      MetricName: CustomBlockTraffic    # in custom rules
      MetricName: RateLimitTraffic      # in rate rules
```

### WA520 -- Duplicate statement across rules in phase

**Severity:** WARNING

Two or more rules in the same phase have identical `Statement` dicts (after normalization). This usually indicates a copy-paste error where the statement was duplicated but the action or priority was changed without updating the condition.

**Triggers on:**

```yaml
aws_waf_custom_rules:
  - ref: block-china
    Priority: 10
    Action:
      Block: {}
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
    ...
  - ref: count-china
    Priority: 20
    Action:
      Count: {}
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]      # identical statement
    ...
```

**Fix:** Verify this is intentional. If not, update one of the statements to match its intended condition.

### WA326 -- IPSetReferenceStatement references IP Set not in lists section

**Severity:** INFO

An `IPSetReferenceStatement` references an IP Set (by ARN) whose name does not appear in the `lists` section of the rules file. If the IP Set is managed by octorules, it should be declared in the `lists` section for full lifecycle management (create, update, delete).

The name is extracted from the ARN: `arn:aws:wafv2:REGION:ACCOUNT:SCOPE/ipset/NAME/ID`.

**Triggers on:**

```yaml
lists:
  - name: allowed-ips
    kind: ip
    items: [...]

aws_waf_custom_rules:
  - ref: block-bad-ips
    Priority: 10
    Action:
      Block: {}
    Statement:
      IPSetReferenceStatement:
        ARN: arn:aws:wafv2:us-east-1:123456789012:regional/ipset/bad-ips/abc123
        # "bad-ips" is not in the lists section
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: BlockBadIPs
```

**Fix:** Add the IP Set to the `lists` section:

```yaml
lists:
  - name: bad-ips
    kind: ip
    items:
      - ip: "1.2.3.4/32"
```

> **Note:** This check only fires when a `lists` section exists with at least one entry. If you don't use octorules-managed IP Sets, this rule won't fire.

### WA340 -- Estimated total WCU exceeds Web ACL limit

**Severity:** WARNING

The estimated total Web ACL Capacity Units (WCU) across all AWS phases exceeds the default Web ACL limit of 1,500 WCU. Each statement type has a known base WCU cost, and compound statements (And, Or, Not, RateBasedStatement) add to the total recursively. Managed rule groups are estimated at 100 WCU each (actual cost varies).

**WCU cost table:**

| Statement | Base WCU |
|-----------|----------|
| ByteMatchStatement | 2 + (1 per TextTransformation) |
| RegexMatchStatement | 5 + (1 per TextTransformation) |
| RegexPatternSetReferenceStatement | 5 |
| GeoMatchStatement | 2 |
| IPSetReferenceStatement | 1 |
| SizeConstraintStatement | 2 + (1 per TextTransformation) |
| SqliMatchStatement | 15 + (1 per TextTransformation) |
| XssMatchStatement | 15 + (1 per TextTransformation) |
| LabelMatchStatement | 1 |
| ManagedRuleGroupStatement | ~100 (estimate) |
| RuleGroupReferenceStatement | 1 |
| RateBasedStatement | 2 + ScopeDownStatement cost |
| AndStatement | 1 + sum of nested costs |
| OrStatement | 1 + sum of nested costs |
| NotStatement | 1 + nested cost |

Each rule also adds 1 base WCU.

**Triggers on:** Web ACL with many managed rule groups or complex custom rules.

**Fix:** Reduce complexity by simplifying conditions, removing unused rules, or requesting a WCU limit increase from AWS Support.

> **Note:** The estimate is a lower bound. Actual WCU consumption may vary, especially for managed rule groups. Use the AWS WAF console to see the exact WCU for managed rule groups.

### WA341 -- GeoMatchStatement likely always true

**Severity:** WARNING

A `GeoMatchStatement` lists 200 or more country codes, covering nearly all countries. This condition will match virtually all requests and is likely unintentional.

**Triggers on:**

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["AF", "AL", "DZ", ...]  # 200+ codes
```

**Fix:** If you want to match all traffic, remove the `GeoMatchStatement` entirely and use the action directly. If you want to exclude specific countries, use a `NotStatement` wrapping a `GeoMatchStatement` with the excluded countries.

### WA342 -- Contradictory AND conditions (non-overlapping GeoMatch sets)

**Severity:** WARNING

An `AndStatement` contains two or more `GeoMatchStatement` conditions with non-overlapping `CountryCodes` sets. Since a request can only originate from one country, no request can match both conditions simultaneously, making the entire `AndStatement` unsatisfiable.

**Triggers on:**

```yaml
    Statement:
      AndStatement:
        Statements:
          - GeoMatchStatement:
              CountryCodes: ["US", "CA"]
          - GeoMatchStatement:
              CountryCodes: ["DE", "FR"]
```

**Fix:** If you want to match traffic from any of these countries, use an `OrStatement` instead:

```yaml
    Statement:
      OrStatement:
        Statements:
          - GeoMatchStatement:
              CountryCodes: ["US", "CA"]
          - GeoMatchStatement:
              CountryCodes: ["DE", "FR"]
```

Or combine the country codes into a single `GeoMatchStatement`:

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["US", "CA", "DE", "FR"]
```

### WA343 -- Always-false pattern (SizeConstraint size < 0 is impossible)

**Severity:** WARNING

A `SizeConstraintStatement` with `Size: 0` and `ComparisonOperator: LT` is always false because the size of a request component cannot be negative.

**Triggers on:**

```yaml
    Statement:
      SizeConstraintStatement:
        FieldToMatch:
          Body: {}
        ComparisonOperator: LT
        Size: 0
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Use `EQ` to match empty values, or `GT` to match non-empty values:

```yaml
        ComparisonOperator: EQ    # matches empty body
        Size: 0
```

---

## Best Practice

### WA600 -- Rule is disabled (enabled: false)

**Severity:** INFO

A rule has `enabled: false`, which means it will not be applied. This is an informational check to highlight disabled rules that may have been left behind after troubleshooting or a temporary change.

**Triggers on:**

```yaml
aws_waf_custom_rules:
  - ref: legacy-block
    enabled: false
    Priority: 10
    Action:
      Block: {}
    Statement:
      GeoMatchStatement:
        CountryCodes: ["CN"]
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: LegacyBlock
```

**Fix:** Remove the rule entirely if it is no longer needed, or set `enabled: true` (or remove the `enabled` key) to re-enable it.
