# Lint Rule Reference

`octorules lint` performs offline static analysis of your AWS WAF rules files. **98 rules** with the `WA` prefix cover structure, actions, statements, visibility config, priority, cross-rule analysis, and best practices.

These rules are registered automatically when `octorules-aws` is installed. They run alongside any core and other provider rules during `octorules lint`.

**Note:** Lint rules fire independently — multiple rules may report on the same input when they catch different concerns, providing richer signal for policy optimization.

### Suppressing rules

Add a `# octorules:disable=RULE` comment immediately before a rule to suppress a specific finding. Multiple rule IDs can be comma-separated.

```yaml
aws:
  waf_custom_rules:
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
aws:
  waf_custom_rules:
    # octorules:disable=WA020,WA313
    - ref: legacy-rule
      Priority: 10
      CustomField: something
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
| [WA006](#wa006--rule-missing-statement) | Rule missing 'Statement' | ERROR |
| [WA010](#wa010--invalid-ref-format) | Invalid ref format | ERROR |
| [WA020](#wa020--unknown-top-level-rule-field) | Unknown top-level rule field | WARNING |
| [WA021](#wa021--actionoverrideaction-must-be-dict) | Action/OverrideAction must be dict | ERROR |
| [WA022](#wa022--duplicate-ref-within-phase) | Duplicate ref within phase | ERROR |
| [WA023](#wa023--rule-entry-is-not-a-dict) | Rule entry is not a dict | ERROR |
| [WA024](#wa024--phase-value-is-not-a-list) | Phase value is not a list | ERROR |
| [WA025](#wa025--http-header-name-should-be-lowercase) | HTTP header name should be lowercase | INFO |
| [WA100](#wa100--priority-must-be-a-non-negative-integer) | Priority must be a non-negative integer | ERROR |
| [WA101](#wa101--duplicate-priority-across-rules) | Duplicate Priority across rules | ERROR |
| [WA102](#wa102--non-contiguous-rule-priorities) | Non-contiguous rule priorities | INFO |
| [WA154](#wa154--rulelabels-uses-reserved-namespace) | RuleLabels uses reserved aws:/awswaf: namespace | ERROR |
| [WA156](#wa156--managedrulegroupstatement-version-not-pinned) | ManagedRuleGroupStatement version not pinned | WARNING |
| [WA157](#wa157--excludedrules-must-be-a-list-of-dicts-with-name) | ExcludedRules must be a list of dicts with Name | ERROR |
| [WA158](#wa158--ip-set-exceeds-10000-address-limit) | IP set exceeds 10,000 address limit | WARNING |
| [WA159](#wa159--ruleactionoverrides-entry-missing-name-or-actiontouse) | RuleActionOverrides entry missing Name or ActionToUse | ERROR |
| [WA160](#wa160--ruleactionoverrides-actiontouse-has-invalid-action) | RuleActionOverrides ActionToUse has invalid action | ERROR |
| [WA161](#wa161--excludedrules--aws-directs-to-ruleactionoverrides-instead) | ExcludedRules — AWS directs to RuleActionOverrides instead | INFO |
| [WA162](#wa162--reservedbogon-ip-in-ip-set) | Reserved/bogon IP in IP set | WARNING |
| [WA163](#wa163--catch-all-cidr-in-ip-set) | Catch-all CIDR (0.0.0.0/0 or ::/0) in IP set | WARNING |
| [WA164](#wa164--overlapping-ipcidr-entries-in-ip-set) | Overlapping IP/CIDR entries in IP set | WARNING |
| [WA165](#wa165--regex-pattern-set-exceeds-10-pattern-limit) | Regex pattern set exceeds 10-pattern limit | ERROR |
| [WA168](#wa168--regex-pattern-set-entry-exceeds-200-characters) | Regex pattern-set entry exceeds 200 characters | ERROR |
| [WA166](#wa166--cidr-has-host-bits-set-in-ip-set) | CIDR has host bits set in IP set | WARNING |
| [WA167](#wa167--overlappingduplicate-cidr-across-rules-in-same-phase) | Overlapping/duplicate CIDR across rules in same phase | WARNING |
| [WA200](#wa200--invalid-action-type) | Invalid Action type | ERROR |
| [WA201](#wa201--invalid-overrideaction-type) | Invalid OverrideAction type | ERROR |
| [WA300](#wa300--statement-must-have-exactly-one-type) | Statement must have exactly one type | ERROR |
| [WA301](#wa301--unknown-statement-type) | Unknown statement type | WARNING |
| [WA302](#wa302--arn-format-mismatch) | ARN format mismatch | WARNING |
| [WA303](#wa303--ratebasedstatementlimit-invalid) | RateBasedStatement.Limit invalid | ERROR |
| [WA304](#wa304--ratebasedstatement-missing-aggregatekeytype) | RateBasedStatement missing AggregateKeyType | ERROR |
| [WA305](#wa305--invalid-aggregatekeytype) | Invalid AggregateKeyType | ERROR |
| [WA306](#wa306--ratebasedstatementlimit-exceeds-maximum) | RateBasedStatement.Limit exceeds maximum | ERROR |
| [WA307](#wa307--searchstring-exceeds-200-byte-limit) | SearchString exceeds 200-byte limit | ERROR |
| [WA308](#wa308--regexstring-exceeds-512-byte-limit) | RegexString exceeds 512-byte limit | ERROR |
| [WA309](#wa309--ratebasedstatement-without-scopedownstatement) | RateBasedStatement without ScopeDownStatement rate-limits all traffic | WARNING |
| [WA310](#wa310--andorstatement-must-have-2-10-nested-statements) | And/OrStatement must have 2–10 nested statements | ERROR |
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
| [WA322](#wa322--statement-entry-in-andorstatement-is-not-a-dict) | Statement entry in And/OrStatement is not a dict | ERROR |
| [WA323](#wa323--geomatchstatement-exceeds-50-country-codes) | GeoMatchStatement exceeds 50 country codes | ERROR |
| [WA324](#wa324--ratebasedstatementcustomkeys-exceeds-maximum-of-5) | RateBasedStatement.CustomKeys exceeds maximum of 5 | ERROR |
| [WA325](#wa325--fieldtomatch-headerscookies-matchpattern-exceeds-maximum-of-199-patterns) | FieldToMatch Headers/Cookies MatchPattern exceeds maximum of 199 patterns | ERROR |
| [WA328](#wa328--bytematchstatement-searchstring-is-empty) | ByteMatchStatement SearchString is empty | ERROR |
| [WA337](#wa337--invalid-custom-key-type-in-customkeys) | Invalid custom key type in CustomKeys | ERROR |
| [WA338](#wa338--invalid-oversizehandling-value) | Invalid OversizeHandling value | ERROR |
| [WA339](#wa339--invalid-fallbackbehavior-value) | Invalid FallbackBehavior value | ERROR |
| [WA330](#wa330--statement-nesting-exceeds-maximum-depth) | Statement nesting exceeds maximum depth | ERROR |
| [WA331](#wa331--texttransformations-exceeds-maximum-of-10-per-statement) | TextTransformations exceeds maximum of 10 per statement | ERROR |
| [WA332](#wa332--duplicate-texttransformation-priority) | Duplicate TextTransformation Priority | ERROR |
| [WA334](#wa334--sizeconstraintstatementssize-must-be-non-negative) | SizeConstraintStatement.Size must be non-negative | ERROR |
| [WA335](#wa335--jsonbodymatchscope-invalid) | JsonBody.MatchScope invalid | ERROR |
| [WA336](#wa336--jsonbodyinvalidfallbackbehavior-invalid) | JsonBody.InvalidFallbackBehavior invalid | ERROR |
| [WA350](#wa350--action-must-have-exactly-one-key) | Action must have exactly one key | ERROR |
| [WA351](#wa351--unknown-action-type) | Unknown action type | ERROR |
| [WA352](#wa352--overrideaction-on-non-group-statement) | OverrideAction on non-group statement | WARNING |
| [WA353](#wa353--customresponse-status-code-invalid) | CustomResponse status code invalid | ERROR |
| [WA354](#wa354--customresponse-body-exceeds-4096-bytes) | CustomResponse body exceeds 4,096 bytes | ERROR |
| [WA355](#wa355--customresponse-exceeds-10-custom-headers) | CustomResponse exceeds 10 custom headers | ERROR |
| [WA356](#wa356--customresponse-header-name-invalid) | CustomResponse header name invalid | ERROR |
| [WA357](#wa357--customresponsebodykey-is-empty) | CustomResponseBodyKey is empty | WARNING |
| [WA358](#wa358--customresponse-missing-responsecode) | CustomResponse missing 'ResponseCode' | ERROR |
| [WA400](#wa400--visibilityconfig-missing-required-field) | VisibilityConfig missing required field | ERROR |
| [WA401](#wa401--visibilityconfig-field-wrong-type) | VisibilityConfig field wrong type | ERROR |
| [WA402](#wa402--metricname-exceeds-128-characters) | MetricName exceeds 128 characters | ERROR |
| [WA500](#wa500--duplicate-metricname-across-rules) | Duplicate MetricName across rules | ERROR |
| [WA501](#wa501--duplicate-metricname-across-phases) | Duplicate MetricName across phases | ERROR |
| [WA520](#wa520--duplicate-statement-across-rules-in-phase) | Duplicate statement across rules in phase | WARNING |
| [WA326](#wa326--ipsetreferencestatement-references-ip-set-not-in-lists-section) | IPSetReferenceStatement references IP Set not in lists section | INFO |
| [WA327](#wa327--regexpatternsetreferencestatement-references-regex-pattern-set-not-in-lists-section) | RegexPatternSetReferenceStatement references Regex Pattern Set not in lists section | INFO |
| [WA340](#wa340--estimated-total-wcu-exceeds-web-acl-limit) | Estimated total WCU exceeds Web ACL limit | WARNING |
| [WA341](#wa341--geomatchstatement-likely-always-true) | GeoMatchStatement likely always true | WARNING |
| [WA342](#wa342--contradictory-and-conditions-non-overlapping-geomatch-sets) | Contradictory AND conditions (non-overlapping GeoMatch sets) | WARNING |
| [WA343](#wa343--always-false-pattern-sizeconstraint-size--0-is-impossible) | Always-false pattern (SizeConstraint size < 0 is impossible) | WARNING |
| [WA344](#wa344--overly-permissive-regex-pattern) | Overly-permissive regex pattern | WARNING |
| [WA345](#wa345--fully-anchored-literal-regex) | Fully-anchored literal regex | INFO |
| [WA346](#wa346--http-method-in-bytematchstatement-searchstring-should-be-uppercase) | HTTP method in ByteMatchStatement SearchString should be uppercase | WARNING |
| [WA347](#wa347--uripath-searchstring-should-start-with) | UriPath SearchString should start with / | WARNING |
| [WA348](#wa348--contradictory-bytematch-in-andstatement) | Contradictory ByteMatch in AndStatement | WARNING |
| [WA600](#wa600--rule-is-disabled-enabled-false) | Rule is disabled (enabled: false) | INFO |
| [WA601](#wa601--total-rule-count-above-100-octorules-guidance) | Total rule count above 100 (octorules guidance) | WARNING |
| [WA602](#wa602--count-action-on-managedrulegroup-logs-all-traffic) | Count action on ManagedRuleGroup logs all traffic | INFO |
| [WA603](#wa603--rule-likely-unreachable-after-always-true-terminating-rule) | Rule likely unreachable after always-true terminating rule | WARNING |

---

## Categories

| WA Range | Category | Rules |
|----------|----------|-------|
| WA001–WA003, WA010, WA020–WA024, WA154 | Structure | 10 |
| WA025 | Style | 1 |
| WA100–WA102 | Priority | 3 |
| WA004–WA005, WA200–WA201, WA350–WA357 | Action | 12 |
| WA400–WA402, WA500–WA501 | Visibility | 5 |
| WA156–WA157, WA159–WA161, WA300–WA325, WA328, WA330–WA332, WA334–WA339, WA341–WA348 | Statement | 49 |
| WA158, WA162–WA168, WA326–WA327, WA340, WA520, WA603 | Cross-rule | 13 |
| WA600–WA602 | Best practice | 3 |

---

## Structure & YAML

### WA001 -- Rule missing 'ref'

**Severity:** ERROR

Every rule must have a `ref` field that serves as the rule's unique identifier (maps to the AWS WAF rule `Name`).

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
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
aws:
  waf_custom_rules:
    - ref: block-china
      Priority: 10
```

### WA010 -- Invalid ref format

**Severity:** ERROR

The `ref` value must be 1-128 characters and contain only alphanumeric characters, underscores, and hyphens (`A-Z`, `a-z`, `0-9`, `_`, `-`). This matches the AWS WAF rule name constraints.

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
    - ref: "my rule with spaces!"
      Priority: 10
```

**Fix:** Use only allowed characters:

```yaml
aws:
  waf_custom_rules:
    - ref: my-rule-with-spaces
      Priority: 10
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
aws:
  waf_custom_rules:
    - ref: block-bad-ips
      Priority: 10
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
aws:
  waf_managed_rules:
    - ref: aws-common-rules
      Priority: 10
      OverrideAction:
        Count: {}
      Statement:
        ManagedRuleGroupStatement:
          VendorName: AWS
          Name: AWSManagedRulesCommonRuleSet
```

### WA006 -- Rule missing 'Statement'

**Severity:** ERROR

Every rule must have a `Statement` defining what traffic it matches — it is a required member of the WAFv2 `Rule` shape, and the API rejects rules without one.

**Triggers on:**

```yaml
  - ref: block-bad-ips
    Priority: 10
    Action:
      Block: {}
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: block-bad-ips
```

**Fix:** Add a `Statement`:

```yaml
    Statement:
      IPSetReferenceStatement:
        ARN: arn:aws:wafv2:us-east-1:123456789012:regional/ipset/bad-ips/abc123
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
aws:
  waf_custom_rules:
    - ref: block-china
      Priority: 10
    - ref: block-china      # duplicate
      Priority: 20
```

**Fix:** Give each rule a unique `ref`.

### WA023 -- Rule entry is not a dict

**Severity:** ERROR

A rule entry in a phase list is not a dict (e.g., a bare string or number). Each entry must be a YAML mapping.

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
    - not-a-dict
    - 42
```

**Fix:** Replace the entry with a valid rule mapping.

### WA024 -- Phase value is not a list

**Severity:** ERROR

A phase key has a non-list value (e.g., a string or dict instead of a YAML sequence). Each phase must contain a list of rules.

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
```

**Fix:** Replace the value with a YAML list of rules.

### WA025 -- HTTP header name should be lowercase

**Severity:** INFO

HTTP header names are case-insensitive by the RFC, but it is conventional to use lowercase. This rule flags HTTP header names that include uppercase letters in CustomResponse headers or in ByteMatchStatement SearchString when the field is a header.

**Triggers on:**

```yaml
  - ref: custom-response
    Priority: 10
    Action:
      Block:
        CustomResponse:
          ResponseHeaders:
            - Name: "X-Custom-Header"   # should be lowercase
              Value: "blocked"
    Statement:
      IPSetReferenceStatement:
        ARN: arn:...
    VisibilityConfig:
      SampledRequestsEnabled: true
      CloudWatchMetricsEnabled: true
      MetricName: CustomResp
```

**Fix:** Use lowercase header names:

```yaml
            - Name: "x-custom-header"
              Value: "blocked"
```

### WA154 -- RuleLabels uses reserved namespace

**Severity:** ERROR

A `RuleLabels` entry has a `Name` starting with `aws:` or `awswaf:`. These prefixes are reserved by AWS WAF for managed labels and cannot be used in custom rules.

**Fix:** Use a custom namespace prefix (e.g., `myapp:blocked`).

---

## Priority

### WA100 -- Priority must be a non-negative integer

**Severity:** ERROR

The `Priority` field must be a non-negative integer (0 or greater). Strings, floats, booleans, and negative values are rejected.

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
    - ref: bad-priority
      Priority: "high"
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
aws:
  waf_custom_rules:
    - ref: rule-a
      Priority: 10
    - ref: rule-b
      Priority: 10     # same as rule-a
```

**Fix:** Assign distinct priority values:

```yaml
aws:
  waf_custom_rules:
    - ref: rule-a
      Priority: 10
    - ref: rule-b
      Priority: 20
```

### WA102 -- Non-contiguous rule priorities

**Severity:** INFO

Rule priorities within a phase have gaps (e.g., 10, 20, 50 — gap between 20 and 50). Non-contiguous priorities often indicate accidentally deleted rules or incomplete rollouts.

**Fix:** Review whether the gap is intentional. Renumber if rules were removed.

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

The statement type key is not in the recognized set of AWS WAF statement types. This may indicate a typo or an unsupported statement type. Recognized types: `AndStatement`, `AsnMatchStatement`, `ByteMatchStatement`, `GeoMatchStatement`, `IPSetReferenceStatement`, `LabelMatchStatement`, `ManagedRuleGroupStatement`, `NotStatement`, `OrStatement`, `RateBasedStatement`, `RegexMatchStatement`, `RegexPatternSetReferenceStatement`, `RuleGroupReferenceStatement`, `SizeConstraintStatement`, `SqliMatchStatement`, `XssMatchStatement`.

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

The `Limit` field in a `RateBasedStatement` must be an integer >= 10. AWS WAF requires the rate limit to be at least 10 requests per evaluation window.

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 5               # below minimum of 10
        AggregateKeyType: IP
```

Also fires when `Limit` is entirely missing from `RateBasedStatement`, or when `EvaluationWindowSec` has an invalid value (must be one of 60, 120, 300, 600).

**Fix:** Set `Limit` to at least 10:

```yaml
        Limit: 10
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

### WA307 -- SearchString exceeds 200-byte limit

**Severity:** ERROR

The `SearchString` in a `ByteMatchStatement` must not exceed 200 bytes when encoded as UTF-8. AWS WAF rejects longer values at the API level.

**Triggers on:**

```yaml
    Statement:
      ByteMatchStatement:
        SearchString: "<very long string exceeding 200 bytes>"
        FieldToMatch:
          UriPath: {}
        TextTransformations:
          - Priority: 0
            Type: NONE
        PositionalConstraint: CONTAINS
```

**Fix:** Shorten the `SearchString` to fit within 200 bytes. For multi-byte characters (e.g., accented letters, emoji), note that the byte count may exceed the character count.

> **Note:** The limit is measured in bytes (UTF-8), not characters. A string of 200 ASCII characters is exactly at the limit, but 101 two-byte characters (202 bytes) exceeds it.

### WA308 -- RegexString exceeds 512-byte limit

**Severity:** ERROR

The `RegexString` in a `RegexMatchStatement` must not exceed 512 bytes when encoded as UTF-8 (the API model's `RegexPatternString` bound). Entries inside a regex pattern set have a different, tighter bound — 200 characters, checked by WA168.

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

### WA310 -- And/OrStatement must have 2–10 nested statements

**Severity:** ERROR

`AndStatement` and `OrStatement` require a `Statements` list with 2–10 entries. Fewer than 2 is pointless; more than 10 is rejected by the AWS WAF API.

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

### WA322 -- Statement entry in And/OrStatement is not a dict

**Severity:** ERROR

Triggers when an `AndStatement` or `OrStatement` contains a `Statements` item that is not a dict (e.g., a string, number, or null).

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
    - ref: bad-compound
      Priority: 1
      Action:
        Block: {}
      Statement:
        AndStatement:
          Statements:
            - ByteMatchStatement:
                SearchString: "test"
                FieldToMatch:
                  QueryString: {}
                PositionalConstraint: CONTAINS
                TextTransformations:
                  - Priority: 0
                    Type: NONE
            - "not a statement"       # triggers WA322
```

**Fix:** Ensure every item in `Statements` is a dict containing exactly one statement type key.

### WA323 -- GeoMatchStatement exceeds 50 country codes

**Severity:** ERROR

The `CountryCodes` list in a `GeoMatchStatement` must not exceed 50 entries. AWS WAF enforces this limit at the API level.

**Triggers on:**

```yaml
    Statement:
      GeoMatchStatement:
        CountryCodes: ["US", "DE", "FR", "GB", "JP", "CN", "RU", "BR", "IN", "AU", "CA", "MX", "KR", "IT", "ES", "NL", "SE", "NO", "DK", "FI", "PL", "CZ", "AT", "CH", "BE", "IE", "PT", "GR", "HU", "RO", "BG", "HR", "SK", "SI", "LT", "LV", "EE", "CY", "MT", "LU", "IS", "LI", "TR", "UA", "GE", "AM", "AZ", "KZ", "UZ", "TM", "TJ"]
```

**Fix:** Reduce the list to 50 or fewer country codes. If you need to match more countries, use an `OrStatement` with multiple `GeoMatchStatement` blocks.

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

### WA325 -- FieldToMatch Headers/Cookies MatchPattern exceeds maximum of 199 patterns

**Severity:** ERROR

The `MatchPattern` in a `Headers` or `Cookies` `FieldToMatch` must not exceed 199 entries in any of its inclusion/exclusion lists (`IncludedHeaders`, `ExcludedHeaders`, `IncludedCookies`, `ExcludedCookies`). AWS API Reference for `HeaderMatchPattern` and `CookieMatchPattern`: "Array Members: Minimum number of 1 item. Maximum number of 199 items."

**Triggers on:**

```yaml
        FieldToMatch:
          Headers:
            MatchPattern:
              IncludedHeaders: [h0, h1, "…", h199]    # 200 > 199
            MatchScope: ALL
            OversizeHandling: MATCH
```

**Fix:** Reduce the list to 199 or fewer patterns.

### WA328 -- ByteMatchStatement SearchString is empty

**Severity:** ERROR

Triggers when a `ByteMatchStatement` has an empty `SearchString`. An empty search pattern matches nothing and is almost certainly a configuration error.

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
    - ref: empty-search
      Priority: 1
      Action:
        Block: {}
      Statement:
        ByteMatchStatement:
          SearchString: ""         # empty — matches nothing
          FieldToMatch:
            QueryString: {}
          PositionalConstraint: CONTAINS
          TextTransformations:
            - Priority: 0
              Type: NONE
```

**Fix:** Provide a non-empty `SearchString` value.

### WA337 -- Invalid custom key type in CustomKeys

**Severity:** ERROR

A `CustomKeys` entry in a `RateBasedStatement` uses an unrecognized key type. Each entry must have exactly one key from the valid set: `ASN`, `Cookie`, `ForwardedIP`, `HTTPMethod`, `Header`, `IP`, `JA3Fingerprint`, `JA4Fingerprint`, `LabelNamespace`, `QueryArgument`, `QueryString`, `UriPath`.

**Triggers on:**

```yaml
    Statement:
      RateBasedStatement:
        Limit: 200
        AggregateKeyType: CUSTOM_KEYS
        CustomKeys:
          - InvalidType:        # not a valid custom key type
              Name: test
```

**Fix:** Use a valid custom key type:

```yaml
          - Header:
              Name: x-api-key
```

### WA338 -- Invalid OversizeHandling value

**Severity:** ERROR

The `OversizeHandling` field in a FieldToMatch component (`Body`, `JsonBody`, `Headers`, `Cookies`, `HeaderOrder`) must be one of: `CONTINUE`, `MATCH`, `NO_MATCH`. This controls how AWS WAF handles requests whose inspected component exceeds the size limit.

**Triggers on:**

```yaml
        FieldToMatch:
          Body:
            OversizeHandling: REJECT    # not a valid value
```

**Fix:** Use a valid `OversizeHandling` value:

```yaml
            OversizeHandling: CONTINUE
```

### WA339 -- Invalid FallbackBehavior value

**Severity:** ERROR

The `FallbackBehavior` field in `JA3Fingerprint`, `JA4Fingerprint`, `UriFragment` (inside FieldToMatch), or `ForwardedIPConfig` (inside RateBasedStatement) must be one of: `MATCH`, `NO_MATCH`. This controls the match result when the field cannot be evaluated.

**Triggers on:**

```yaml
        FieldToMatch:
          JA3Fingerprint:
            FallbackBehavior: EVALUATE_AS_STRING    # not valid here
```

**Fix:** Use a valid `FallbackBehavior` value:

```yaml
            FallbackBehavior: MATCH
```

### WA330 -- Statement nesting exceeds maximum depth

**Severity:** ERROR

Statement nesting (via `AndStatement`, `OrStatement`, `NotStatement`, `RateBasedStatement.ScopeDownStatement`) exceeds the maximum depth of 20 levels. Deeply nested statements are rejected by the AWS WAF API and indicate overly complex rule logic.

**Fix:** Flatten compound statements or split into separate rules.

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

### WA156 -- ManagedRuleGroupStatement version not pinned

**Severity:** WARNING

A `ManagedRuleGroupStatement` does not have a `Version` field. Without version pinning, AWS automatically updates the managed rule group, which can change security behavior without notice.

**Fix:** Add `Version` to pin to a specific release:

```yaml
    Statement:
      ManagedRuleGroupStatement:
        VendorName: AWS
        Name: AWSManagedRulesCommonRuleSet
        Version: "Version_1.0"
```

### WA157 -- ExcludedRules must be a list of dicts with Name

**Severity:** ERROR

The `ExcludedRules` field in a `ManagedRuleGroupStatement` must be a list of objects, each containing a `Name` string field identifying the managed rule to exclude.

**Triggers on:**

```yaml
    Statement:
      ManagedRuleGroupStatement:
        VendorName: AWS
        Name: AWSManagedRulesCommonRuleSet
        ExcludedRules: "SizeRestrictions_BODY"    # must be a list
```

Or:

```yaml
        ExcludedRules:
          - "SizeRestrictions_BODY"    # must be a dict with Name
```

Or:

```yaml
        ExcludedRules:
          - Priority: 1    # missing Name
```

**Fix:** Use the correct structure:

```yaml
        ExcludedRules:
          - Name: SizeRestrictions_BODY
          - Name: NoUserAgent_HEADER
```

### WA159 -- RuleActionOverrides entry missing Name or ActionToUse

**Severity:** ERROR

Each entry in a `ManagedRuleGroupStatement.RuleActionOverrides` list must be a dict containing both a `Name` (string) and an `ActionToUse` (dict) field. This rule fires when either field is missing, has the wrong type, or the entry itself is not a dict.

**Triggers on:**

```yaml
    Statement:
      ManagedRuleGroupStatement:
        VendorName: AWS
        Name: AWSManagedRulesCommonRuleSet
        RuleActionOverrides:
          - Name: SizeRestrictions_BODY
            # missing ActionToUse
```

**Fix:** Add both required fields:

```yaml
        RuleActionOverrides:
          - Name: SizeRestrictions_BODY
            ActionToUse:
              Count: {}
```

### WA160 -- RuleActionOverrides ActionToUse has invalid action

**Severity:** ERROR

The `ActionToUse` dict in a `RuleActionOverrides` entry must contain exactly one key from the valid set of AWS WAF actions: `Allow`, `Block`, `Captcha`, `Challenge`, `Count`.

**Triggers on:**

```yaml
        RuleActionOverrides:
          - Name: SizeRestrictions_BODY
            ActionToUse:
              Deny: {}    # not a valid action
```

Or:

```yaml
            ActionToUse:
              Block: {}
              Count: {}    # two actions
```

**Fix:** Use exactly one valid action:

```yaml
            ActionToUse:
              Count: {}
```

### WA161 -- ExcludedRules -- AWS directs to RuleActionOverrides instead

**Severity:** INFO

A `ManagedRuleGroupStatement` uses the deprecated `ExcludedRules` field without also providing `RuleActionOverrides`. AWS recommends migrating to `RuleActionOverrides`, which provides finer-grained control by specifying an explicit action per rule instead of blanket exclusion.

**Triggers on:**

```yaml
    Statement:
      ManagedRuleGroupStatement:
        VendorName: AWS
        Name: AWSManagedRulesCommonRuleSet
        ExcludedRules:
          - Name: SizeRestrictions_BODY
```

**Fix:** Migrate to `RuleActionOverrides` with an explicit action:

```yaml
    Statement:
      ManagedRuleGroupStatement:
        VendorName: AWS
        Name: AWSManagedRulesCommonRuleSet
        RuleActionOverrides:
          - Name: SizeRestrictions_BODY
            ActionToUse:
              Count: {}
```

> **Note:** This rule does not fire when both `ExcludedRules` and `RuleActionOverrides` are present, since the migration may be in progress.

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
aws:
  waf_custom_rules:
    - ref: rule-a
      Priority: 10
      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: BlockBadTraffic
    - ref: rule-b
      Priority: 20
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
aws:
  waf_custom_rules:
    - ref: custom-block
      Priority: 10
      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: BlockTraffic

  waf_rate_rules:
    - ref: rate-limit
      Priority: 10
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
aws:
  waf_custom_rules:
    - ref: block-china
      Priority: 10
      Action:
        Block: {}
      Statement:
        GeoMatchStatement:
          CountryCodes: ["CN"]
    - ref: count-china
      Priority: 20
      Action:
        Count: {}
      Statement:
        GeoMatchStatement:
          CountryCodes: ["CN"]      # identical statement
```

**Fix:** Verify this is intentional. If not, update one of the statements to match its intended condition.

### WA326 -- IPSetReferenceStatement references IP Set not in lists section

**Severity:** INFO

An `IPSetReferenceStatement` references an IP Set (by ARN) whose name does not appear in the `lists` section of the rules file. If the IP Set is managed by octorules, it should be declared in the `lists` section for full lifecycle management (create, update, delete).

The name is extracted from the ARN: `arn:aws:wafv2:REGION:ACCOUNT:SCOPE/ipset/NAME/ID`.

**Triggers on:**

```yaml
aws:
  lists:
    - name: allowed-ips
      kind: ip
      items: [...]

  waf_custom_rules:
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
aws:
  lists:
    - name: bad-ips
      kind: ip
      items:
        - ip: "1.2.3.4/32"
```

> **Note:** This check only fires when a `lists` section exists with at least one entry. If you don't use octorules-managed IP Sets, this rule won't fire.

### WA327 -- RegexPatternSetReferenceStatement references Regex Pattern Set not in lists section

**Severity:** INFO

A `RegexPatternSetReferenceStatement` references a Regex Pattern Set (by ARN) whose name does not appear in the `lists` section of the rules file with `kind: regex`. If the Regex Pattern Set is managed by octorules, it should be declared in the `lists` section for full lifecycle management (create, update, delete).

The name is extracted from the ARN: `arn:aws:wafv2:REGION:ACCOUNT:SCOPE/regexpatternset/NAME/ID`.

**Triggers on:**

```yaml
aws:
  lists:
    - name: allowed-patterns
      kind: regex
      items: [...]

  waf_custom_rules:
    - ref: block-bad-ua
      Priority: 10
      Action:
        Block: {}
      Statement:
        RegexPatternSetReferenceStatement:
          ARN: arn:aws:wafv2:us-east-1:123456789012:regional/regexpatternset/bad-ua-patterns/abc123
          # "bad-ua-patterns" is not in the lists section
          FieldToMatch:
            SingleHeader:
              Name: user-agent
          TextTransformations:
            - Priority: 0
              Type: NONE
      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: BlockBadUA
```

**Fix:** Add the Regex Pattern Set to the `lists` section:

```yaml
aws:
  lists:
    - name: bad-ua-patterns
      kind: regex
      items:
        - pattern: "BadBot.*"
        - pattern: "EvilCrawler/\\d+"
```

> **Note:** This check only fires when a `lists` section exists with at least one `kind: regex` entry. If you don't use octorules-managed Regex Pattern Sets, this rule won't fire.

### WA158 -- IP set exceeds 10,000 address limit

**Severity:** WARNING

A list in the `lists` section has more than 10,000 items. AWS WAF limits IP sets to 10,000 CIDR entries.

**Fix:** Split the list into multiple IP sets, or remove unused entries.

### WA162 -- Reserved/bogon IP in IP set

**Severity:** WARNING

Triggers when an IP set in the `lists` section contains addresses from reserved or bogon ranges (RFC 1918 private, loopback, link-local, CGNAT, documentation, multicast, etc.).

**Triggers on:**

```yaml
aws:
  lists:
    - name: blocked_ips
      kind: ip
      items:
        - ip: 10.0.0.0/8      # RFC 1918 private
        - ip: 127.0.0.1       # loopback
```

**Fix:** Use public IP addresses, or suppress the warning if intentionally blocking private ranges.

### WA163 -- Catch-all CIDR in IP set

**Severity:** WARNING

Triggers when an IP set contains `0.0.0.0/0` or `::/0`. Those CIDRs match every address, so blocking against them takes the entire internet down rather than a targeted set. The usual cause is a placeholder the author forgot to replace.

**Triggers on:**

```yaml
aws:
  lists:
    - name: blocklist
      kind: ip
      items:
        - ip: 0.0.0.0/0       # <-- blocks everything
        - ip: 192.168.1.0/24
```

**Fix:** Replace the catch-all entry with specific CIDRs, or remove it if the intent is to deny all traffic reaching the IPSetReferenceStatement (in which case the statement itself is superfluous — drop the rule).

### WA164 -- Overlapping IP/CIDR entries in IP set

**Severity:** WARNING

Triggers when two entries in the same IP set overlap — one CIDR contains the other. The narrower entry is redundant because the broader one already matches every address it would. Catch-all entries (`0.0.0.0/0`, `::/0`) are handled by WA163 and excluded here to avoid noise.

Uses a sweep-line algorithm (O(n log n)) so 1,000-entry IP sets lint in well under a second.

**Triggers on:**

```yaml
aws:
  lists:
    - name: blocked_ips
      kind: ip
      items:
        - ip: 10.0.0.0/8      # broader
        - ip: 10.1.0.0/16     # <-- redundant, already covered by 10.0.0.0/8
```

**Fix:** Remove the narrower CIDR (the broader one already matches it), or split the IPSet into multiple sets with distinct ranges if the entries came from different sources.

### WA165 -- Regex pattern set exceeds 10-pattern limit

**Severity:** ERROR

AWS WAFv2 caps regex pattern sets at **10 patterns per set** (per-region), and the limit is **not adjustable** through Service Quotas. Sets with more than 10 patterns will fail at apply time, so this is reported as ERROR rather than WARNING.

Reference: <https://docs.aws.amazon.com/waf/latest/developerguide/limits.html>

**Triggers on:**

```yaml
aws:
  lists:
    - name: blocked_paths
      kind: regex
      items:
        - "^/admin"
        - "^/wp-admin"
        - "^/phpmyadmin"
        # ... 8 more entries → exceeds 10-pattern cap
```

**Fix:** Split the patterns across multiple regex pattern sets (each used by its own rule), or combine them into a single more-permissive regex (e.g. `^/(admin|wp-admin|phpmyadmin|…)`).


### WA168 -- Regex pattern-set entry exceeds 200 characters

**Severity:** ERROR

Each pattern inside a regex pattern set (`kind: regex` list) is capped at 200 characters — AWS WAF quotas: "Maximum number of characters in each regex pattern | 200". An inline `RegexMatchStatement.RegexString` has a different bound (512, checked by WA308).

**Triggers on:**

```yaml
lists:
  - name: blocked-paths
    kind: regex
    items:
      - "<a pattern longer than 200 characters>"
```

**Fix:** Shorten the pattern, or split it across several entries.

### WA166 -- CIDR has host bits set in IP set

**Severity:** WARNING

An IPv4 or IPv6 CIDR in an IP Set has host bits set (i.e., bits after the prefix length that should be zero). For example, `10.0.0.1/24` should be `10.0.0.0/24`. Host bits waste space and suggest a misunderstanding of CIDR notation.

**Triggers on:**

```yaml
aws:
  lists:
    - name: allowed-ranges
      kind: ip
      items:
        - ip: "10.0.0.1/24"    # host bits set; should be 10.0.0.0/24
        - ip: "192.168.1.5/32" # OK (single host)
        - ip: "2001:db8::1/48" # host bits set; should be 2001:db8::/48
```

**Fix:** Use canonical CIDR notation with host bits cleared:

```yaml
      - ip: "10.0.0.0/24"
      - ip: "2001:db8::/48"
```

### WA167 -- Overlapping/duplicate CIDR across rules in same phase

**Severity:** WARNING

A higher-priority rule with a terminating action (Allow, Block, Captcha, Challenge) references an IP set whose CIDRs contain or equal CIDRs referenced by a lower-priority rule — the same set or a different one. The lower-priority rule never sees the overlapping traffic. Fires once per shadowed rule pair, on the shadowed rule's ref. Catch-all entries (`0.0.0.0/0`, `::/0`) are excluded (WA163 owns them). Detection is a single sweep over all referenced CIDRs (sorted broadest-first with an ancestor stack), so large rule suites stay fast.

**Triggers on:**

```yaml
aws:
  lists:
    - name: blocked-ips-1
      kind: ip
      items:
        - ip: "10.0.0.0/8"

    - name: blocked-ips-2
      kind: ip
      items:
        - ip: "10.1.0.0/16"    # overlaps with 10.0.0.0/8
        - ip: "10.1.0.0/16"    # duplicate entry within same set

  waf_custom_rules:
    - ref: block-bad-1
      Priority: 10
      Action:
        Block: {}
      Statement:
        IPSetReferenceStatement:
          ARN: arn:.../ipset/blocked-ips-1/...

    - ref: block-bad-2
      Priority: 20
      Action:
        Block: {}
      Statement:
        IPSetReferenceStatement:
          ARN: arn:.../ipset/blocked-ips-2/...  # overlaps with rule 1
```

**Fix:** Consolidate overlapping IP Sets into a single list, or remove duplicates within a list.

### WA340 -- Estimated total WCU exceeds Web ACL limit

**Severity:** WARNING

The estimated total Web ACL Capacity Units (WCU) across all AWS phases exceeds the default Web ACL limit of 1,500 WCU. Each statement type has a known base WCU cost, and compound statements (And, Or, Not, RateBasedStatement) add to the total recursively.

For AWS-vendored managed rule groups, the estimator uses AWS's published per-group WCU costs (e.g. `AWSManagedRulesCommonRuleSet` = 700, `AWSManagedRulesAmazonIpReputationList` = 25). Marketplace vendor groups and unrecognized AWS group names fall back to a generic 100 WCU estimate; you can override these explicitly via `octorules_aws.validate.set_managed_rule_group_wcu_overrides()`:

```python
from octorules_aws.validate import set_managed_rule_group_wcu_overrides
set_managed_rule_group_wcu_overrides({
    "Cloudflare/SomeGroup": 75,        # marketplace vendor
    "AWSManagedRulesCustomGroup": 50,  # name-only match (vendor-agnostic)
})
```

**WCU cost table:**

| Statement | Base WCU |
|-----------|----------|
| ByteMatchStatement | 2 (`EXACTLY`/`STARTS_WITH`/`ENDS_WITH`) or 10 (`CONTAINS`/`CONTAINS_WORD`) |
| RegexMatchStatement | 3 |
| RegexPatternSetReferenceStatement | 25 |
| GeoMatchStatement | 1 |
| IPSetReferenceStatement | 1 (+4 with forwarded-IP position `ANY`) |
| SizeConstraintStatement | 1 |
| SqliMatchStatement | 20 (`LOW` sensitivity, the default) or 30 (`HIGH`) |
| XssMatchStatement | 40 |
| LabelMatchStatement | 1 |
| AsnMatchStatement | 1 |
| ManagedRuleGroupStatement | per-group lookup (AWS-vendored) or 100 (default) |
| RuleGroupReferenceStatement | 1 |
| RateBasedStatement | 2 + 30 per custom aggregation key + ScopeDownStatement cost |
| AndStatement | 1 + sum of nested costs |
| OrStatement | 1 + sum of nested costs |
| NotStatement | 1 + nested cost |

Statements that inspect a request component additionally pay +10 WCU per
`TextTransformation`, +10 for the All-query-parameters component, and double
their base cost for the JSON-body component. Each rule also adds 1 base WCU.

**Triggers on:** Web ACL with many managed rule groups or complex custom rules.

**Fix:** Reduce complexity by simplifying conditions, removing unused rules, or requesting a WCU limit increase from AWS Support. If you have a custom capacity limit, set `wcu_limit` in the provider config:

```yaml
providers:
  aws:
    wcu_limit: 5000
```

> **Note:** The estimate is a lower bound. Actual WCU consumption may vary, especially for managed rule groups. Use the AWS WAF console to see the exact WCU for managed rule groups.

### WA341 -- GeoMatchStatement likely always true

**Severity:** WARNING

A `GeoMatchStatement` lists 200 or more country codes, covering nearly all countries. This condition will match virtually all requests and is likely unintentional.

> **Note:** The 200-code threshold is an octorules heuristic, not an AWS limit. AWS imposes no such cap; the value is chosen to approximate "essentially every country" (the ISO 3166 list has ~250 codes).

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

### WA344 -- Overly-permissive regex pattern

**Severity:** WARNING

A regex pattern is overly permissive and will match more traffic than intended. Patterns are evaluated against a set of known-permissive regexes (e.g., `..*` which matches any string, or patterns without anchors), as well as context-specific patterns for UriPath. This rule parallels CF548 from the Cloudflare provider.

**Triggers on:**

```yaml
  - ref: uri-filter
    Priority: 10
    Action:
      Block: {}
    Statement:
      RegexMatchStatement:
        RegexString: ".*"  # matches everything; probably unintended
        FieldToMatch:
          UriPath: {}
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Use a more specific regex that matches only the paths you intend to block:

```yaml
        RegexString: "^/admin(/.*)?$"  # specific to admin paths
```

### WA345 -- Fully-anchored literal regex

**Severity:** INFO

A regex pattern is fully anchored (starts with `^` and ends with `$`) and contains only literal characters (no regex metacharacters). Such patterns are better implemented as `ByteMatchStatement` with `EXACTLY` constraint, which is faster and less error-prone.

**Triggers on:**

```yaml
  - ref: exact-match
    Priority: 10
    Action:
      Block: {}
    Statement:
      RegexMatchStatement:
        RegexString: "^/api/admin$"  # fully anchored literal
        FieldToMatch:
          UriPath: {}
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Use `ByteMatchStatement` with `EXACTLY` instead:

```yaml
    Statement:
      ByteMatchStatement:
        SearchString: "/api/admin"
        FieldToMatch:
          UriPath: {}
        PositionalConstraint: EXACTLY
        TextTransformations:
          - Priority: 0
            Type: NONE
```

### WA346 -- HTTP method in ByteMatchStatement SearchString should be uppercase

**Severity:** WARNING

A `ByteMatchStatement` with `FieldToMatch: HttpMethod` has a `SearchString` containing HTTP method names in lowercase (get, post, put, delete, etc.) when they should be uppercase (GET, POST, PUT, DELETE). AWS WAF normalizes HTTP methods to uppercase, so lowercase patterns will not match.

**Triggers on:**

```yaml
  - ref: method-check
    Priority: 10
    Action:
      Block: {}
    Statement:
      ByteMatchStatement:
        SearchString: "post"  # should be "POST"
        FieldToMatch:
          HttpMethod: {}
        PositionalConstraint: EXACTLY
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Use uppercase method names:

```yaml
        SearchString: "POST"
```

### WA347 -- UriPath SearchString should start with /

**Severity:** WARNING

A `ByteMatchStatement` or `RegexMatchStatement` with `FieldToMatch: UriPath` has a `SearchString` that does not start with `/`. Per AWS WAF documentation, UriPath always begins with `/`, so patterns without a leading slash will never match.

**Triggers on:**

```yaml
  - ref: path-check
    Priority: 10
    Action:
      Block: {}
    Statement:
      ByteMatchStatement:
        SearchString: "admin"  # should start with /
        FieldToMatch:
          UriPath: {}
        PositionalConstraint: CONTAINS
        TextTransformations:
          - Priority: 0
            Type: NONE
```

**Fix:** Add a leading slash:

```yaml
        SearchString: "/admin"
```

### WA348 -- Contradictory ByteMatch in AndStatement

**Severity:** WARNING

An `AndStatement` contains two or more `ByteMatchStatement` entries on the same field, both using `EXACTLY` constraint, with different `SearchString` values and the same text transformations. Such a rule can never match (a field cannot be two different exact values at once).

**Triggers on:**

```yaml
  - ref: contradictory
    Priority: 10
    Action:
      Block: {}
    Statement:
      AndStatement:
        Statements:
          - ByteMatchStatement:
              SearchString: "admin"
              FieldToMatch:
                UriPath: {}
              PositionalConstraint: EXACTLY
              TextTransformations:
                - Priority: 0
                  Type: NONE
          - ByteMatchStatement:
              SearchString: "login"  # same field, different value, both EXACTLY
              FieldToMatch:
                UriPath: {}
              PositionalConstraint: EXACTLY
              TextTransformations:
                - Priority: 0
                  Type: NONE
```

**Fix:** Use `CONTAINS` or other match types to allow both patterns, or split the rule to evaluate different fields:

```yaml
aws:
  waf_custom_rules:
    - ref: allow-either-path
      Priority: 10
      Action:
        Block: {}
      Statement:
        OrStatement:  # either path
          Statements:
            - ByteMatchStatement:
                SearchString: "/admin"
                FieldToMatch:
                  UriPath: {}
                PositionalConstraint: EXACTLY
            - ByteMatchStatement:
                SearchString: "/login"
                FieldToMatch:
                  UriPath: {}
                PositionalConstraint: EXACTLY
```

---

## Best Practice

### WA600 -- Rule is disabled (enabled: false)

**Severity:** INFO

A rule has `enabled: false`, which means it will not be applied. This is an informational check to highlight disabled rules that may have been left behind after troubleshooting or a temporary change.

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
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

### WA601 -- Total rule count above 100 (octorules guidance)

**Severity:** WARNING

The total number of rules across all AWS WAF phases in this zone exceeds 100. This threshold is octorules guidance, not an AWS limit — AWS bounds a WAFv2 web ACL by WCU capacity (5,000 WCUs, estimated by WA340), never by rule count. A three-digit rule count is usually worth a review.

**Triggers on:** a zone whose combined custom rules across all phases total more than 100.

**Fix:** Review whether the zone needs this many rules; WA340's WCU estimate is the binding constraint.

### WA602 -- Count action on ManagedRuleGroup logs all traffic

**Severity:** INFO

A rule with `Action: Count` or `OverrideAction: Count` on a `ManagedRuleGroupStatement` without a `ScopeDownStatement` wrapper logs all traffic through the managed rule group without blocking anything. At the Web ACL level, managed rule groups use `OverrideAction` (not `Action`) to override the group's default behavior. This is usually unintentional — it generates noise in CloudWatch WAF logs and consumes WCU without providing protection.

**Fix:** Either change the action to `Block` for protection, or add a `ScopeDownStatement` to limit which requests are counted.

### WA603 -- Rule likely unreachable after always-true terminating rule

**Severity:** WARNING

Triggers when a rule is preceded by a lower-priority rule that likely matches all traffic (e.g., GeoMatchStatement with 200+ country codes) and has a terminating action (Block, Allow, Captcha, or Challenge). AWS WAF evaluates rules in priority order and stops on the first matching terminating action.

Count actions do not terminate — they log and continue to the next rule.

**Triggers on:**

```yaml
aws:
  waf_custom_rules:
    - ref: catch-all
      Priority: 0
      Action:
        Block: {}
      Statement:
        GeoMatchStatement:
          CountryCodes: [US, CA, GB, ...]  # 200+ countries
    - ref: specific-rule                    # unreachable
      Priority: 1
      Action:
        Block: {}
      Statement:
        ByteMatchStatement:
          SearchString: "admin"
          FieldToMatch:
            UriPath: {}
          PositionalConstraint: CONTAINS
          TextTransformations:
            - Priority: 0
              Type: NONE
```

**Fix:** Reorder rules so the catch-all rule has a higher priority number, or add a `ScopeDownStatement` to narrow its scope.

### WA354 -- CustomResponse body exceeds 4,096 bytes

**Severity:** ERROR

The `CustomResponse.ResponseBody` field exceeds the AWS WAF limit of 4,096 bytes (4 KB). Oversized bodies are rejected by the API.

**Fix:** Shorten the response body to fit within 4,096 bytes.

### WA355 -- CustomResponse exceeds 10 custom headers

**Severity:** ERROR

The `CustomResponse.ResponseHeaders` list has more than 10 entries, exceeding the AWS WAF limit.

**Fix:** Reduce the number of custom response headers to 10 or fewer.

### WA356 -- CustomResponse header name invalid

**Severity:** ERROR

A custom response header name contains characters not allowed by RFC 7230 (HTTP token syntax). Header names must only contain alphanumeric characters and `!#$%&'*+-.^_`|~`.

**Fix:** Rename the header to use only valid token characters.

### WA357 -- CustomResponseBodyKey is empty

**Severity:** WARNING

The `CustomResponseBodyKey` field in a `CustomResponse` is present but empty. This key references a named response body defined in the Web ACL's `CustomResponseBodies` map. An empty key cannot match any defined body.

**Fix:** Set the key to the name of a defined custom response body, or remove the field if no custom body is needed.

### WA358 -- CustomResponse missing 'ResponseCode'

**Severity:** ERROR

A `Block` action's `CustomResponse` must set `ResponseCode` — it is the one member the WAFv2 service model requires. A `CustomResponse` with only headers or a body key is rejected by the API.

**Fix:** Add `ResponseCode` (an integer in 200-599) to the `CustomResponse` block.
