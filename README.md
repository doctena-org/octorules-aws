# octorules-aws

AWS WAF v2 provider for [octorules](https://github.com/doctena-org/octorules) — manages AWS WAF Web ACL rules, Rule Groups, and IP Sets as YAML.

## Installation

```bash
pip install octorules-aws
```

This installs octorules (core) and octorules-aws. The provider is auto-discovered — no `class:` needed in config.

## Configuration

```yaml
providers:
  aws:
    region: us-east-1
    waf_scope: REGIONAL
  rules:
    directory: ./rules

zones:
  my-web-acl:
    sources:
      - rules
```

Each zone name maps to an AWS WAF Web ACL name. The provider resolves Web ACL names to IDs at runtime.

### Authentication

AWS credentials are resolved via the standard
[boto3 credential chain](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html)
— no token is needed in the config file. Common options:

- **Environment variables**: `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
- **Shared credentials file**: `~/.aws/credentials`
- **IAM role** (EC2, ECS, Lambda): automatic

Required IAM permissions:

- `wafv2:GetWebACL`, `wafv2:UpdateWebACL` — for phase rule operations
- `wafv2:ListWebACLs` — for zone ID resolution and zone discovery
- `wafv2:GetRuleGroup`, `wafv2:UpdateRuleGroup`, `wafv2:ListRuleGroups` — for custom rulesets (Rule Groups)
- `wafv2:GetIPSet`, `wafv2:UpdateIPSet`, `wafv2:CreateIPSet`, `wafv2:DeleteIPSet`, `wafv2:ListIPSets` — for lists (IP Sets)

### Provider settings

All settings below go under the provider section (e.g. `providers.aws`).

| Key | Default | Description |
|-----|---------|-------------|
| `region` | `AWS_DEFAULT_REGION` or `us-east-1` | AWS region |
| `waf_scope` | `AWS_WAF_SCOPE` or `REGIONAL` | `REGIONAL` or `CLOUDFRONT` |
| `max_retries` | `2` | API retry count |
| `timeout` | `30` | API timeout in seconds |
| `wcu_limit` | `1500` | Web ACL WCU capacity for WA340 lint check. Override for accounts with custom limits (up to 5,000). |

Safety thresholds are configured under `safety:` (framework-owned, not forwarded to the provider):

| Key | Default | Description |
|-----|---------|-------------|
| `safety.delete_threshold` | `30.0` | Max % of rules that can be deleted |
| `safety.update_threshold` | `30.0` | Max % of rules that can be updated |
| `safety.min_existing` | `3` | Min rules before thresholds apply |

## Supported features

| Feature | Status | AWS concept |
|---------|--------|-------------|
| Phase rules (4 phases) | Supported | Web ACL rules |
| Custom rulesets | Supported | Rule Groups |
| Lists (IP) | Supported | IP Sets |
| Lists (regex) | Supported | Regex Pattern Sets |
| Web ACL settings | Supported | DefaultAction, ChallengeConfig, CaptchaConfig, TokenDomains, AssociationConfig, CustomResponseBodies |
| Page Shield | Not supported | — |
| Zone discovery (`list_zones`) | Supported | Lists Web ACLs |
| Account-level scopes | Not supported | — |
| Audit IP extraction (`octorules audit`) | Supported | IPSet reference resolution |

## Phase mapping

| octorules phase | AWS WAF concept |
|---|---|
| `aws_waf_custom_rules` | Custom rules (IP match, geo match, byte match, etc.) |
| `aws_waf_rate_rules` | Rate-based rules |
| `aws_waf_managed_rules` | Managed rule group references |
| `aws_waf_rule_group_rules` | Rule group references |

All phases require `action` to be specified explicitly (no default action).

> **Rule-level metadata:** All AWS WAF rules support the `octorules:` key for per-rule metadata — `ignored: true` to skip a rule during plan/sync, and `included`/`excluded` to restrict rules to specific providers. See [octorules core docs](https://github.com/doctena-org/octorules#rule-level-metadata) for syntax and examples.

## Custom rulesets (Rule Groups)

AWS WAF Rule Groups map to octorules custom rulesets. octorules manages the full
lifecycle: create, update rules, and delete.

### Managing an existing Rule Group

```yaml
# rules/my-web-acl.yaml
custom_rulesets:
  - id: abcd1234-5678-9012-3456-789012345678
    name: My Rule Group
    phase: aws_waf_custom
    rules:
      - ref: block-bad-ips
        action:
          Block: {}
        Statement:
          IPSetReferenceStatement:
            ARN: arn:aws:wafv2:us-east-1:123456789012:regional/ipset/blocked/efgh5678
        VisibilityConfig:
          SampledRequestsEnabled: true
          CloudWatchMetricsEnabled: true
          MetricName: BlockBadIPs
```

### Creating a new Rule Group

Omit the `id` field and add `capacity` to create a new Rule Group:

```yaml
custom_rulesets:
  - name: Block Bad Actors
    capacity: 100
    phase: aws_waf_custom
    rules:
      - ref: block-scanner
        action:
          Block: {}
        Statement:
          ByteMatchStatement:
            SearchString: "BadBot"
            FieldToMatch:
              SingleHeader:
                Name: user-agent
            PositionalConstraint: CONTAINS
            TextTransformations:
              - Priority: 0
                Type: LOWERCASE
        VisibilityConfig:
          SampledRequestsEnabled: true
          CloudWatchMetricsEnabled: true
          MetricName: BlockScanner
```

`capacity` is an AWS WAF concept — an immutable budget (1-5000) that limits rule
complexity within the Rule Group. It cannot be changed after creation. If you need
more capacity, delete and recreate the Rule Group with a higher value.

**How it works:**

- The `name` field is the identity key. Rule Groups are matched between YAML and AWS by name.
- The presence of a `custom_rulesets:` key means ALL Rule Groups are managed — Rule Groups in AWS not in YAML are planned for deletion.
- If the `custom_rulesets:` key is absent, Rule Groups are ignored entirely.
- `id` is optional: present for existing Rule Groups, absent for new ones.
- After creation, use `octorules dump` to export the assigned `id` back to YAML.

## Lists (IP Sets & Regex Pattern Sets)

AWS WAF IP Sets and Regex Pattern Sets map to octorules lists. Add a `lists` section to your rules file:

```yaml
# rules/my-web-acl.yaml
lists:
  - name: blocked-ips
    kind: ip
    description: "Known bad IPs"
    items:
      - ip: "1.2.3.4/32"
      - ip: "10.0.0.0/8"

  - name: bad-ua-patterns
    kind: regex
    description: "Bad user-agent patterns"
    items:
      - pattern: "BadBot.*"
      - pattern: "EvilCrawler/\\d+"
```

IP lists (`kind: ip`) map to AWS WAF IP Sets. Regex lists (`kind: regex`) map to AWS WAF Regex Pattern Sets and are referenced via `RegexPatternSetReferenceStatement`.

> **Note:** ASN, hostname, and redirect list kinds are not available for AWS WAF.

## Linting

75 AWS-specific lint rules (WA prefix) covering structure, actions, statements, and cross-rule analysis:

| Prefix | Category | Rules |
|--------|----------|-------|
| WA001-WA005, WA010, WA020-WA022, WA154 | Structure & YAML | 10 |
| WA100-WA102 | Priority | 3 |
| WA200-WA201 | Action type | 2 |
| WA156-WA161, WA300-WA343 | Statement deep validation | 39 |
| WA350-WA357 | Action parameters | 8 |
| WA400-WA402 | VisibilityConfig | 3 |
| WA158, WA326-WA327, WA340, WA500-WA501, WA520 | Cross-rule | 7 |
| WA600-WA602 | Best practice | 3 |

```bash
octorules lint --config config.yaml
```

Lint rules are registered automatically when octorules-aws is installed. See [docs/lint.md](docs/lint.md) for the full rule reference with examples.

> **Note:** WA500 checks for duplicate MetricName within a single phase. WA501 checks across phases — AWS WAF requires MetricName to be unique across **all** rules in a Web ACL.

## Known limitations

- **Web ACL creation/deletion:** octorules-aws manages rules and Rule Groups within existing Web ACLs. Creating or deleting Web ACLs must be done via the AWS console, CLI, or Terraform.
- **Concurrent updates:** Rule updates use AWS WAF optimistic locking (LockToken). Stale lock errors are retried automatically (up to 3 attempts with linear backoff). If the same Web ACL is updated by multiple writers targeting the **same phase** simultaneously, the last writer wins.
- **Rule Group capacity is immutable:** AWS WAF sets Rule Group capacity at creation time. To change capacity, delete and recreate the Rule Group with the new value.

## Development

```bash
git clone git@github.com:doctena-org/octorules-aws.git
cd octorules-aws
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
