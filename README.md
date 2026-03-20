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
| Lists (IP only) | Supported | IP Sets |
| Page Shield | Not supported | — |
| Zone discovery (`list_zones`) | Supported | Lists Web ACLs |
| Account-level scopes | Not supported | — |

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

AWS WAF Rule Groups map to octorules custom rulesets. Add a `custom_rulesets` section to your rules file:

```yaml
# rules/my-web-acl.yaml
custom_rulesets:
  - id: arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/my-group/abcd1234
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

## Lists (IP Sets)

AWS WAF IP Sets map to octorules lists. Add a `lists` section to your rules file:

```yaml
# rules/my-web-acl.yaml
lists:
  - name: blocked-ips
    kind: ip
    description: "Known bad IPs"
    items:
      - ip: "1.2.3.4/32"
      - ip: "10.0.0.0/8"
```

> **Note:** AWS WAF only supports IP lists (`kind: ip`). ASN, hostname, and redirect list kinds are not available.

## Linting

42 AWS-specific lint rules (WA prefix) covering structure, actions, statements, and cross-rule analysis:

| Prefix | Category | Rules |
|--------|----------|-------|
| WA001-WA005, WA010, WA020-WA022 | Structure & YAML | 9 |
| WA100-WA101 | Priority | 2 |
| WA200-WA201 | Action type | 2 |
| WA300-WA321 | Statement deep validation | 18 |
| WA350-WA353 | Action parameters | 4 |
| WA400-WA402 | VisibilityConfig | 3 |
| WA500-WA501, WA520 | Cross-rule | 3 |
| WA600 | Best practice | 1 |

```bash
octorules lint --config config.yaml
```

Lint rules are registered automatically when octorules-aws is installed. See [docs/lint.md](docs/lint.md) for the full rule reference with examples.

> **Note:** WA500 checks for duplicate MetricName within a single phase. WA501 checks across phases — AWS WAF requires MetricName to be unique across **all** rules in a Web ACL.

## Known limitations

- **Web ACL creation/deletion:** octorules-aws manages rules within existing Web ACLs and Rule Groups. Creating or deleting Web ACLs and Rule Groups must be done via the AWS console or CLI.
- **Concurrent updates:** Rule updates use AWS WAF optimistic locking (LockToken). Stale lock errors are retried automatically (up to 3 attempts). If the same Web ACL is updated by multiple writers targeting the **same phase** simultaneously, the last writer wins.

## Development

```bash
git clone git@github.com:doctena-org/octorules-aws.git
cd octorules-aws
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
