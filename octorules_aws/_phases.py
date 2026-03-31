"""AWS WAF phase definitions (shared between __init__ and provider)."""

from octorules.phases import Phase

AWS_PHASES = [
    Phase("aws_waf_custom_rules", "aws_waf_custom", None, zone_level=True, account_level=False),
    Phase("aws_waf_rate_rules", "aws_waf_rate", None, zone_level=True, account_level=False),
    Phase("aws_waf_managed_rules", "aws_waf_managed", None, zone_level=True, account_level=False),
    Phase(
        "aws_waf_rule_group_rules",
        "aws_waf_rule_group",
        None,
        zone_level=True,
        account_level=False,
    ),
]

AWS_PHASE_NAMES: frozenset[str] = frozenset(p.friendly_name for p in AWS_PHASES)
AWS_PHASE_IDS: frozenset[str] = frozenset(p.provider_id for p in AWS_PHASES)
