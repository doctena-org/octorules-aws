"""AWS WAF provider for octorules."""

from octorules.phases import Phase, register_api_fields, register_non_phase_key, register_phases

from octorules_aws.provider import AwsWafProvider
from octorules_aws.validate import validate_rules

_AWS_PHASES = [
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

register_phases(_AWS_PHASES)
register_api_fields("rule", {"OverrideAction"})
register_non_phase_key("custom_rulesets")

from octorules_aws.linter import register_aws_linter  # noqa: E402

register_aws_linter()

__all__ = ["AwsWafProvider", "validate_rules"]
