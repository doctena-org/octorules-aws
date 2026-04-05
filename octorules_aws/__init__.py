"""AWS WAF provider for octorules."""

from octorules.phases import register_api_fields, register_non_phase_key, register_phases

from octorules_aws._phases import AWS_PHASE_IDS, AWS_PHASE_NAMES, AWS_PHASES
from octorules_aws.provider import AwsWafProvider
from octorules_aws.validate import validate_rules

# Keep backward-compatible alias for internal use.
_AWS_PHASES = AWS_PHASES

register_phases(_AWS_PHASES)
register_api_fields("rule", {"OverrideAction"})
register_non_phase_key("custom_rulesets")
register_non_phase_key("aws_waf_settings")

from octorules_aws.linter import register_aws_linter  # noqa: E402

register_aws_linter()

# Register ACL settings extension.
from octorules_aws._acl_settings import register_acl_settings  # noqa: E402

register_acl_settings()

# Register audit IP extractor.
from octorules_aws.audit import register_aws_audit  # noqa: E402

register_aws_audit()

__all__ = ["AWS_PHASE_IDS", "AWS_PHASE_NAMES", "AwsWafProvider", "validate_rules"]
