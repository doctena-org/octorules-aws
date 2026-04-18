"""AWS WAF linter -- registers all AWS-specific lint rules and plugins."""

from octorules.registration import idempotent_registration


@idempotent_registration
def register_aws_linter() -> None:
    """Register the AWS WAF lint plugin, rule definitions, and non-phase keys."""
    from octorules.linter.plugin import LintPlugin, register_linter
    from octorules.linter.rules.registry import register_rules

    from octorules_aws.linter._plugin import AWS_RULE_IDS, aws_lint
    from octorules_aws.linter._rules import AWS_RULE_METAS

    register_linter(LintPlugin(name="aws", lint_fn=aws_lint, rule_ids=AWS_RULE_IDS))
    register_rules(AWS_RULE_METAS)
