"""AWS WAF linter -- registers all AWS-specific lint rules and plugins."""

import threading

_registered = False
_register_lock = threading.Lock()


def register_aws_linter() -> None:
    """Register the AWS WAF lint plugin, rule definitions, and non-phase keys.

    Safe to call multiple times -- subsequent calls are no-ops.
    Thread-safe: uses a lock to protect the check-and-set.
    """
    global _registered
    if _registered:
        return

    with _register_lock:
        # Double-check after acquiring the lock
        if _registered:
            return

        from octorules.linter.plugin import LintPlugin, register_linter
        from octorules.linter.rules.registry import register_rules

        from octorules_aws.linter._plugin import AWS_RULE_IDS, aws_lint
        from octorules_aws.linter._rules import AWS_RULE_METAS

        register_linter(LintPlugin(name="aws", lint_fn=aws_lint, rule_ids=AWS_RULE_IDS))
        register_rules(AWS_RULE_METAS)

        _registered = True
