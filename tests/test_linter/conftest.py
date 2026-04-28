"""Shared fixtures for the AWS linter test suite.

Assertion helpers (``assert_lint``, ``assert_no_lint``) live in
``octorules.testing.lint``; this conftest only ensures AWS rules are
registered before tests run.
"""

from octorules_aws.linter import register_aws_linter

# Ensure AWS linter rules are registered before any test in this directory runs.
register_aws_linter()
