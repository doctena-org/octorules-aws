"""End-to-end tests for the 'octorules lint' CLI command with the AWS provider."""

from pathlib import Path

import pytest
from octorules.cli import build_parser, cmd_lint, main
from octorules.config import Config

# Importing the provider module triggers register_aws_linter() at module
# load time, which cmd_lint depends on.
import octorules_aws  # noqa: F401


@pytest.fixture
def lint_config(tmp_path):
    """Minimal config + rules files exercising AWS-specific lint paths."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    # Clean IP set — public CIDRs only.
    (rules_dir / "clean-acl.yaml").write_text(
        "lists:\n"
        "  - name: allowed-ips\n"
        "    kind: ip\n"
        "    items:\n"
        "      - 1.2.3.0/24\n"
        "      - 8.8.8.0/24\n"
    )

    # Bad IP set — triggers WA162 (reserved) + WA163 (catch-all) + WA164 (overlap).
    (rules_dir / "bad-acl.yaml").write_text(
        "lists:\n"
        "  - name: messy-ips\n"
        "    kind: ip\n"
        "    items:\n"
        "      - 10.0.0.0/8\n"  # WA162: RFC 1918
        "      - 0.0.0.0/0\n"  # WA163: catch-all
        "      - 172.16.0.0/12\n"  # WA162
        "      - 172.20.0.0/16\n"  # WA162 + WA164 (overlaps 172.16.0.0/12)
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  aws:\n"
        "    region: us-east-1\n"
        "    scope: REGIONAL\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  clean-acl:\n"
        "    sources:\n"
        "      - rules\n"
        "  bad-acl:\n"
        "    sources:\n"
        "      - rules\n"
    )
    return Config.from_file(config_file)


class TestBuildParser:
    def test_lint_subcommand_exists(self):
        parser = build_parser()
        args = parser.parse_args(["lint"])
        assert args.command == "lint"

    def test_lint_rule_filter_accepts_wa_codes(self):
        parser = build_parser()
        args = parser.parse_args(["lint", "--rule", "WA162", "--rule", "WA163", "--rule", "WA164"])
        assert args.lint_rules == ["WA162", "WA163", "WA164"]


class TestCmdLint:
    def test_clean_rules_exit_0(self, lint_config):
        rc = cmd_lint(lint_config, ["clean-acl"])
        assert rc == 0

    def test_bad_rules_surface_all_three_ipset_rules(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-acl"])
        captured = capsys.readouterr()
        assert "WA162" in captured.out, "reserved-IP rule should fire"
        assert "WA163" in captured.out, "catch-all rule should fire"
        assert "WA164" in captured.out, "IPSet-overlap rule should fire"

    def test_wa163_catch_all_specific(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-acl"], lint_rules=["WA163"])
        captured = capsys.readouterr()
        assert "WA163" in captured.out
        assert "0.0.0.0/0" in captured.out

    def test_wa164_overlap_specific(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-acl"], lint_rules=["WA164"])
        captured = capsys.readouterr()
        assert "WA164" in captured.out
        # The narrower (172.20.0.0/16) should be flagged against the broader.
        assert "172.20.0.0/16" in captured.out

    def test_json_format(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-acl"], lint_format="json")
        captured = capsys.readouterr()
        assert '"rule_id"' in captured.out

    def test_sarif_format(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad-acl"], lint_format="sarif")
        captured = capsys.readouterr()
        assert '"version": "2.1.0"' in captured.out

    def test_output_file(self, lint_config, tmp_path):
        out_file = str(tmp_path / "lint-report.txt")
        cmd_lint(lint_config, ["bad-acl"], output_file=out_file)
        assert Path(out_file).exists()
        assert "WA" in Path(out_file).read_text()


class TestMainLintCommand:
    def test_main_lint_exits_zero_on_clean(self, lint_config, tmp_path):
        config_file = tmp_path / "config.yaml"
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(config_file), "lint", "--zone", "clean-acl"])
        assert exc_info.value.code == 0
