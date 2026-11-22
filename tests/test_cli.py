"""Unit tests for sysadmin telemetry CLI dispatcher."""

import pytest
from sysadmin_telemetry.cli import build_parser, main


def test_cli_parser_build():
    """Verify CLI parser builds and exposes subcommands."""
    parser = build_parser()
    assert parser.prog == "sysadmin-cli"
    actions = [a.dest for a in parser._actions]
    assert "command" in actions


def test_cli_help():
    """Verify --help flag exits with status code 0."""
    exit_code = main(["--help"])
    assert exit_code == 0


def test_cli_empty_args():
    """Verify empty args invocation returns 0 with help print."""
    exit_code = main([])
    assert exit_code == 0
