from __future__ import annotations

import sys
from typing import Generator

import pytest
from pytest import MonkeyPatch
from pytest_mock import MockerFixture

from anaconda_auth.cli import app
from anaconda_auth.client import BaseClient

from .conftest import CLIInvoker


@pytest.fixture
def is_a_tty(mocker: MockerFixture) -> Generator[None, None, None]:
    mocked = mocker.patch("anaconda_auth.cli.sys")
    mocked.stdout.isatty.return_value = True
    yield


@pytest.fixture
def is_not_a_tty(mocker: MockerFixture) -> Generator[None, None, None]:
    mocked = mocker.patch("anaconda_auth.cli.sys")
    mocked.stdout.isatty.return_value = False
    yield


@pytest.mark.usefixtures("disable_dot_env", "is_a_tty")
@pytest.mark.parametrize("subcommand", ["auth", "cloud"])
def test_login_required_tty(
    monkeypatch: MonkeyPatch,
    mocker: MockerFixture,
    invoke_cli: CLIInvoker,
    subcommand: str,
) -> None:
    monkeypatch.delenv("ANACONDA_AUTH_API_KEY", raising=False)

    login = mocker.patch("anaconda_auth.cli.login")

    _ = invoke_cli([subcommand, "api-key"], input="n")
    login.assert_not_called()

    _ = invoke_cli([subcommand, "api-key"], input="y")
    login.assert_called_once()


@pytest.mark.usefixtures("disable_dot_env", "is_not_a_tty")
@pytest.mark.parametrize("subcommand", ["auth", "cloud"])
def test_login_error_handler_no_tty(
    monkeypatch: MonkeyPatch,
    mocker: MockerFixture,
    invoke_cli: CLIInvoker,
    subcommand: str,
) -> None:
    monkeypatch.delenv("ANACONDA_AUTH_API_KEY", raising=False)
    login = mocker.patch("anaconda_auth.cli.login")

    result = invoke_cli([subcommand, "api-key"])
    login.assert_not_called()

    assert "Login is required" in result.stdout


@pytest.mark.usefixtures("disable_dot_env")
@pytest.mark.parametrize("subcommand", ["auth", "cloud"])
def test_api_key_prefers_env_var(
    monkeypatch: MonkeyPatch, invoke_cli: CLIInvoker, subcommand: str
) -> None:
    monkeypatch.setenv("ANACONDA_AUTH_API_KEY", "foo")

    result = invoke_cli([subcommand, "api-key"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "foo"


@pytest.mark.usefixtures("disable_dot_env", "is_a_tty")
@pytest.mark.parametrize("subcommand", ["auth", "cloud"])
def test_http_error_login(
    monkeypatch: MonkeyPatch,
    invoke_cli: CLIInvoker,
    mocker: MockerFixture,
    subcommand: str,
) -> None:
    monkeypatch.setenv("ANACONDA_AUTH_API_KEY", "foo")
    login = mocker.patch("anaconda_auth.cli.login")

    result = invoke_cli([subcommand, "whoami"], input="y")
    login.assert_called_once()

    assert "is invalid" in result.stdout


@pytest.mark.usefixtures("is_a_tty")
@pytest.mark.parametrize("subcommand", ["auth", "cloud"])
def test_http_error_general(
    monkeypatch: MonkeyPatch,
    invoke_cli: CLIInvoker,
    mocker: MockerFixture,
    subcommand: str,
) -> None:
    @app.command("bad-request")
    def bad_request() -> None:
        client = BaseClient()
        res = client.get("api/docs/not-found")
        res.raise_for_status()

    result = invoke_cli([subcommand, "bad-request"])

    assert "404 Client Error" in result.stdout
    assert result.exit_code == 1


@pytest.mark.parametrize(
    "options",
    [
        ("-n", "someuser"),
        ("--name", "someuser"),
        ("-o", "someorg"),
        ("--org", "someorg"),
        ("--organization", "someorg"),
        ("--strength", "strong"),
        ("--strength", "weak"),
        ("--strong",),
        ("-w",),
        ("--weak",),
        ("--url", "https://some-server.com"),
        ("--max-age", "3600"),
        ("-s", "repo conda:download"),
        ("--scopes", "repo conda:download"),
        ("--out", "some-file.log"),
        ("-x",),
        ("--list-scopes",),
        ("-l",),
        ("--list",),
        ("-r", "token-1"),
        ("--remove", "token-1"),
        ("-c",),
        ("--create",),
        ("-i",),
        ("--info",),
        ("--current-info",),
    ],
)
def test_fallback_to_anaconda_client(
    options: tuple[str],
    invoke_cli: CLIInvoker,
    monkeypatch: MonkeyPatch,
    mocker: MockerFixture,
) -> None:
    """We fallback to anaconda-client for token management if any of its options are passed."""
    binstar_main = mocker.patch("binstar_client.scripts.cli.main")

    # Construct the CLI arguments
    args = ["auth", *options]

    # We need to override sys.argv since these get set by pytest
    monkeypatch.setattr(sys, "argv", ["some-anaconda-bin", *args])

    # Run the equivalent of `anaconda auth <options...>`
    result = invoke_cli(args)
    assert result.exit_code == 0

    # Calls are delegated to anaconda-client
    binstar_main.assert_called_once()
    binstar_main.assert_called_once_with(args, allow_plugin_main=False)
