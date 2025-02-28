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
