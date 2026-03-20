from __future__ import annotations

import sys
from typing import Generator

import pytest
from pytest import MonkeyPatch
from pytest_mock import MockerFixture

from anaconda_auth.cli import app
from anaconda_auth.client import BaseClient
from tests.conftest import CLIInvoker


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
    monkeypatch: MonkeyPatch, invoke_cli: CLIInvoker, subcommand: str, valid_api_key
) -> None:
    api_key = valid_api_key.api_key
    monkeypatch.setenv("ANACONDA_AUTH_API_KEY", api_key)

    result = invoke_cli([subcommand, "api-key"])
    assert result.exit_code == 0
    assert result.stdout.strip() == api_key


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


def test_post_login_setup_called_after_login(
    mocker: MockerFixture,
) -> None:
    from anaconda_auth.token import TokenNotFoundError

    mocker.patch("anaconda_auth.cli.login")
    mocker.patch(
        "anaconda_auth.cli.TokenInfo.load",
        side_effect=TokenNotFoundError,
    )
    mock_setup = mocker.patch("anaconda_auth.cli._post_login_setup")

    from anaconda_auth.cli import auth_login

    try:
        auth_login(force=False, ssl_verify=None, at=None)
    except SystemExit:
        pass

    mock_setup.assert_called_once()


@pytest.mark.parametrize("ssl_verify", [None, True, False])
def test_post_login_setup_called_after_login_with_ssl_verify(
    ssl_verify: bool | None,
    mocker: MockerFixture,
) -> None:
    from anaconda_auth.token import TokenNotFoundError

    mocker.patch("anaconda_auth.cli.login")
    mocker.patch(
        "anaconda_auth.cli.TokenInfo.load",
        side_effect=TokenNotFoundError,
    )
    import anaconda_auth.cli

    mock_setup = mocker.spy(anaconda_auth.cli, "_post_login_setup")
    mocker.patch("shutil.which", return_value="/usr/bin/conda")
    mock_fetch = mocker.patch("anaconda_auth.cli.fetch_org_features", return_value=None)

    from anaconda_auth.cli import auth_login

    try:
        auth_login(force=False, ssl_verify=ssl_verify)
    except SystemExit:
        pass

    mock_setup.assert_called_once()
    assert mock_setup.call_args.kwargs == {"ssl_verify": ssl_verify}
    assert mock_fetch.call_args.kwargs == {"ssl_verify": ssl_verify}


def test_post_login_setup_skips_when_conda_not_available(
    mocker: MockerFixture,
) -> None:
    mocker.patch("shutil.which", return_value=None)
    mock_fetch = mocker.patch("anaconda_auth.cli.fetch_org_features")

    from anaconda_auth.cli import _post_login_setup

    _post_login_setup()
    mock_fetch.assert_not_called()


def test_post_login_setup_skips_when_fetch_fails(
    mocker: MockerFixture,
) -> None:
    mocker.patch("shutil.which", return_value="/usr/bin/conda")
    mocker.patch("anaconda_auth.cli.fetch_org_features", return_value=None)
    mock_installed = mocker.patch(
        "anaconda_auth._conda.env_logger_config.is_env_manager_installed"
    )

    from anaconda_auth.cli import _post_login_setup

    _post_login_setup()
    mock_installed.assert_not_called()


def test_post_login_setup_skips_when_no_env_orgs(
    mocker: MockerFixture,
) -> None:
    mocker.patch("shutil.which", return_value="/usr/bin/conda")
    mocker.patch(
        "anaconda_auth.cli.fetch_org_features",
        return_value=[{"org": "my-org", "features": ["community"]}],
    )
    mock_installed = mocker.patch(
        "anaconda_auth._conda.env_logger_config.is_env_manager_installed"
    )

    from anaconda_auth.cli import _post_login_setup

    _post_login_setup()
    mock_installed.assert_not_called()


def test_post_login_setup_installs_and_registers_single_org(
    mocker: MockerFixture,
) -> None:
    mocker.patch("shutil.which", return_value="/usr/bin/conda")
    mocker.patch(
        "anaconda_auth.cli.fetch_org_features",
        return_value=[{"org": "my-org", "features": ["environments"]}],
    )
    mocker.patch(
        "anaconda_auth._conda.env_logger_config.is_env_manager_installed",
        return_value=False,
    )
    mocker.patch("rich.prompt.Confirm.ask", return_value=True)
    mock_install = mocker.patch(
        "anaconda_auth._conda.env_logger_config.install_env_manager",
        return_value=(True, ""),
    )
    mock_register = mocker.patch(
        "anaconda_auth._conda.env_logger_config.register_org",
        return_value=True,
    )

    from anaconda_auth.cli import _post_login_setup

    _post_login_setup()
    mock_install.assert_called_once()
    mock_register.assert_called_once()


def test_post_login_setup_skips_install_when_already_installed(
    mocker: MockerFixture,
) -> None:
    mocker.patch("shutil.which", return_value="/usr/bin/conda")
    mocker.patch(
        "anaconda_auth.cli.fetch_org_features",
        return_value=[{"org": "my-org", "features": ["environments"]}],
    )
    mocker.patch(
        "anaconda_auth._conda.env_logger_config.is_env_manager_installed",
        return_value=True,
    )
    mock_install = mocker.patch(
        "anaconda_auth._conda.env_logger_config.install_env_manager",
    )
    mock_register = mocker.patch(
        "anaconda_auth._conda.env_logger_config.register_org",
        return_value=True,
    )

    from anaconda_auth.cli import _post_login_setup

    _post_login_setup()
    mock_install.assert_not_called()
    mock_register.assert_called_once()


def test_post_login_setup_aborts_when_user_declines_install(
    mocker: MockerFixture,
) -> None:
    mocker.patch("shutil.which", return_value="/usr/bin/conda")
    mocker.patch(
        "anaconda_auth.cli.fetch_org_features",
        return_value=[{"org": "my-org", "features": ["environments"]}],
    )
    mocker.patch(
        "anaconda_auth._conda.env_logger_config.is_env_manager_installed",
        return_value=False,
    )
    mocker.patch("rich.prompt.Confirm.ask", return_value=False)
    mock_register = mocker.patch(
        "anaconda_auth._conda.env_logger_config.register_org",
    )

    from anaconda_auth.cli import _post_login_setup

    _post_login_setup()
    mock_register.assert_not_called()


def test_post_login_setup_shows_warning_when_register_fails(
    mocker: MockerFixture,
) -> None:
    mocker.patch("shutil.which", return_value="/usr/bin/conda")
    mocker.patch(
        "anaconda_auth.cli.fetch_org_features",
        return_value=[{"org": "my-org", "features": ["environments"]}],
    )
    mocker.patch(
        "anaconda_auth._conda.env_logger_config.is_env_manager_installed",
        return_value=True,
    )
    mocker.patch(
        "anaconda_auth._conda.env_logger_config.register_org",
        return_value=False,
    )
    mock_print = mocker.patch("anaconda_auth.cli.console.print")

    from anaconda_auth.cli import _post_login_setup

    _post_login_setup()

    # Verify the warning message includes the retry command
    warning_call = mock_print.call_args_list[-1]
    message = warning_call[0][0]
    assert "conda env-log register" in message
