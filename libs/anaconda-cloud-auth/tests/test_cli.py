import pytest
from pytest import MonkeyPatch
from pytest_mock import MockerFixture
from typer.testing import CliRunner

from anaconda_cloud_auth.cli import app


@pytest.mark.usefixtures("disable_dot_env")
def test_api_key_not_logged_in(monkeypatch: MonkeyPatch, mocker: MockerFixture) -> None:
    monkeypatch.delenv("ANACONDA_CLOUD_API_KEY", raising=False)

    login = mocker.patch("anaconda_cloud_auth.cli.login")

    runner = CliRunner()
    _ = runner.invoke(app, ["api-key"])

    login.assert_called_once()


@pytest.mark.usefixtures("disable_dot_env")
def test_api_key_prefers_env_var(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ANACONDA_CLOUD_API_KEY", "foo")

    runner = CliRunner()
    result = runner.invoke(app, ["api-key"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "foo"
