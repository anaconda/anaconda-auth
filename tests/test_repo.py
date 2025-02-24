import pytest
from pytest_mock import MockerFixture

from .conftest import CLIInvoker

pytest.importorskip("conda")

from anaconda_auth._conda.repo_config import REPO_URL  # noqa: E402


def test_token_list_no_tokens(mocker: MockerFixture, invoke_cli: CLIInvoker) -> None:
    mock = mocker.patch(
        "anaconda_auth._conda.repo_config.read_binstar_tokens",
        return_value={},
    )
    result = invoke_cli(["token", "list"])

    mock.assert_called_once()

    assert result.exit_code == 1
    assert (
        "No repo tokens are installed. Run `anaconda token install`." in result.stdout
    )
    assert "Aborted." in result.stdout


def test_token_list_has_tokens(mocker: MockerFixture, invoke_cli: CLIInvoker) -> None:
    test_repo_token = "test-repo-token"
    mock = mocker.patch(
        "anaconda_auth._conda.repo_config.read_binstar_tokens",
        return_value={REPO_URL: test_repo_token},
    )
    result = invoke_cli(["token", "list"])

    mock.assert_called_once()

    assert result.exit_code == 0
    assert f"{REPO_URL} {test_repo_token}" in result.stdout
