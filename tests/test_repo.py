from datetime import datetime
from uuid import uuid4

import pytest
from pytest_mock import MockerFixture

from .conftest import CLIInvoker

pytest.importorskip("conda")

from anaconda_auth._conda.repo_config import REPO_URL  # noqa: E402
from anaconda_auth.repo import RepoAPIClient  # noqa: E402
from anaconda_auth.repo import TokenInfoResponse  # noqa: E402


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
    assert "Anaconda Repository Tokens" in result.stdout
    assert REPO_URL in result.stdout
    assert test_repo_token in result.stdout


@pytest.fixture(autouse=True)
def mock_do_auth_flow(mocker: MockerFixture) -> None:
    mocker.patch(
        "anaconda_auth.repo._do_auth_flow",
        return_value="test-access-token",
    )


def test_get_repo_token_info_no_token(mocker: MockerFixture) -> None:
    # TODO: This is just a test of the mock ...
    mocker.patch(
        "anaconda_auth.repo.RepoAPIClient.get_repo_token_info",
        return_value=None,
    )

    client = RepoAPIClient()
    token_info = client.get_repo_token_info(org_name="test-org-name")
    assert token_info is None


def test_get_repo_token_info_has_token(mocker: MockerFixture, requests_mock) -> None:
    org_name = "test-org-name"
    expected_token_info = TokenInfoResponse(
        id=uuid4(), expires_at=datetime(year=2025, month=1, day=1)
    )

    requests_mock.get(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        json=expected_token_info.model_dump(mode="json"),
    )

    client = RepoAPIClient()
    token_info = client.get_repo_token_info(org_name="test-org-name")
    assert token_info == expected_token_info
