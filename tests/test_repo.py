from datetime import datetime
from uuid import uuid4

import pytest
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestMocker

from .conftest import CLIInvoker

pytest.importorskip("conda")

# ruff: noqa: E402
from anaconda_auth._conda.repo_config import REPO_URL
from anaconda_auth.repo import OrganizationData
from anaconda_auth.repo import RepoAPIClient
from anaconda_auth.repo import TokenCreateResponse
from anaconda_auth.repo import TokenInfoResponse
from anaconda_auth.token import TokenInfo


@pytest.fixture(autouse=True)
def token_info():
    token_info = TokenInfo.load(create=True)
    token_info.save()
    return token_info


@pytest.fixture(autouse=True)
def mock_do_auth_flow(mocker: MockerFixture) -> None:
    mocker.patch(
        "anaconda_auth.repo._do_auth_flow",
        return_value="test-access-token",
    )


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


def test_token_install_does_not_exist_yet(
    requests_mock: RequestMocker, invoke_cli: CLIInvoker
) -> None:
    org_name = "test-org-name"
    test_token = "test-token"

    requests_mock.get(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        status_code=404,
    )
    requests_mock.put(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        json={"token": test_token, "expires_at": "2025-01-01T00:00:00"},
    )
    requests_mock.head(
        f"https://repo.anaconda.cloud/t/{test_token}/repo/main/noarch/repodata.json",
        status_code=200,
    )

    result = invoke_cli(["token", "install", "--org", org_name])
    assert result.exit_code == 0

    token_info = TokenInfo.load()
    repo_token = token_info.get_repo_token(org_name=org_name)
    assert repo_token == test_token


def test_get_repo_token_info_no_token(requests_mock: RequestMocker) -> None:
    org_name = "test-org-name"

    requests_mock.get(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        status_code=404,
    )

    client = RepoAPIClient()
    token_info = client.get_repo_token_info(org_name=org_name)
    assert token_info is None


def test_get_repo_token_info_has_token(requests_mock: RequestMocker) -> None:
    org_name = "test-org-name"
    expected_token_info = TokenInfoResponse(
        id=uuid4(), expires_at=datetime(year=2025, month=1, day=1)
    )

    requests_mock.get(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        json=expected_token_info.model_dump(mode="json"),
    )

    client = RepoAPIClient()
    token_info = client.get_repo_token_info(org_name=org_name)
    assert token_info == expected_token_info


def test_create_repo_token_info_has_token(requests_mock: RequestMocker) -> None:
    org_name = "test-org-name"
    expected_response_data = {
        "token": "test-token",
        "expires_at": "2025-01-01T00:00:00",
    }

    requests_mock.put(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        json=expected_response_data,
    )

    client = RepoAPIClient()
    token_info = client.create_repo_token(org_name=org_name)
    assert token_info == TokenCreateResponse(**expected_response_data)


def test_get_organizations_for_user(requests_mock: RequestMocker) -> None:
    requests_mock.get(
        "https://anaconda.com/api/organizations/my",
        json=[
            {
                "id": "2902d4e4-7ad8-45dd-8d67-13bbed665409",
                "name": "my-org",
                "title": "My Cool Organization",
            }
        ],
    )

    client = RepoAPIClient()
    organizations = client.get_organizations_for_user()
    assert organizations == [
        OrganizationData(name="my-org", title="My Cool Organization")
    ]
