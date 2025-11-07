from datetime import datetime
from uuid import UUID

import pytest
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestMocker

pytest.importorskip("conda")

# ruff: noqa: E402
from anaconda_auth.repo import OrganizationData
from anaconda_auth.repo import RepoAPIClient
from anaconda_auth.repo import TokenCreateResponse
from anaconda_auth.repo import TokenInfoResponse


@pytest.fixture(autouse=True)
def mock_do_auth_flow(mocker: MockerFixture) -> None:
    mocker.patch(
        "anaconda_auth.actions._do_auth_flow",
        return_value="test-access-token",
    )


@pytest.fixture(
    autouse=True, params=["security_subscription", "commercial_subscription"]
)
def user_has_business_subscription(
    request, requests_mock: RequestMocker, org_name: str, business_org_id: UUID
) -> None:
    requests_mock.get(
        "https://anaconda.com/api/account",
        json={
            "subscriptions": [
                {
                    "org_id": str(business_org_id),
                    "product_code": request.param,
                }
            ]
        },
    )


@pytest.fixture(autouse=True)
def repodata_json_available_with_token(
    requests_mock: RequestMocker, token_created_in_service: TokenCreateResponse
) -> None:
    requests_mock.head(
        f"https://repo.anaconda.cloud/t/{token_created_in_service.token}/repo/main/noarch/repodata.json",
        status_code=200,
    )


def test_get_repo_token_info_no_token(
    org_name: str, token_does_not_exist_in_service: None
) -> None:
    client = RepoAPIClient()
    token_info = client._get_repo_token_info(org_name=org_name)
    assert token_info is None


def test_get_repo_token_info_has_token(
    org_name: str,
    token_exists_in_service: TokenInfoResponse,
) -> None:
    client = RepoAPIClient()
    token_info = client._get_repo_token_info(org_name=org_name)
    assert token_info == token_exists_in_service


def test_create_repo_token_info_has_token(
    org_name: str,
    token_created_in_service: TokenCreateResponse,
) -> None:
    client = RepoAPIClient()
    token_info = client._create_repo_token(org_name=org_name)
    assert token_info == token_created_in_service


def test_get_organizations_for_user(user_has_one_org: list[OrganizationData]) -> None:
    client = RepoAPIClient()
    organizations = client.get_organizations_for_user()
    assert organizations == user_has_one_org


def test_get_business_organizations_for_user(
    org_name: str,
    business_org_id: UUID,
    user_has_multiple_orgs: list[OrganizationData],
    user_has_business_subscription: None,
) -> None:
    client = RepoAPIClient()
    organizations = client.get_business_organizations_for_user()
    assert organizations == [
        OrganizationData(
            id=business_org_id, name=org_name, title="My Business Organization"
        )
    ]


def test_get_business_organizations_for_user_only_starter(
    org_name: str,
    business_org_id: UUID,
    user_has_multiple_orgs: list[OrganizationData],
    user_has_starter_subscription: None,
) -> None:
    client = RepoAPIClient()
    organizations = client.get_business_organizations_for_user()
    assert organizations == []


def test_issue_new_token_prints_success_message_via_client(
    org_name: str, mocker: MockerFixture, capsys: pytest.CaptureFixture
) -> None:
    client = RepoAPIClient()
    mocker.patch.object(client, "_get_repo_token_info", return_value=None)

    mock_response = mocker.MagicMock()
    mock_response.expires_at = datetime(2025, 12, 31)
    mocker.patch.object(client, "_create_repo_token", return_value=mock_response)
    client.issue_new_token(org_name=org_name)
    res = capsys.readouterr()
    expected_msg = "Your conda token has been installed and expires 2025-12-31 00:00:00. To view your token(s), you can use anaconda token list\n"

    assert expected_msg in res.out


def test_issue_new_token_prints_success_message_via_cli(
    org_name: str,
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture,
    token_exists_in_service,
    token_created_in_service,
    invoke_cli,
) -> None:
    result = invoke_cli(["token", "install", "--org", org_name], input="y\nn\n")

    expected_msg = "Your conda token has been installed and expires 2025-01-01 00:00:00. To view your token(s), you can use anaconda token list\n"
    assert result.exit_code == 0, result.stdout
    assert expected_msg in result.stdout


def test_set_token_prints_success_message_via_cli(
    org_name: str,
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture,
    token_exists_in_service,
    token_created_in_service,
    invoke_cli,
) -> None:
    result = invoke_cli(
        ["token", "set", "--org", org_name, token_created_in_service.token],
        input="y\nn\n",
    )

    assert result.exit_code == 0, result.stdout


def test_set_token_failure_without_token(
    org_name: str,
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture,
    token_exists_in_service,
    token_created_in_service,
    invoke_cli,
) -> None:
    result = invoke_cli(
        [
            "token",
            "set",
        ],
        input="y\nn\n",
    )

    assert result.exit_code == 2, result.stdout
