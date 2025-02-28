from datetime import datetime
from uuid import UUID
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
from anaconda_auth.token import TokenNotFoundError


@pytest.fixture()
def org_name() -> str:
    return "test-org-name"


@pytest.fixture()
def business_org_id() -> UUID:
    return uuid4()


@pytest.fixture(autouse=True)
def token_info():
    token_info = TokenInfo.load(create=True)
    token_info.save()
    return token_info


@pytest.fixture()
def token_is_installed(org_name: str, token_info: TokenInfo) -> TokenInfo:
    token_info.set_repo_token(org_name=org_name, token="test-token")
    token_info.save()
    return token_info


@pytest.fixture(autouse=True)
def mock_do_auth_flow(mocker: MockerFixture) -> None:
    mocker.patch(
        "anaconda_auth.repo._do_auth_flow",
        return_value="test-access-token",
    )


@pytest.fixture()
def token_does_not_exist_in_service(
    requests_mock: RequestMocker, org_name: str
) -> None:
    requests_mock.get(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        status_code=404,
    )


@pytest.fixture()
def token_exists_in_service(
    requests_mock: RequestMocker, org_name: str
) -> TokenInfoResponse:
    token_info = TokenInfoResponse(
        id=uuid4(), expires_at=datetime(year=2025, month=1, day=1)
    )
    requests_mock.get(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        json=token_info.model_dump(mode="json"),
    )
    return token_info


@pytest.fixture()
def token_created_in_service(
    requests_mock: RequestMocker, org_name: str
) -> TokenCreateResponse:
    test_token = "test-token"
    payload = {"token": test_token, "expires_at": "2025-01-01T00:00:00"}
    requests_mock.put(
        f"https://anaconda.com/api/organizations/{org_name}/ce/current-token",
        json=payload,
    )
    return TokenCreateResponse(**payload)


@pytest.fixture()
def user_has_one_org(
    requests_mock: RequestMocker, org_name: str, business_org_id: UUID
) -> TokenCreateResponse:
    requests_mock.get(
        "https://anaconda.com/api/organizations/my",
        json=[
            {
                "id": str(business_org_id),
                "name": org_name,
                "title": "My Cool Organization",
            }
        ],
    )
    return [
        OrganizationData(
            id=business_org_id, name=org_name, title="My Cool Organization"
        )
    ]


@pytest.fixture()
def user_has_multiple_orgs(
    requests_mock: RequestMocker, org_name: str, business_org_id: UUID
) -> TokenCreateResponse:
    first_id = uuid4()
    requests_mock.get(
        "https://anaconda.com/api/organizations/my",
        json=[
            {
                "id": str(first_id),
                "name": "first-org",
                "title": "My First Organization",
            },
            {
                "id": str(business_org_id),
                "name": org_name,
                "title": "My Business Organization",
            },
        ],
    )
    return [
        OrganizationData(id=first_id, name="first-org", title="My First Organizatoin"),
        OrganizationData(
            id=business_org_id, name=org_name, title="My Business Organization"
        ),
    ]


@pytest.fixture()
def user_has_no_orgs(requests_mock: RequestMocker) -> list[OrganizationData]:
    requests_mock.get(
        "https://anaconda.com/api/organizations/my",
        json=[],
    )
    return []


@pytest.fixture(
    autouse=True, params=["security_subscription", "commercial_subscription"]
)
def user_has_business_subscription(
    request, requests_mock: RequestMocker, org_name: str, business_org_id: UUID
) -> TokenCreateResponse:
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


@pytest.fixture()
def user_has_starter_subscription(
    request, requests_mock: RequestMocker, business_org_id: UUID
) -> TokenCreateResponse:
    requests_mock.get(
        "https://anaconda.com/api/account",
        json={
            "subscriptions": [
                {
                    "org_id": str(business_org_id),
                    "product_code": "starter_subscription",
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


@pytest.mark.parametrize("option_flag", ["-o", "--org"])
def test_token_install_does_not_exist_yet(
    option_flag: str,
    org_name: str,
    token_does_not_exist_in_service: None,
    token_created_in_service: str,
    *,
    invoke_cli: CLIInvoker,
) -> None:
    result = invoke_cli(["token", "install", option_flag, org_name])
    assert result.exit_code == 0

    token_info = TokenInfo.load()
    repo_token = token_info.get_repo_token(org_name=org_name)
    assert repo_token == token_created_in_service.token


@pytest.mark.parametrize("option_flag", ["-o", "--org"])
def test_token_install_exists_already_accept(
    option_flag: str,
    org_name: str,
    token_exists_in_service: None,
    token_created_in_service: TokenCreateResponse,
    *,
    invoke_cli: CLIInvoker,
) -> None:
    result = invoke_cli(["token", "install", option_flag, org_name], input="y")
    assert result.exit_code == 0, result.stdout

    token_info = TokenInfo.load()
    repo_token = token_info.get_repo_token(org_name=org_name)
    assert repo_token == token_created_in_service.token


@pytest.mark.parametrize("option_flag", ["-o", "--org"])
def test_token_install_exists_already_decline(
    option_flag: str,
    org_name: str,
    token_exists_in_service: None,
    token_created_in_service: str,
    *,
    invoke_cli: CLIInvoker,
) -> None:
    result = invoke_cli(["token", "install", option_flag, org_name], input="n")
    assert result.exit_code == 1, result.stdout

    token_info = TokenInfo.load()
    with pytest.raises(TokenNotFoundError):
        _ = token_info.get_repo_token(org_name=org_name)


def test_token_install_no_available_org(
    user_has_no_orgs: list[OrganizationData],
    *,
    invoke_cli: CLIInvoker,
) -> None:
    result = invoke_cli(["token", "install"])
    assert result.exit_code == 1, result.stdout
    assert "No organizations found." in result.stdout
    assert "Aborted." in result.stdout


def test_token_install_select_first_if_only_org(
    org_name: str,
    token_does_not_exist_in_service: None,
    token_created_in_service: str,
    user_has_one_org: list[OrganizationData],
    *,
    invoke_cli: CLIInvoker,
) -> None:
    result = invoke_cli(["token", "install"])
    assert result.exit_code == 0, result.stdout
    assert (
        f"Only one organization found, automatically selecting: {org_name}"
        in result.stdout
    )

    token_info = TokenInfo.load()
    repo_token = token_info.get_repo_token(org_name=org_name)
    assert repo_token == token_created_in_service.token


def test_token_install_select_second_of_multiple_orgs(
    org_name: str,
    token_does_not_exist_in_service: None,
    token_created_in_service: str,
    user_has_multiple_orgs: list[OrganizationData],
    *,
    invoke_cli: CLIInvoker,
) -> None:
    # TODO: This uses the "j" key binding. I can't figure out how to send the right
    #       escape code for down arrow.
    result = invoke_cli(["token", "install"], input="j\n")
    assert result.exit_code == 0, result.stdout

    token_info = TokenInfo.load()
    repo_token = token_info.get_repo_token(org_name=org_name)
    assert repo_token == token_created_in_service.token


@pytest.mark.parametrize("option_flag", ["-o", "--org"])
def test_token_uninstall(
    option_flag: str,
    org_name: str,
    token_is_installed: TokenInfo,
    *,
    invoke_cli: CLIInvoker,
) -> None:
    result = invoke_cli(["token", "uninstall", option_flag, org_name])
    assert result.exit_code == 0, result.stdout

    token_info = TokenInfo.load()
    with pytest.raises(TokenNotFoundError):
        _ = token_info.get_repo_token(org_name=org_name)


def test_get_repo_token_info_no_token(
    org_name: str, token_does_not_exist_in_service: None
) -> None:
    client = RepoAPIClient()
    token_info = client.get_repo_token_info(org_name=org_name)
    assert token_info is None


def test_get_repo_token_info_has_token(
    org_name: str,
    token_exists_in_service: TokenInfoResponse,
) -> None:
    client = RepoAPIClient()
    token_info = client.get_repo_token_info(org_name=org_name)
    assert token_info == token_exists_in_service


def test_create_repo_token_info_has_token(
    org_name: str,
    token_created_in_service: TokenCreateResponse,
) -> None:
    client = RepoAPIClient()
    token_info = client.create_repo_token(org_name=org_name)
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
