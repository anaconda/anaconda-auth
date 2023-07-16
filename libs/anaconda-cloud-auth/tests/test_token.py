import pytest
from pytest_mock import MockerFixture

from anaconda_cloud_auth.actions import logout
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.token import TokenExpiredError
from anaconda_cloud_auth.token import TokenInfo
from anaconda_cloud_auth.token import TokenNotFoundError


def test_expired_token_error(outdated_token_info: TokenInfo) -> None:
    with pytest.raises(TokenExpiredError):
        _ = outdated_token_info.get_access_token()


def test_token_not_found() -> None:
    auth_config = AuthConfig()

    with pytest.raises(TokenNotFoundError):
        _ = TokenInfo.load(auth_config.domain)

    with pytest.raises(TokenNotFoundError):
        _ = TokenInfo(domain=auth_config.domain).get_access_token()


def test_logout_multiple_okay(mocker: MockerFixture) -> None:
    """We can logout multiple times and no exception is raised."""
    import keyring

    delete_spy = mocker.spy(keyring, "delete_password")

    auth_config = AuthConfig(domain="test")
    token_info = TokenInfo(api_key="key", domain=auth_config.domain)
    token_info.save()

    for _ in range(2):
        logout(auth_config)

    delete_spy.assert_called_once()
