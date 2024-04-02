import pytest
from requests import Response
from requests.hooks import dispatch_hook

from anaconda_cloud_auth.token import TokenInfo

conda = pytest.importorskip("conda")

from conda.gateways.connection.session import CondaSession  # noqa: E402
from conda.gateways.connection.session import get_session  # noqa: E402

from anaconda_cloud_auth._conda.auth_handler import AnacondaCloudAuthError  # noqa: E402
from anaconda_cloud_auth._conda.auth_handler import (  # noqa: E402
    AnacondaCloudAuthHandler,
)


@pytest.fixture()
def mocked_conda_token(mocker):
    mocker.patch(
        "conda_token.repo_config.token_list",
        return_value={
            "https://repo.anaconda.cloud/repo/my-org/my-channel": "my-test-token"
        },
    )


@pytest.fixture()
def mocked_token_info(mocker):
    mocker.patch(
        "anaconda_cloud_auth.token.TokenInfo.load",
        return_value=TokenInfo(
            domain="repo.anaconda.cloud",
            repo_token="my-test-token-in-token-info",
        ),
    )


@pytest.fixture()
def handler():
    return AnacondaCloudAuthHandler(
        channel_name="https://repo.anaconda.cloud/repo/my-org/my-channel"
    )


@pytest.mark.usefixtures("mocked_conda_token")
def test_get_token_via_conda_token(handler):
    assert handler.token == "my-test-token"


@pytest.mark.usefixtures("mocked_token_info")
def test_get_token_via_keyring(handler):
    assert handler.token == "my-test-token-in-token-info"


def test_get_token_missing(handler):
    with pytest.raises(AnacondaCloudAuthError):
        _ = handler.token


@pytest.fixture()
def url() -> str:
    return "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"


@pytest.fixture()
def session(handler, url) -> CondaSession:
    # Create a session and assign the handler to it
    get_session.cache_clear()
    session_obj = get_session(url)
    session_obj.auth = handler
    return session_obj


@pytest.mark.usefixtures("mocked_token_info")
def test_inject_header_during_request(session, url, monkeypatch):
    # Set up a dummy function that will capture the PreparedRequest without sending it.
    request = None

    def capture_request(req, *args, **kwargs):
        nonlocal request
        request = req

    monkeypatch.setattr(session, "send", capture_request)

    # Make sure the token got injected
    session.get(url)
    assert request.headers.get("Authorization") == "token my-test-token-in-token-info"


@pytest.mark.usefixtures("mocked_token_info")
def test_response_callback_403(session, url, monkeypatch):
    def trigger_403(req, *args, **kwargs):
        response = Response()
        response.status_code = 403
        response = dispatch_hook("response", req.hooks, response, **kwargs)
        return response

    monkeypatch.setattr(session, "send", trigger_403)

    # A 403 response is captured by the hook and a custom exception is raised
    with pytest.raises(AnacondaCloudAuthError):
        session.get(url)
