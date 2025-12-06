import pytest
from requests import PreparedRequest
from requests import Response
from requests.hooks import dispatch_hook

from anaconda_auth.token import TokenInfo

conda = pytest.importorskip("conda")

from conda.base.context import context as conda_context  # noqa: E402
from conda.gateways.connection.session import CondaSession  # noqa: E402
from conda.gateways.connection.session import get_session  # noqa: E402

from anaconda_auth._conda import config as plugin_config  # noqa: E402
from anaconda_auth._conda.auth_handler import AnacondaAuthError  # noqa: E402
from anaconda_auth._conda.auth_handler import AnacondaAuthHandler  # noqa: E402


@pytest.fixture()
def mocked_empty_conda_token(mocker):
    mocker.patch(
        "anaconda_auth._conda.repo_config.token_list",
        return_value={},
    )


@pytest.fixture()
def mocked_conda_token(mocker):
    mocker.patch(
        "anaconda_auth._conda.repo_config.token_list",
        return_value={"https://repo.anaconda.cloud/repo/": "my-test-token"},
    )


@pytest.fixture()
def mocked_token_info(mocker):
    mocker.patch(
        "anaconda_auth.token.TokenInfo.load",
        return_value=TokenInfo(
            domain="repo.anaconda.cloud",
            repo_tokens=[
                {
                    "org_name": "my-first-org",
                    "token": "my-first-test-token-in-token-info",
                },
                {"org_name": "my-org", "token": "my-test-token-in-token-info"},
            ],
        ),
    )


@pytest.fixture()
def mocked_token_info_with_api_key(mocker):
    mocker.patch(
        "anaconda_auth.token.TokenInfo.load",
        return_value=TokenInfo(
            domain="repo.anaconda.cloud",
            api_key="my-test-api-key",
            repo_tokens=[
                {
                    "org_name": "my-first-org",
                    "token": "my-first-test-token-in-token-info",
                },
                {"org_name": "my-org", "token": "my-test-token-in-token-info"},
            ],
        ),
    )


@pytest.fixture()
def handler():
    return AnacondaAuthHandler(
        channel_name="https://repo.anaconda.cloud/repo/my-org/my-channel"
    )


@pytest.mark.usefixtures("mocked_conda_token")
def test_get_token_via_conda_token(handler):
    token = handler._load_token(
        "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"
    )
    assert token == "my-test-token"


@pytest.mark.usefixtures("mocked_token_info")
def test_get_repo_token_via_keyring(handler):
    token = handler._load_token(
        "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"
    )
    assert token == "my-test-token-in-token-info"


@pytest.mark.usefixtures("mocked_token_info_with_api_key")
def test_get_unified_api_token_for_dotcom(handler, monkeypatch):
    # It should not matter what this value is; the API key should still be attached
    monkeypatch.setenv("ANACONDA_AUTH_USE_UNIFIED_REPO_API_KEY", "False")
    for host in ("repo.anaconda.com", "repo.continuum.io"):
        token = handler._load_token(f"https://{host}/pkgs/main/noarch/repodata.json")
        assert token == "my-test-api-key"


@pytest.mark.usefixtures("mocked_token_info_with_api_key")
def test_get_unified_api_token_via_keyring(handler, monkeypatch):
    monkeypatch.setenv("ANACONDA_AUTH_USE_UNIFIED_REPO_API_KEY", "True")
    token = handler._load_token(
        "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"
    )
    assert token == "my-test-api-key"


@pytest.mark.usefixtures("mocked_token_info")
def test_auth_handler_call_sets_authorization_header_repo_token(handler, monkeypatch):
    request = PreparedRequest()
    request.url = (
        "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"
    )
    request.headers = {}

    modified_request = handler(request)

    assert (
        modified_request.headers["Authorization"] == "token my-test-token-in-token-info"
    )


@pytest.mark.usefixtures("mocked_token_info_with_api_key")
def test_auth_handler_call_sets_authorization_header_unified_api_token(
    handler, monkeypatch
):
    monkeypatch.setenv("ANACONDA_AUTH_USE_UNIFIED_REPO_API_KEY", "True")

    request = PreparedRequest()
    request.url = (
        "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"
    )
    request.headers = {}

    modified_request = handler(request)

    assert modified_request.headers["Authorization"] == "Bearer my-test-api-key"


@pytest.mark.usefixtures("mocked_token_info")
def test_get_token_for_main_finds_first_token(handler):
    token = handler._load_token(
        "https://repo.anaconda.cloud/repo/main/noarch/repodata.json"
    )
    assert token == "my-first-test-token-in-token-info"


@pytest.mark.usefixtures("mocked_empty_conda_token")
def test_get_token_missing(handler):
    token = handler._load_token(
        "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"
    )
    assert token is None


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


@pytest.mark.parametrize("mocked_status_code", [401, 403])
@pytest.mark.usefixtures("mocked_token_info")
def test_response_callback_error_handler(
    mocked_status_code, *, session, url, monkeypatch
):
    def _mocked_request(req, *args, **kwargs):
        response = Response()
        response.status_code = mocked_status_code
        response = dispatch_hook("response", req.hooks, response, **kwargs)
        return response

    monkeypatch.setattr(session, "send", _mocked_request)

    # A 403 response is captured by the hook and a custom exception is raised
    with pytest.raises(AnacondaAuthError):
        session.get(url)


@pytest.mark.parametrize("mocked_status_code", [401, 403])
def test_inject_no_header_during_request_if_no_token(
    mocked_status_code, *, session, url, monkeypatch
):
    """
    If there is not token, we first make a request without an Authorization header.
    If the server responds with an error code, we raise an exception.
    """
    # Set up a dummy function that will capture the PreparedRequest without sending it.
    request = None

    def _mocked_request(req, *args, **kwargs):
        # Capture the request object for introspection later
        nonlocal request
        request = req

        # Simulate a 403 response from the server
        response = Response()
        response.status_code = mocked_status_code
        response = dispatch_hook("response", req.hooks, response, **kwargs)
        return response

    monkeypatch.setattr(session, "send", _mocked_request)

    # An error response is captured by the hook and a custom exception is raised
    with pytest.raises(AnacondaAuthError):
        session.get(url)

    # Make sure the token did not get injected
    assert request.headers.get("Authorization") is None


REFERENCE = {
    "https://repo.continuum.io/*": {"auth": "anaconda-auth"},
    "https://repo.anaconda.com/*": {"auth": "anaconda-auth"},
    "https://repo.anaconda.cloud/*": {"auth": "anaconda-auth"},
    "https://anaconda.com/*": {"auth": "anaconda-auth"},
}


def _parse_config(config):
    result = {}
    for crec in config:
        chan = crec["channel"]
        if chan in REFERENCE:
            print(chan, crec)
            drec = result.setdefault(chan, {})
            drec.update({k: v for k, v in crec.items() if k != "channel"})
    return result


def test_channel_settings_empty():
    assert _parse_config(conda_context.channel_settings) == {}


def test_channel_settings_installed(condarc_path):
    fpath = condarc_path.parent / "condarc.d" / "anaconda-auth.yml"
    assert not fpath.exists() and not fpath.parent.exists()
    plugin_config._write_condarc_d_settings()
    assert fpath.exists()
    assert fpath.read_text().strip()
    conda_context.__init__()
    assert _parse_config(conda_context.channel_settings) == REFERENCE
