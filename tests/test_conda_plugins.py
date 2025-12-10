from urllib.parse import urlparse

import pytest
from requests import PreparedRequest
from requests import Response
from requests.hooks import dispatch_hook

from anaconda_auth.token import TokenInfo

conda = pytest.importorskip("conda")

from conda.base import context  # noqa: E402
from conda.base.context import context as conda_context  # noqa: E402
from conda.gateways.connection.session import CondaSession  # noqa: E402
from conda.gateways.connection.session import get_session  # noqa: E402

from anaconda_auth._conda import config as plugin_config  # noqa: E402
from anaconda_auth._conda.auth_handler import AccessCredential  # noqa: E402
from anaconda_auth._conda.auth_handler import AnacondaAuthError  # noqa: E402
from anaconda_auth._conda.auth_handler import AnacondaAuthHandler  # noqa: E402
from anaconda_auth._conda.condarc import CondaRC  # noqa: E402
from anaconda_auth._conda.config import CredentialType  # noqa: E402


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
    assert token == AccessCredential("my-test-token", CredentialType.REPO_TOKEN)


@pytest.mark.usefixtures("mocked_token_info")
def test_get_repo_token_via_keyring(handler):
    token = handler._load_token(
        "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"
    )
    assert token == AccessCredential(
        "my-test-token-in-token-info", CredentialType.REPO_TOKEN
    )


@pytest.mark.usefixtures("mocked_token_info_with_api_key")
def test_get_unified_api_token_for_dotcom(handler, monkeypatch):
    # It should not matter what this value is; the API key should still be attached
    monkeypatch.setenv("ANACONDA_AUTH_USE_UNIFIED_REPO_API_KEY", "False")
    for host in ("repo.anaconda.com", "repo.continuum.io"):
        token = handler._load_token(f"https://{host}/pkgs/main/noarch/repodata.json")
        assert token == AccessCredential("my-test-api-key", CredentialType.API_KEY)


@pytest.mark.usefixtures("mocked_token_info_with_api_key")
def test_get_unified_api_token_via_keyring(handler, monkeypatch):
    monkeypatch.setenv("ANACONDA_AUTH_USE_UNIFIED_REPO_API_KEY", "True")
    token = handler._load_token(
        "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"
    )
    assert token == AccessCredential("my-test-api-key", CredentialType.API_KEY)


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
    assert token == AccessCredential(
        "my-first-test-token-in-token-info", CredentialType.REPO_TOKEN
    )


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
    "https://repo.anaconda.cloud/*": "anaconda-auth",
}


def test_channel_settings_yaml():
    yaml1 = plugin_config._build_channel_yaml(False, False).splitlines()
    assert "# DO NOT EDIT THIS FILE." in yaml1
    assert "channel_settings: []" in yaml1
    yaml2 = plugin_config._build_channel_yaml(True, False).splitlines()
    assert "# DO NOT EDIT THIS FILE." in yaml2
    assert "channel_settings:" in yaml2
    assert any(line[0] in "#c- " for line in yaml2)


def test_channel_settings_empty(conda_search_path):
    plugin_config._assert_settings(conda_context, {})


def test_channel_settings_prefix(conda_search_path):
    fpath = conda_search_path.prefix / "anaconda-auth.yml"
    assert not fpath.exists()
    plugin_config._write_condarc_d_settings()
    with pytest.raises(FileExistsError):
        plugin_config._write_condarc_d_settings()
    plugin_config._write_condarc_d_settings(overwrite=True)
    plugin_config._verify_channel_settings(filtered=False)
    context.reset_context()
    plugin_config._assert_settings(conda_context, REFERENCE)


def test_channel_settings_user(conda_search_path):
    fpath = conda_search_path.user
    assert not fpath.read_text().strip()
    condarc = CondaRC(fpath)
    condarc.update_channel_settings("my-test-channel", "anaconda-auth", username=None)
    condarc.save()
    context.reset_context()
    plugin_config._assert_settings(conda_context, {"my-test-channel": "anaconda-auth"})


def test_channel_settings_site(conda_search_path):
    condarc = CondaRC(conda_search_path.sites / "anaconda-auth-sites.yml")
    condarc.update_channel_settings("my-site-channel", "anaconda-auth", username=None)
    condarc.save()
    context.reset_context()
    plugin_config._assert_settings(conda_context, {"my-site-channel": "anaconda-auth"})


def test_channel_settings_merged(conda_search_path):
    plugin_config._write_condarc_d_settings()

    condarc1 = CondaRC(conda_search_path.user)
    condarc1.update_channel_settings("my-test-channel", "anaconda-auth", username=None)
    condarc1.save()

    condarc2 = CondaRC(conda_search_path.sites / "anaconda-auth-sites.yml")
    condarc2.update_channel_settings("my-site-channel", "anaconda-auth", username=None)
    condarc2.save()

    context.reset_context()
    expected = REFERENCE.copy()
    expected["my-test-channel"] = "anaconda-auth"
    expected["my-site-channel"] = "anaconda-auth"
    plugin_config._assert_settings(conda_context, expected)


def test_load_token_domain_anaconda_dot_com_default(conda_search_path):
    channel_url = "https://repo.anaconda.com/repo/some-channel"
    handler = AnacondaAuthHandler(channel_name=channel_url)
    url = channel_url + "/noarch/repodata.json"
    token_domain, credential_type = handler._load_token_domain(parsed_url=urlparse(url))

    assert token_domain == "anaconda.com"
    assert credential_type == CredentialType.API_KEY


def test_load_token_domain_anaconda_cloud_default(conda_search_path):
    channel_url = "https://repo.anaconda.cloud/repo/some-channel"
    handler = AnacondaAuthHandler(channel_name=channel_url)
    url = channel_url + "/noarch/repodata.json"
    token_domain, credential_type = handler._load_token_domain(parsed_url=urlparse(url))

    assert token_domain == "anaconda.com"
    assert credential_type == CredentialType.REPO_TOKEN


def test_load_token_domain_anaconda_cloud_api_key(conda_search_path, monkeypatch):
    monkeypatch.setenv("ANACONDA_AUTH_USE_UNIFIED_REPO_API_KEY", "True")

    channel_url = "https://repo.anaconda.cloud/repo/some-channel"
    handler = AnacondaAuthHandler(channel_name=channel_url)
    url = channel_url + "/noarch/repodata.json"
    token_domain, credential_type = handler._load_token_domain(parsed_url=urlparse(url))

    assert token_domain == "anaconda.com"
    assert credential_type == CredentialType.API_KEY
