import pytest

conda = pytest.importorskip("conda")

from conda.gateways.connection.session import get_session  # noqa: E402

from anaconda_cloud_auth.plugins import AnacondaCloudAuthHandler  # noqa: E402


@pytest.fixture(autouse=True)
def mocked_conda_token(mocker):
    mocker.patch(
        "conda_token.repo_config.token_list",
        return_value={
            "https://repo.anaconda.cloud/repo/my-org/my-channel": "my-test-token"
        },
    )


@pytest.fixture()
def handler():
    return AnacondaCloudAuthHandler(
        channel_name="https://repo.anaconda.cloud/repo/my-org/my-channel"
    )


def test_get_token(handler):
    assert handler.token == "my-test-token"


def test_inject_header_during_request(handler, monkeypatch):
    url = "https://repo.anaconda.cloud/repo/my-org/my-channel/noarch/repodata.json"

    # Create a session and assign the handler to it
    get_session.cache_clear()
    session_obj = get_session(url)
    session_obj.auth = handler

    # Set up a dummy function that will capture the PreparedRequest without sending it.
    request = None

    def capture_request(req, *args, **kwargs):
        nonlocal request
        request = req

    monkeypatch.setattr(session_obj, "send", capture_request)

    # Make sure the token got injected
    session_obj.get(url)
    assert request.headers.get("Authorization") == "token my-test-token"
