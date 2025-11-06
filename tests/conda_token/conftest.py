import os
import warnings
from unittest import mock

import pytest

conda = pytest.importorskip("conda")

from anaconda_auth._conda.repo_config import token_remove  # noqa: E402
from anaconda_auth._conda.repo_config import token_set  # noqa: E402


def pytest_configure(config):
    warnings.filterwarnings("always")


@pytest.fixture(scope="session")
def test_server_url() -> str:
    """Run a test server, and return its URL."""
    from . import testing_server

    return testing_server.run_server()


@pytest.fixture
def repo_url(test_server_url: str) -> str:
    repo_url = test_server_url + "/repo/"
    with mock.patch.dict(os.environ, {"CONDA_TOKEN_REPO_URL": repo_url}):
        with mock.patch("anaconda_auth._conda.repo_config.REPO_URL", repo_url):
            yield repo_url


@pytest.fixture(scope="function")
def remove_token(repo_url):
    token_remove()
    yield
    token_remove()


@pytest.fixture(scope="session")
def remove_token_end_of_session():
    yield
    token_remove()


@pytest.fixture(scope="function")
def remove_token_no_repo_url_mock():
    """
    Remove token without mock repo_url
    """
    token_remove()
    yield
    token_remove()


@pytest.fixture(scope="function")
def set_dummy_token(repo_url):
    token_remove()
    token_set("SECRET", force=True)
    yield
    token_remove()


@pytest.fixture(scope="function")
def set_secret_token():
    token_remove()
    secret_token = os.environ.get("CE_TOKEN", "SECRET_TOKEN")
    token_set(secret_token, force=True)
    yield
    token_remove()


@pytest.fixture(scope="function")
def set_secret_token_mock_server(repo_url):
    token_remove()
    secret_token = os.environ.get("CE_TOKEN", "SECRET_TOKEN")
    token_set(secret_token, force=True)
    yield
    token_remove()


@pytest.fixture(scope="function")
def set_secret_token_with_signing():
    token_remove()
    secret_token = os.environ.get("CE_TOKEN", "SECRET_TOKEN")
    token_set(secret_token, enable_signature_verification=True, force=True)
    yield
    token_remove()


@pytest.fixture(scope="function")
def secret_token():
    token = os.environ.get("CE_TOKEN", "SECRET_TOKEN")
    yield token


@pytest.fixture
def channeldata_url(repo_url):
    return repo_url + "main/channeldata.json"


@pytest.fixture
def repodata_url(repo_url):
    return repo_url + "main/osx-64/repodata.json"
