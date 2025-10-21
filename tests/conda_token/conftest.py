import os
import warnings
from unittest import mock

import pytest

conda = pytest.importorskip("conda")

from conda.base.context import reset_context  # noqa: E402

from anaconda_auth._conda import condarc as condarc_module  # noqa: E402
from anaconda_auth._conda import repo_config  # noqa: E402
from anaconda_auth._conda.conda_api import Commands  # noqa: E402
from anaconda_auth._conda.conda_api import run_command  # noqa: E402
from anaconda_auth._conda.repo_config import clean_index  # noqa: E402
from anaconda_auth._conda.repo_config import token_remove  # noqa: E402
from anaconda_auth._conda.repo_config import token_set  # noqa: E402


def pytest_configure(config):
    warnings.filterwarnings("always")


@pytest.fixture(autouse=True)
def empty_condarc(monkeypatch, tmp_path):
    condarc_path = tmp_path / ".condarc"
    monkeypatch.setattr(condarc_module, "DEFAULT_CONDARC_PATH", condarc_path)

    orig_get_condarc_args = repo_config._get_condarc_args

    def _new_get_condarc_args(
        condarc_system: bool = False,
        condarc_env: bool = False,
        condarc_file: str | None = None,
    ) -> None:
        return orig_get_condarc_args(condarc_file=str(condarc_path))

    monkeypatch.setattr(repo_config, "_get_condarc_args", _new_get_condarc_args)

    with condarc_path.open("w") as fp:
        fp.write("")
    reset_context([condarc_path])
    yield condarc_path


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


@pytest.fixture(scope="session")
def reset_channels_alias():
    clean_index()
    run_command(Commands.CONFIG, "--remove-key", "channels", use_exception_handler=True)
    run_command(
        Commands.CONFIG, "--prepend", "channels", "defaults", use_exception_handler=True
    )
    run_command(
        Commands.CONFIG,
        "--set",
        "channel_alias",
        "https://conda.anaconda.org",
        use_exception_handler=True,
    )


@pytest.fixture(scope="function")
def set_ssl_verify_true():
    run_command(
        Commands.CONFIG, "--set", "ssl_verify", "true", use_exception_handler=True
    )
    yield
    run_command(
        Commands.CONFIG, "--set", "ssl_verify", "true", use_exception_handler=True
    )


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


@pytest.fixture(scope="function")
def uninstall_rope():
    run_command(Commands.REMOVE, "rope", "-y", "--force", use_exception_handler=True)
    yield
    run_command(Commands.REMOVE, "rope", "-y", "--force", use_exception_handler=True)


@pytest.fixture
def channeldata_url(repo_url):
    return repo_url + "main/channeldata.json"


@pytest.fixture
def repodata_url(repo_url):
    return repo_url + "main/osx-64/repodata.json"
