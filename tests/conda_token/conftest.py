import os
import warnings
from unittest import mock

import pytest

conda = pytest.importorskip("conda")

from conda.base import context as conda_context  # noqa: E402
from conda.base.context import reset_context  # noqa: E402

from anaconda_auth._conda import condarc as condarc_module  # noqa: E402
from anaconda_auth._conda import repo_config  # noqa: E402
from anaconda_auth._conda.conda_api import Commands  # noqa: E402
from anaconda_auth._conda.conda_api import run_command  # noqa: E402
from anaconda_auth._conda.repo_config import token_remove  # noqa: E402
from anaconda_auth._conda.repo_config import token_set  # noqa: E402


def pytest_configure(config):
    warnings.filterwarnings("always")


@pytest.fixture()
def condarc_path(tmp_path):
    """Returns the path of a temporary, empty .condarc file."""
    condarc_path = tmp_path / ".condarc"
    condarc_path.touch()
    yield condarc_path


@pytest.fixture(autouse=True)
def patch_conda_config_to_use_temp_condarc(monkeypatch, condarc_path):
    """Patch operations that modify .condarc to prevent modifying
    the ~/.condarc of the user running the tests.
    """
    monkeypatch.setattr(condarc_module, "DEFAULT_CONDARC_PATH", condarc_path)

    # Patch the handling of conda CLI arguments to pass the path to the condarc file
    orig_get_condarc_args = repo_config._get_condarc_args

    def _new_get_condarc_args(*args, **kwargs) -> None:
        return orig_get_condarc_args(condarc_file=str(condarc_path))

    monkeypatch.setattr(repo_config, "_get_condarc_args", _new_get_condarc_args)

    # Patch reset_context function such that it only loads config from our temp file
    orig_reset_context = reset_context

    def _new_reset_context(*args, **kwargs):
        return orig_reset_context([condarc_path])

    monkeypatch.setattr(conda_context, "reset_context", _new_reset_context)
    reset_context()
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
def uninstall_rope(condarc_path):
    run_command(
        Commands.REMOVE,
        "rope",
        "-y",
        "--force",
        f"--file={condarc_path}",
        use_exception_handler=True,
    )
    yield
    run_command(
        Commands.REMOVE,
        "rope",
        "-y",
        "--force",
        f"--file={condarc_path}",
        use_exception_handler=True,
    )


@pytest.fixture
def channeldata_url(repo_url):
    return repo_url + "main/channeldata.json"


@pytest.fixture
def repodata_url(repo_url):
    return repo_url + "main/osx-64/repodata.json"
