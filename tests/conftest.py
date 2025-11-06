from __future__ import annotations

import os
import traceback
import warnings
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import IO
from typing import Any
from typing import Generator
from typing import Mapping
from typing import Protocol
from typing import Sequence
from typing import cast

import pytest
import typer
from click.testing import Result
from dotenv import load_dotenv
from keyring.backend import KeyringBackend
from pytest import MonkeyPatch
from pytest_mock import MockerFixture
from typer.testing import CliRunner

from anaconda_auth.client import BaseClient
from anaconda_auth.token import TokenInfo
from anaconda_cli_base.cli import app

load_dotenv()


def is_conda_installed():
    try:
        import conda  # noqa: F401

        return True
    except ImportError:
        return False


class MockedKeyring(KeyringBackend):
    """A high-priority in-memory keyring backend for testing"""

    priority = 10000.0  # type: ignore
    _data: dict = defaultdict(dict)

    def __init__(self) -> None:
        super().__init__()

    def set_password(self, service: str, username: str, password: str) -> None:
        self._data[service][username] = password

    def get_password(self, service: str, username: str) -> str | None:
        password = self._data.get(service, {}).get(username, None)
        return password

    def delete_password(self, service: str, username: str) -> None:
        _ = self._data.get(service, {}).pop(username)


@pytest.fixture(autouse=True)
def clear_mocked_keyring() -> None:
    MockedKeyring._data = defaultdict(dict)


@pytest.fixture(autouse=True)
def set_keyring_name(mocker: MockerFixture) -> None:
    mocker.patch("anaconda_auth.token.KEYRING_NAME", "Anaconda Test")


@pytest.fixture
def outdated_api_key() -> str:
    # This is an old token from the dev system that will always be out-of-date
    api_key = (
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHQiLCJ0eXAiOiJKV1QifQ"
        ".eyJleHAiOjE2ODkwODg3ODYsInN1YiI6ImQwNGMzNTZiLWFmZDItNGIzZ"
        "S04MGYyLTQwMzExM2UwOTc0YiJ9.tTi_gttpQWhiTy_Uh0bDohN34mqd_6"
        "AHvyXf8_R5PFxjI-z9Ei0S3XCm9siP0RfyJx2j08SRs3FwXpkT8b8jP__C"
        "h-Y4K-zXYksZnTGcQ77YhKQCoKpGSpGlE4yD6gRXRRDT7bHs4H7gf4e6iD"
        "1Vdcq0yx5-5h-CbBgSwS9LSpJ_HDZBUy-xbRrw0aD36aQ5qs6huswgCOQa"
        "9YrYfsrSbZW8uY48LAt5Y69t8x1twNBI5_Cumx-JEZuDLQxq7HQp7wKldE"
        "tbycV5uemKjyR1Qeuva2zCKYB3FEXdTEiWHhTzhSQ-3-xjUrIZvpfGJd3G"
        "CzXlkUhpeDoj2KbSN-Lq0Q"
    )
    return api_key


@pytest.fixture
def outdated_token_info(outdated_api_key: str) -> TokenInfo:
    return TokenInfo(api_key=outdated_api_key, domain="mocked-domain")


@pytest.fixture()
def tmp_cwd(monkeypatch: MonkeyPatch, tmp_path: Path) -> Path:
    """Create & return a temporary directory after setting current working directory to it."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture(scope="session")
def is_not_none() -> Any:
    """
    An object that can be used to test whether another is None.

    This is particularly useful when testing contents of collections, e.g.:

    ```python
    def test_data(data, is_not_none):
        assert data == {"some_key": is_not_none, "some_other_key": 5}
    ```

    """

    class _NotNone:
        def __eq__(self, other: Any) -> bool:
            return other is not None

    return _NotNone()


@pytest.fixture
def disable_dot_env(mocker: MockerFixture) -> None:
    from anaconda_cli_base.config import AnacondaBaseSettings

    mocker.patch.dict(AnacondaBaseSettings.model_config, {"env_file": ""})


@pytest.fixture(autouse=True)
def disable_config_toml(tmp_path: Path, monkeypatch: MonkeyPatch):
    monkeypatch.setenv("ANACONDA_CONFIG_TOML", str(tmp_path / "empty-config.toml"))


@pytest.fixture
def api_key() -> str | None:
    return os.getenv("TEST_API_KEY")


@pytest.fixture()
def integration_test_client(api_key: str | None) -> BaseClient:
    c = BaseClient(api_key=api_key)
    return c


@pytest.fixture()
def save_api_key_to_token(api_key: str | None) -> Generator[None, None, None]:
    from anaconda_auth.config import AnacondaAuthConfig

    conf = AnacondaAuthConfig()
    token = TokenInfo(api_key=api_key, domain=conf.domain)
    token.save()
    yield


def pytest_addoption(parser):  # type: ignore
    """Defines custom CLI options."""
    parser.addoption(
        "--integration",
        action="store_true",
        dest="integration",
        default=False,
        help="enable integration tests",
    )
    parser.addoption(
        "--error-on-pending-deprecations",
        action="store_true",
        default=False,
        help="Treat PendingDeprecationWarnings from anaconda_auth as errors",
    )


def pytest_configure(config):
    """Customize warning filters to ignore PendingDeprecationWarnings that are
    raised by other conda plugins, while allowing us to still catch our own.
    """
    if config.getoption("--error-on-pending-deprecations"):
        warnings.simplefilter("error", PendingDeprecationWarning)

        original_warn = warnings.warn

        def custom_warn(message, category=UserWarning, stacklevel=1, source=None):
            if isinstance(category, type) and issubclass(
                category, PendingDeprecationWarning
            ):
                stack = traceback.extract_stack()
                # Ignore the warning if any of the known plugins matches
                for frame in stack:
                    if "conda_libmamba_solver" in frame.filename:
                        return
                    if "anaconda_anon_usage" in frame.filename:
                        return

            original_warn(message, category, stacklevel + 1, source)

        warnings.warn = custom_warn


def pytest_collection_modifyitems(config, items):  # type: ignore
    """Auto-mark each test in the integration directory, and enable them based on CLI flag."""
    integration_test_root_dir = Path(__file__).parent / "integration"
    run_integration_tests = config.getoption("--integration")
    for item in items:
        # Here, we add a marker to any test in the "tests/integration" directory
        if integration_test_root_dir in Path(item.fspath).parents:
            item.add_marker(pytest.mark.integration)

        # Add a skip marker if the CLI option is not used. We use an additional marker so that we can
        # independently select integrations with `pytest -m integration` and enable them with `--integration`.
        if "integration" in item.keywords and not run_integration_tests:
            item.add_marker(pytest.mark.skip(reason="need --integration to run"))


@pytest.fixture
def with_aau_token(mocker: MockerFixture) -> None:
    mocker.patch("anaconda_auth.config.AnacondaAuthConfig.aau_token", "anon-token")


@pytest.fixture
def without_aau_token(mocker: MockerFixture) -> None:
    mocker.patch("anaconda_auth.config.AnacondaAuthConfig.aau_token", None)


class MockResponse:
    def __init__(
        self,
        *,
        status_code: int,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.status_code = status_code
        self.json_data = json_data
        self.headers = headers or {}

    def json(self) -> dict[str, Any]:
        return self.json_data or {}


class MockedRequest:
    def __init__(
        self,
        *,
        response_status_code: int,
        response_data: dict[str, Any] | None = None,
        response_headers: dict[str, str] | None = None,
    ) -> None:
        self.response_status_code = response_status_code
        self.response_data = response_data
        self.response_headers = response_headers
        self.called_with_args: tuple[Any] = ()  # type: ignore
        self.called_with_kwargs: dict[str, Any] = {}

    def __call__(self, *args: Any, **kwargs: Any) -> MockResponse:
        self.called_with_args = args  # type: ignore
        self.called_with_kwargs = kwargs
        return MockResponse(
            status_code=self.response_status_code,
            json_data=self.response_data,
            headers=self.response_headers,
        )


class CLIInvoker(Protocol):
    def __call__(
        self,
        # app: typer.Typer,
        args: str | Sequence[str] | None = None,
        input: bytes | str | IO[Any] | None = None,
        env: Mapping[str, str] | None = None,
        catch_exceptions: bool = True,
        color: bool = False,
        **extra: Any,
    ) -> Result: ...


@pytest.fixture()
def invoke_cli(tmp_cwd: Path) -> CLIInvoker:
    """Returns a function, which can be used to call the CLI from within a temporary directory."""

    runner = CliRunner()

    return partial(runner.invoke, cast(typer.Typer, app))


@pytest.fixture
def config_toml(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> Generator[Path, None, None]:
    config_file = tmp_path / "config.toml"
    monkeypatch.setenv("ANACONDA_CONFIG_TOML", str(config_file))
    yield config_file


@pytest.fixture()
def condarc_path(tmp_path):
    """Returns the path of a temporary, empty .condarc file."""
    condarc_path = tmp_path / ".condarc"
    condarc_path.touch()
    yield condarc_path


@pytest.fixture(autouse=is_conda_installed())
def patch_conda_config_to_use_temp_condarc(monkeypatch, condarc_path):
    """Patch operations that modify .condarc to prevent modifying
    the ~/.condarc of the user running the tests.
    """
    from conda.base import context as conda_context
    from conda.base.context import reset_context

    from anaconda_auth._conda import condarc as condarc_module
    from anaconda_auth._conda import repo_config

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
