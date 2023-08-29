import os
from collections import defaultdict
from pathlib import Path
from typing import Any
from typing import Union

import pytest
from _pytest.monkeypatch import MonkeyPatch
from dotenv import load_dotenv
from keyring.backend import KeyringBackend
from pytest_mock import MockerFixture

from anaconda_cloud_auth import config
from anaconda_cloud_auth import login
from anaconda_cloud_auth.client import BaseClient
from anaconda_cloud_auth.console import console
from anaconda_cloud_auth.token import TokenInfo

load_dotenv()


class MockedKeyring(KeyringBackend):
    """A high-priority in-memory keyring backend for testing"""

    priority = 10000.0  # type: ignore
    _data: dict = defaultdict(dict)

    def __init__(self) -> None:
        super().__init__()

    def set_password(self, service: str, username: str, password: str) -> None:
        self._data[service][username] = password

    def get_password(self, service: str, username: str) -> Union[str, None]:
        password = self._data.get(service, {}).get(username, None)
        return password

    def delete_password(self, service: str, username: str) -> None:
        _ = self._data.get(service, {}).pop(username)


@pytest.fixture(autouse=True)
def clear_mocked_keyring() -> None:
    MockedKeyring._data = defaultdict(dict)


@pytest.fixture(autouse=True)
def set_keyring_name(mocker: MockerFixture) -> None:
    mocker.patch("anaconda_cloud_auth.token.KEYRING_NAME", "Anaconda Cloud Test")


@pytest.fixture
def outdated_token_info() -> TokenInfo:
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
    return TokenInfo(api_key=api_key, domain="mocked-domain")


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
def disable_dot_env(monkeypatch: MonkeyPatch) -> None:
    from anaconda_cloud_auth.config import APIConfig
    from anaconda_cloud_auth.config import AuthConfig

    monkeypatch.setattr(APIConfig.Config, "env_file", "")
    monkeypatch.setattr(AuthConfig.Config, "env_file", "")


@pytest.fixture()
def integration_test_client(monkeypatch: MonkeyPatch) -> BaseClient:
    """Provides a request client configured to talk to the automation environment.

    We first load credentials from environment variables. We then use a special
    user credential to generate an API key via basic login. Finally, we patch
    the configuration and clients such that CloudFlare headers are included and
    the domains match the automation environment.

    """
    if (email := os.getenv("TEST_AUTOMATION_USER_EMAIL")) is None:
        raise ValueError(
            "TEST_AUTOMATION_USER_EMAIL must be specified as an environment variable or in `.env`"
        )
    if (password := os.getenv("TEST_AUTOMATION_USER_PASSWORD")) is None:
        raise ValueError(
            "TEST_AUTOMATION_USER_PASSWORD must be specified as an environment variable or in `.env`"
        )

    monkeypatch.setenv(
        "ANACONDA_CLOUD_AUTH_DOMAIN", "nucleus-automation.anacondaconnect.com/api/iam"
    )
    monkeypatch.setenv(
        "ANACONDA_CLOUD_API_DOMAIN", "nucleus-automation.anacondaconnect.com"
    )
    monkeypatch.setenv(
        "ANACONDA_CLOUD_AUTH_CLIENT_ID", "e0648d7e-72c1-4159-b7e8-5d020ac134c2"
    )

    # Here, we store Cloudflare headers to allow use of Warp from GitHub Actions runners.
    # These are stored as secrets in Vault.
    if client_id := os.getenv("CF_CLIENT_ID"):
        monkeypatch.setitem(
            config.OIDC_REQUEST_HEADERS, "CF-Access-Client-Id", client_id
        )
    if client_secret := os.getenv("CF_CLIENT_SECRET"):
        monkeypatch.setitem(
            config.OIDC_REQUEST_HEADERS, "CF-Access-Client-Secret", client_secret
        )

    def mock_input(msg: str, **kwargs: Any) -> str:
        """Mock the input function to mimic user entry."""
        if msg == "Please enter your email: ":
            return email
        elif msg == "Please enter your password: ":
            return password
        else:
            raise ValueError(f"Unknown input statement: {msg}")

    monkeypatch.setattr(console, "input", mock_input)

    login(basic=True)

    client = BaseClient()
    if client_id:
        client.headers["CF-Access-Client-Id"] = client_id
    if client_secret:
        client.headers["CF-Access-Client-Secret"] = client_secret

    return client


def pytest_addoption(parser):  # type: ignore
    """Defines custom CLI options."""
    parser.addoption(
        "--integration",
        action="store_true",
        dest="integration",
        default=False,
        help="enable integration tests",
    )


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
