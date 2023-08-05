from collections import defaultdict
from pathlib import Path
from typing import Any
from typing import Union

import pytest
from _pytest.monkeypatch import MonkeyPatch
from keyring.backend import KeyringBackend
from pytest_mock import MockerFixture

from anaconda_cloud_auth.token import TokenInfo


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
