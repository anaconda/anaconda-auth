import os
from pathlib import Path
from typing import Any

import pytest
from _pytest.monkeypatch import MonkeyPatch
from dotenv import load_dotenv

load_dotenv()

# TODO: Figure out a better way to set these dynamically, and mock out the service
os.environ.setdefault("BASE_URL", "http://test-anaconda.cloud")
os.environ.setdefault("IAM_CLIENT_ID", "test-client-id")
os.environ.setdefault("IAM_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("ORY_AUTH_DOMAIN", "")
os.environ.setdefault("ORY_CLIENT_ID", "test-client-id")


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
