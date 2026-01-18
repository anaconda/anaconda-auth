import warnings

import pytest

from anaconda_auth.async_client import AsyncBaseClient

from .conftest import MockedRequest
from .conftest import MockResponse


@pytest.fixture()
def mocked_request(mocker):
    """A mocked request, returning a custom response."""

    mocked_request = MockedRequest(response_status_code=200)
    mocker.patch("requests.Session.request", mocked_request)


@pytest.fixture()
def mocked_arequest(mocker):
    """A mocked request, returning a custom response."""

    async def mocked_request(*args, **kwargs):
        return MockResponse(status_code=200, headers={"Min-Api-Version": "2023.02.02"})

    mocker.patch("httpx.AsyncClient.request", mocked_request)


@pytest.mark.usefixtures("mocked_arequest")
@pytest.mark.usefixtures("mocked_request")
@pytest.mark.parametrize(
    "api_version, warning_expected", [("2023.01.01", True), ("2023.03.01", False)]
)
@pytest.mark.asyncio
async def test_client_min_api_version_header(
    api_version: str, warning_expected: bool
) -> None:
    client = AsyncBaseClient(user_agent="client/0.1.0", api_version=api_version)
    assert isinstance(client.account, dict)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("default")
        response = await client.get("/api/something")

    assert response.status_code == 200
    assert response.headers.get("Min-Api-Version") == "2023.02.02"

    if warning_expected:
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert (
            "Client API version is 2023.01.01, minimum supported API version is 2023.02.02. "
            "You may need to update your client." == str(w[0].message)
        )
    else:
        assert len(w) == 0
