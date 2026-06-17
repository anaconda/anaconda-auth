from __future__ import annotations

import pytest
from pytest_mock import MockerFixture

from anaconda_auth.config import AnacondaAuthSite
from anaconda_auth.config import OpenIDConfiguration
from anaconda_auth.device_flow import DeviceAuthorizationResponse
from anaconda_auth.device_flow import DeviceCodeFlow

from .conftest import SKIP_IF_TRUSTSTORE_UNSUPPORTED
from .conftest import MockedRequest

DEVICE_AUTH_RESPONSE = {
    "device_code": "device-code",
    "user_code": "USER-CODE",
    "verification_uri": "https://anaconda.com/device",
    "verification_uri_complete": "https://anaconda.com/device?code=USER-CODE",
    "expires_in": 60,
    "interval": 5,
}


@pytest.fixture()
def oidc_config(mocker: MockerFixture) -> None:
    """Avoid the network round-trip to the well-known OIDC document."""
    oidc = OpenIDConfiguration(
        authorization_endpoint="https://auth.anaconda.com/authorize",
        token_endpoint="https://auth.anaconda.com/token",
        device_authorization_endpoint="https://auth.anaconda.com/device",
    )
    mocker.patch(
        "anaconda_auth.config.AnacondaAuthSite.oidc",
        new_callable=mocker.PropertyMock,
        return_value=oidc,
    )


@pytest.mark.parametrize(
    "ssl_verify, expected_verify",
    [
        pytest.param(
            "truststore", True, id="truststore", marks=SKIP_IF_TRUSTSTORE_UNSUPPORTED
        ),
        pytest.param(True, True, id="true"),
        pytest.param(False, False, id="false"),
    ],
)
@pytest.mark.usefixtures("oidc_config")
def test_initiate_device_authorization_forwards_resolved_verify(
    mocker: MockerFixture,
    ssl_verify: bool | str,
    expected_verify: bool,
) -> None:
    """The device-authorization request must use the resolved `verify`, not the raw
    `ssl_verify` config. With `truststore` the literal string was forwarded and
    requests raised `invalid path: truststore`. Regression test."""
    mocked_request = MockedRequest(
        response_status_code=200, response_data=DEVICE_AUTH_RESPONSE
    )
    mocker.patch("requests.Session.request", mocked_request)

    config = AnacondaAuthSite(ssl_verify=ssl_verify)
    flow = DeviceCodeFlow(config=config)
    flow.initiate_device_authorization()

    assert mocked_request.called_with_kwargs["verify"] == expected_verify


@pytest.mark.parametrize(
    "ssl_verify, expected_verify",
    [
        pytest.param(
            "truststore", True, id="truststore", marks=SKIP_IF_TRUSTSTORE_UNSUPPORTED
        ),
        pytest.param(True, True, id="true"),
        pytest.param(False, False, id="false"),
    ],
)
@pytest.mark.usefixtures("oidc_config")
def test_request_token_forwards_resolved_verify(
    mocker: MockerFixture,
    ssl_verify: bool | str,
    expected_verify: bool,
) -> None:
    """The token-polling request must likewise forward the resolved `verify`."""
    mocked_request = MockedRequest(
        response_status_code=200, response_data={"access_token": "access-token"}
    )
    mocker.patch("requests.Session.request", mocked_request)

    config = AnacondaAuthSite(ssl_verify=ssl_verify)
    flow = DeviceCodeFlow(config=config)
    flow.authorize_response = DeviceAuthorizationResponse(**DEVICE_AUTH_RESPONSE)
    flow._request_token()

    assert mocked_request.called_with_kwargs["verify"] == expected_verify
