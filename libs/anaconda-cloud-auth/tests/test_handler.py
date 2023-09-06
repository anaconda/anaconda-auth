from threading import Thread
from typing import Iterator

import pytest
import requests

from anaconda_cloud_auth.handlers import AuthCodeRedirectServer


@pytest.fixture()
def server() -> Iterator[AuthCodeRedirectServer]:
    """Start up the web server responsible for capturing the auth code in a background thread."""
    oidc_path = "/auth/oidc"
    host_name = "localhost"
    server_port = 8080

    server = AuthCodeRedirectServer(oidc_path, (host_name, server_port))

    def _f() -> None:
        with server:
            server.handle_request()

    t = Thread(target=_f, daemon=True)
    t.start()
    yield server


def test_server_response_success(server: AuthCodeRedirectServer) -> None:
    """The server captures the query parameters and then redirects to the success page."""
    # Make the request and ensure the code is captured by the server
    response = requests.get(
        "http://localhost:8080/auth/oidc?code=something&state=some-state"
    )
    assert server.result is not None
    assert server.result.auth_code == "something"
    assert server.result.state == "some-state"

    assert response.status_code == 200
    assert response.url == "https://anaconda.cloud/local-login-success"


@pytest.mark.parametrize(
    "query_params",
    [
        pytest.param("state=some-state", id="missing-code"),
        pytest.param("code=something", id="missing-state"),
    ],
)
def test_server_response_error(
    server: AuthCodeRedirectServer, query_params: str
) -> None:
    """We redirect to the error page if we forget the code or state parameters."""
    response = requests.get(
        f"http://localhost:8080/auth/oidc?state=some-state?{query_params}"
    )
    assert response.status_code == 200
    assert response.url == "https://anaconda.cloud/local-login-error"


def test_server_response_not_found(server: AuthCodeRedirectServer) -> None:
    """Return a 404 if the path is not the OIDC path."""
    response = requests.get(
        "http://localhost:8080/auth/oidc2?code=some-code&state=some-state"
    )
    assert response.status_code == 404
