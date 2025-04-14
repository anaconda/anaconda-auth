import time
from multiprocessing.pool import ThreadPool
from threading import Thread
from typing import Iterator

import pytest
import requests

from anaconda_auth.exceptions import AuthenticationError
from anaconda_auth.handlers import AuthCodeRedirectServer
from anaconda_auth.handlers import capture_auth_code
from anaconda_auth.handlers import shutdown_all_servers

SERVER_PORT = 8123


@pytest.fixture()
def server() -> Iterator[AuthCodeRedirectServer]:
    """Start up the web server responsible for capturing the auth code in a background thread."""
    oidc_path = "/auth/oidc"
    host_name = "localhost"
    server_port = SERVER_PORT

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
        f"http://localhost:{SERVER_PORT}/auth/oidc?code=something&state=some-state"
    )
    assert server.result is not None
    assert server.result.auth_code == "something"
    assert server.result.state == "some-state"

    assert response.status_code == 200
    assert response.url == "https://anaconda.com/app/local-login-success"


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
        f"http://localhost:{SERVER_PORT}/auth/oidc?state=some-state?{query_params}"
    )
    assert response.status_code == 200
    assert response.url == "https://anaconda.com/app/local-login-error"


def test_server_response_not_found(server: AuthCodeRedirectServer) -> None:
    """Return a 404 if the path is not the OIDC path."""
    response = requests.get(
        f"http://localhost:{SERVER_PORT}/auth/oidc2?code=some-code&state=some-state"
    )
    assert response.status_code == 404


def test_shutdown_server_before_completing_authentication() -> None:
    """If e.g. Navigator user starts the auth flow, but tries to close Navigator before finishing, the
    shutdown_all_servers() function can be used to prevent deadlock."""
    with ThreadPool(processes=1) as pool:
        # Start a server in a background thread to capture the auth code
        async_result = pool.apply_async(
            capture_auth_code, ("http://localhost:8000", "random-state")
        )

        # We need to sleep a bit before we can shut down the server
        time.sleep(0.1)

        # Shut it down from the main thread
        shutdown_all_servers()

        # We will have an authentication error because we never captured the code
        with pytest.raises(AuthenticationError):
            async_result.get()

    # If we get this far, we have not hit a deadlock
    assert True
