import logging
import uuid
import webbrowser
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Union
from urllib.parse import urlencode

import pkce
import requests

from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.console import console
from anaconda_cloud_auth.exceptions import AuthenticationError
from anaconda_cloud_auth.exceptions import TokenNotFoundError
from anaconda_cloud_auth.handlers import capture_auth_code
from anaconda_cloud_auth.token import TokenInfo

logger = logging.getLogger(__name__)


def _send_auth_code_request(
    client_id: str,
    authorization_endpoint: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
) -> None:
    """Open the authentication flow in the browser."""
    params = dict(
        client_id=client_id,
        response_type="code",
        scope="openid email profile offline_access",
        state=state,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    encoded_params = urlencode(params)
    url = f"{authorization_endpoint}?{encoded_params}"

    logger.debug(f"Opening auth URL: {url}")

    webbrowser.open(url)


def _do_auth_flow(
    token_endpoint: str,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
) -> TokenInfo:
    """Do the auth flow and return the access_token and jwt_token tuple"""

    state = str(uuid.uuid4())

    code_verifier, code_challenge = pkce.generate_pkce_pair(code_verifier_length=128)

    _send_auth_code_request(
        client_id, authorization_endpoint, redirect_uri, state, code_challenge
    )

    # Listen for the response
    auth_code = capture_auth_code(redirect_uri, state)
    logger.debug("Authentication successful! Getting JWT token.")

    # Do auth code exchange
    response = requests.post(
        token_endpoint,
        data=dict(
            grant_type="authorization_code",
            client_id=client_id,
            code=auth_code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        ),
    )
    result = response.json()

    if "error" in result:
        raise AuthenticationError(
            f"Error getting JWT: {result.get('error')} - {result.get('error_description')}"
        )

    access_token = result.get("access_token")
    id_token = result.get("id_token")
    expires_in = result.get("expires_in")
    refresh_token = result.get("refresh_token")
    # TODO: Remove me
    if refresh_token == "HttpOnly":
        refresh_token = response.cookies.get("refresh_token")

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    token_info = TokenInfo(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        id_token=id_token,
    )

    return token_info


def _login_with_username() -> TokenInfo:
    """Prompt for username and password and log in with the password grant flow."""
    auth_config = AuthConfig()
    username = console.input("Please enter your email: ")
    password = console.input("Please enter your password: ", password=True)
    response = requests.post(
        auth_config.oidc.token_endpoint,
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
        },
    )
    response_data = response.json()
    response.raise_for_status()

    access_token = response_data["access_token"]
    refresh_token = response.cookies.get("refresh_token")
    expires_in = response_data["expires_in"]
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    token_info = TokenInfo(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
    )
    token_info.write()
    return token_info


def login(simple: bool = False) -> TokenInfo:
    """Log into Anaconda.cloud and store the token information in the keyring."""
    if simple:
        return _login_with_username()

    auth_config = AuthConfig()
    oidc_config = auth_config.oidc

    if auth_config.client_id is None:
        raise ValueError("A client_id must be specified to use the oauth flow")

    token_info = _do_auth_flow(
        oidc_config.token_endpoint,
        oidc_config.authorization_endpoint,
        auth_config.client_id,
        auth_config.redirect_uri,
    )

    token_info.check()
    token_info.write()
    return token_info


def logout() -> Union[TokenInfo, None]:
    """Log out of Anaconda.cloud."""
    try:
        token_info = TokenInfo.load()
        token_info.delete()
    except TokenNotFoundError:
        return None

    return token_info
