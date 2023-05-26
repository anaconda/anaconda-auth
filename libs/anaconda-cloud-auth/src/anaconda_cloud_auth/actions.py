import base64
import hashlib
import logging
import uuid
import webbrowser
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Optional
from urllib.parse import urlencode

import jwt
import pkce
import requests
import typer
from requests.auth import HTTPBasicAuth

from anaconda_cloud_cli import console

from anaconda_cloud_auth.config import get_config
from anaconda_cloud_auth.handlers import run_server
from anaconda_cloud_auth.jwt import OryJWKClient
from anaconda_cloud_auth.token import TokenInfo
from anaconda_cloud_auth.token import TokenNotFoundError

logger = logging.getLogger(__name__)


def _validate_access_token(
    access_token: str, algorithm_used: str, expected_hash: str
) -> None:
    """Validate the JWT token.

    We need to compute the hash of the access token and compare it with the hash that is present in the JWT.
    This is to ensure that the token is not tampered with.

    """

    # Get the standard name for the hash alg instead of the OIDC name
    hashlib_alg_name = jwt.get_algorithm_by_name(algorithm_used).hash_alg.name  # type: ignore

    hash = hashlib.new(hashlib_alg_name)
    hash.update(access_token.encode("utf-8"))
    digest = hash.digest()

    # The left half of the total hash contains the expected hash we are
    # looking for.
    # See https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.6
    digest_truncated = digest[: (len(digest) // 2)]

    # digest_truncated is bytes, so we decode and remove the == padding in base64
    computed_hash = (
        base64.urlsafe_b64encode(digest_truncated).decode("utf-8").rstrip("=")
    )

    if computed_hash != expected_hash:
        raise jwt.InvalidSignatureError()


def _validate_token_info(token_info: TokenInfo) -> None:
    if token_info.id_token is None:
        # TODO: legacy IAM doesn't work w/ these validations
        return

    config = get_config()
    jwks_client = OryJWKClient(config.oidc.jwks_uri)
    signing_key = jwks_client.get_signing_key_from_jwt(token_info.id_token)

    try:
        # parse JWT token and verify signature
        id_info = jwt.decode(
            token_info.id_token,
            key=signing_key.key,
            algorithms=config.oidc.id_token_signing_alg_values_supported,
            audience=config.client_id,
        )
    except jwt.exceptions.PyJWTError as e:
        raise typer.Abort(f"Error decoding token: {e}")

    # at this point, the jwt token should be verified and good to go
    # but we still need to verify the access token
    algorithm_used = jwt.get_unverified_header(token_info.id_token)["alg"]

    if token_info.access_token is None:
        raise typer.Abort("No access token found to validate")

    try:
        _validate_access_token(
            token_info.access_token, algorithm_used, id_info["at_hash"]
        )
    except jwt.InvalidSignatureError:
        raise typer.Abort("Access token has an invalid hash.")
    except Exception:
        raise typer.Abort()


def _send_auth_code_request(
    client_id: str,
    authorization_endpoint: str,
    redirect_uri: str,
    state: str,
    code_challenge: Optional[str],
) -> None:
    """Open the authentication flow in the browser."""
    params = dict(
        client_id=client_id,
        response_type="code",
        scope="openid email profile offline_access",
        state=state,
        redirect_uri=redirect_uri,
    )

    if code_challenge is not None:
        params.update(dict(code_challenge=code_challenge, code_challenge_method="S256"))

    encoded_params = urlencode(params)
    url = f"{authorization_endpoint}?{encoded_params}"

    logger.debug(f"Opening auth URL: {url}")

    webbrowser.open(url)


def _do_auth_flow(
    token_endpoint: str,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    client_secret: Optional[str] = None,
) -> TokenInfo:
    """Do the auth flow and return the access_token and jwt_token tuple"""

    state = str(uuid.uuid4())

    if not client_secret:
        # The code challenge is crucial to prevent man-in-the-middle
        # attacks for desktop OAuth2 applications.
        #
        # To use the code challenge, you must set the
        # token_endpoint_auth_method to None in Ory. In the web ui, it's
        # Client authentication mechanism > Authentication Method > None
        code_verifier, code_challenge = pkce.generate_pkce_pair(
            code_verifier_length=128
        )
    else:
        code_verifier, code_challenge = None, None

    _send_auth_code_request(
        client_id, authorization_endpoint, redirect_uri, state, code_challenge
    )

    # Listen for the response
    res = run_server(redirect_uri)

    if res.state != state or not res.auth_code:
        raise typer.Abort(
            "State does not match or does not include an authorization code."
        )

    logger.debug("Authentication successful! Getting JWT token.")

    # Do auth code exchange
    data = dict(
        grant_type="authorization_code",
        client_id=client_id,
        code=res.auth_code,
        redirect_uri=redirect_uri,
    )

    if code_verifier is None:
        if client_secret is None:
            raise ValueError("Client secret must be set if no code_verifier used")
        auth = HTTPBasicAuth("", client_secret)
        response = requests.post(token_endpoint, data=data, auth=auth)
        result = response.json()
        refresh_token = response.cookies.get("refresh_token")
    else:
        data["code_verifier"] = code_verifier
        response = requests.post(token_endpoint, data=data)
        result = response.json()
        refresh_token = result.get("refresh_token")

    if "error" in result:
        raise typer.Abort(
            f"Error getting JWT: {result.get('error')} - {result.get('error_description')}"
        )

    access_token = result.get("access_token")
    id_token = result.get("id_token")
    expires_in = result.get("expires_in")

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    token_info = TokenInfo(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        id_token=id_token,
    )

    return token_info


def _refresh_access_token(token_info: TokenInfo) -> TokenInfo:
    """Refresh the access token and save to the keyring."""
    config = get_config()
    response = requests.post(
        config.oidc.token_endpoint,
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_info.refresh_token,
            "client_id": config.client_id,
        },
    )
    response_data = response.json()

    new_access_token = response_data["access_token"]
    new_refresh_token = response_data["refresh_token"]
    new_id_token = response_data.get("id_token")
    new_expires_in = response_data["expires_in"]
    new_expires_at = datetime.now(timezone.utc) + timedelta(seconds=new_expires_in)

    new_token_info = TokenInfo(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_at=new_expires_at,
        id_token=new_id_token,
    )
    new_token_info.write()
    return new_token_info


def _login_with_username() -> TokenInfo:
    """Prompt for username and password and log in with the password grant flow."""
    config = get_config(use_ory=False)
    username = console.input("Please enter your email: ")
    password = console.input("Please enter your password: ", password=True)
    response = requests.post(
        config.oidc.token_endpoint,
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
        },
    )
    response_data = response.json()

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


def login(use_ory: bool = False, simple: bool = False) -> TokenInfo:
    """Log into Anaconda.cloud and store the token information in the keyring."""
    if use_ory and simple:
        raise ValueError("Cannot select both --ory and --simple")

    if simple:
        return _login_with_username()

    try:
        TokenInfo.load()
    except TokenNotFoundError:
        pass  # Proceed to login
    else:
        force_login = typer.confirm(
            "You are already logged in. Would you like to force a new login?"
        )
        if not force_login:
            raise typer.Exit()

    config = get_config(use_ory=use_ory)
    oidc_config = config.oidc

    if config.client_id is None:
        raise ValueError("A client_id must be specified to use the oauth flow")

    token_info = _do_auth_flow(
        oidc_config.token_endpoint,
        oidc_config.authorization_endpoint,
        config.client_id,
        config.redirect_uri,
        client_secret=config.client_secret,
    )

    token_info.check()
    token_info.write()
    return token_info


def logout() -> TokenInfo | None:
    """Log out of Anaconda.cloud."""
    try:
        token_info = TokenInfo.load()
        token_info.delete()
    except TokenNotFoundError:
        return None

    return token_info
