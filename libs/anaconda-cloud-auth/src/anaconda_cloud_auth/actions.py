import base64
import hashlib
import logging
import uuid
import webbrowser
from typing import Optional
from typing import Union
from urllib.parse import urlencode

import jwt
import requests

from anaconda_cloud_auth._vendor import pkce
from anaconda_cloud_auth.config import APIConfig
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.console import console
from anaconda_cloud_auth.exceptions import AuthenticationError
from anaconda_cloud_auth.exceptions import InvalidTokenError
from anaconda_cloud_auth.exceptions import TokenNotFoundError
from anaconda_cloud_auth.handlers import capture_auth_code
from anaconda_cloud_auth.jwt import JWKClient
from anaconda_cloud_auth.token import TokenInfo

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


def _validate_token_info(access_token: str, id_token: Optional[str]) -> None:
    if id_token is None:
        # TODO: legacy IAM doesn't work w/ these validations
        return

    auth_config = AuthConfig()
    jwks_client = JWKClient(auth_config.oidc.jwks_uri)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    try:
        # parse JWT token and verify signature
        id_info = jwt.decode(
            id_token,
            key=signing_key.key,
            algorithms=auth_config.oidc.id_token_signing_alg_values_supported,
            audience=auth_config.client_id,
        )
    except jwt.exceptions.PyJWTError as e:
        raise InvalidTokenError(f"Error decoding token: {e}")

    # at this point, the jwt token should be verified and good to go
    # but we still need to verify the access token
    algorithm_used = jwt.get_unverified_header(id_token)["alg"]

    if access_token is None:
        raise TokenNotFoundError("No access token found to validate")

    try:
        _validate_access_token(access_token, algorithm_used, id_info["at_hash"])
    except jwt.InvalidSignatureError:
        raise InvalidTokenError("Access token has an invalid hash.")


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


def _do_auth_flow() -> str:
    """Do the browser-based auth flow and return the short-lived access_token and id_token tuple."""
    auth_config = AuthConfig()

    token_endpoint = auth_config.oidc.token_endpoint
    authorization_endpoint = auth_config.oidc.authorization_endpoint
    client_id = auth_config.client_id
    redirect_uri = auth_config.redirect_uri
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

    _validate_token_info(access_token, id_token)

    return access_token


def _login_with_username() -> str:
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
    return access_token


def _get_api_key(access_token: str) -> str:
    config = APIConfig()
    response = requests.post(
        f"https://{config.domain}/api/iam/api-keys",
        json=dict(scopes=["cloud:read", "cloud:write"]),
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if response.status_code != 201:
        console.print("Error retrieving an API key")
        raise AuthenticationError
    return response.json()["api_key"]


def login(simple: bool = False) -> TokenInfo:
    """Log into Anaconda.cloud and store the token information in the keyring."""
    if simple:
        access_token = _login_with_username()
    else:
        access_token = _do_auth_flow()
    api_key = _get_api_key(access_token)
    token_info = TokenInfo(api_key=api_key)
    token_info.save()
    return token_info


def logout() -> Union[TokenInfo, None]:
    """Log out of Anaconda.cloud."""
    try:
        token_info = TokenInfo.load()
        token_info.delete()
    except TokenNotFoundError:
        return None

    return token_info
