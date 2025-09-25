import logging
import uuid
import warnings
import webbrowser
from typing import Optional
from urllib.parse import urlencode

import pkce
import requests

from anaconda_auth import __version__
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.device_flow import DeviceCodeFlow
from anaconda_auth.exceptions import AuthenticationError
from anaconda_auth.exceptions import DeviceFlowDenied
from anaconda_auth.exceptions import DeviceFlowError
from anaconda_auth.exceptions import DeviceFlowTimeout
from anaconda_auth.exceptions import TokenNotFoundError
from anaconda_auth.handlers import capture_auth_code
from anaconda_auth.token import TokenInfo
from anaconda_cli_base.console import console

logger = logging.getLogger(__name__)


def make_auth_code_request_url(
    code_challenge: str, state: str, config: Optional[AnacondaAuthConfig] = None
) -> str:
    """Build the authorization code request URL."""

    if config is None:
        config = AnacondaAuthConfig()

    authorization_endpoint = config.oidc.authorization_endpoint
    client_id = config.client_id
    redirect_uri = config.redirect_uri

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

    return url


def _send_auth_code_request(
    code_challenge: str, state: str, config: AnacondaAuthConfig
) -> None:
    """Open the authentication flow in the browser."""
    url = make_auth_code_request_url(code_challenge, state, config)
    webbrowser.open(url)


def refresh_access_token(refresh_token: str, config: AnacondaAuthConfig) -> str:
    """Refresh and save the tokens."""
    response = requests.post(
        config.oidc.token_endpoint,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": config.client_id,
        },
        verify=config.ssl_verify,
    )
    response.raise_for_status()
    response_data = response.json()

    access_token = response_data["access_token"]
    return access_token


def request_access_token(
    auth_code: str, code_verifier: str, config: AnacondaAuthConfig
) -> str:
    """Request an access token using the provided authorization code and code verifier."""
    token_endpoint = config.oidc.token_endpoint
    client_id = config.client_id
    redirect_uri = config.redirect_uri

    response = requests.post(
        token_endpoint,
        data=dict(
            grant_type="authorization_code",
            client_id=client_id,
            code=auth_code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        ),
        verify=config.ssl_verify,
    )
    result = response.json()

    if "error" in result:
        raise AuthenticationError(
            f"Error getting JWT: {result.get('error')} - {result.get('error_description')}"
        )

    access_token = result.get("access_token")
    return access_token


def _do_device_flow(config: Optional[AnacondaAuthConfig] = None) -> None:
    """Login using OAuth 2.0 device code flow."""
    config = config or AnacondaAuthConfig()

    # Initialize device flow
    device_flow = DeviceCodeFlow(
        auth_url="http://localhost/api/auth",
        client_id=config.client_id,
        ssl_verify=config.ssl_verify,
    )

    try:
        # Step 1: Initiate device authorization
        print("Initiating device authorization...")
        user_code, verification_uri = device_flow.initiate_device_authorization()

        # Step 2: Display instructions to user
        _display_device_instructions(user_code, verification_uri, device_flow)

        # Step 3: Poll for token
        print("\nWaiting for authorization...")
        print("(You can cancel by pressing Ctrl+C)")

        token_response = device_flow.poll_for_token()

        # return access token
        return token_response["access_token"]

        print("✓ Login successful!")

    except DeviceFlowTimeout:
        print("❌ Authorization timed out. Please try again.")
        raise
    except DeviceFlowDenied:
        print("❌ Authorization was denied.")
        raise
    except KeyboardInterrupt:
        print("\n❌ Login cancelled by user.")
        raise
    except DeviceFlowError as e:
        print(f"❌ Login failed: {e}")
        raise


def _display_device_instructions(
    user_code: str, verification_uri: str, device_flow: DeviceCodeFlow
) -> None:
    """Display device authorization instructions to the user."""
    print("\n" + "=" * 60)
    print("DEVICE AUTHORIZATION REQUIRED")
    print("=" * 60)

    complete_uri = device_flow.get_complete_verification_uri()

    if complete_uri:
        print("1. Open this URL in your browser:")
        print(f"   {complete_uri}")
        print("\n2. The code should be pre-filled, just approve the request")

        # Try to open browser automatically
        try:
            webbrowser.open(complete_uri)
            print("   (Browser should open automatically)")
        except Exception:
            pass

    else:
        print("1. Open this URL in your browser:")
        print(f"   {verification_uri}")
        print(f"\n2. Enter this code: {user_code}")
        print(f"   (Code: {user_code})")

        # Try to open browser automatically
        try:
            webbrowser.open(verification_uri)
            print("   (Browser should open automatically)")
        except Exception:
            pass

    print("\n3. Complete the authorization in your browser")
    print("=" * 60)


def _do_auth_flow(config: Optional[AnacondaAuthConfig] = None) -> str:
    """Do the browser-based auth flow and return the short-lived access_token and id_token tuple."""
    config = config or AnacondaAuthConfig()

    state = str(uuid.uuid4())
    code_verifier, code_challenge = pkce.generate_pkce_pair(code_verifier_length=128)

    _send_auth_code_request(code_challenge, state, config)

    # Listen for the response
    auth_code = capture_auth_code(config.redirect_uri, state=state, config=config)
    logger.debug("Authentication successful! Getting JWT token.")

    # Do auth code exchange
    return request_access_token(auth_code, code_verifier, config)


def _login_with_username(config: Optional[AnacondaAuthConfig] = None) -> str:
    """Prompt for username and password and log in with the password grant flow."""
    warnings.warn(
        "Basic login with username/password is deprecated and will be disabled soon.",
        UserWarning,
        stacklevel=0,
    )

    if config is None:
        config = AnacondaAuthConfig()

    username = console.input("Please enter your email: ")
    password = console.input("Please enter your password: ", password=True)
    response = requests.post(
        config.oidc.token_endpoint,
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
        },
        verify=config.ssl_verify,
    )
    response_data = response.json()
    response.raise_for_status()

    access_token = response_data["access_token"]
    return access_token


def _do_login(config: AnacondaAuthConfig, basic: bool) -> None:
    if basic:
        access_token = _login_with_username(config=config)
    elif True:
        access_token = _do_device_flow(config=config)
    else:
        access_token = _do_auth_flow(config=config)
    api_key = get_api_key(access_token, config.ssl_verify)
    token_info = TokenInfo(api_key=api_key, domain=config.domain)
    token_info.save()


def get_api_key(
    access_token: str,
    ssl_verify: bool = True,
    config: Optional[AnacondaAuthConfig] = None,
) -> str:
    config = config or AnacondaAuthConfig()

    headers = {"Authorization": f"Bearer {access_token}"}

    aau_token = config.aau_token
    if aau_token is not None:
        headers["X-AAU-CLIENT"] = aau_token

    # Retry logic until we stabilize on new API
    urls = [
        f"https://{config.auth_domain}/api/auth/api-keys",
        f"https://{config.domain}/api/iam/api-keys",
    ]
    for url in urls:
        response = requests.post(
            url,
            json=dict(
                scopes=["cloud:read", "cloud:write", "repo:read"],
                tags=[f"anaconda-auth/v{__version__}"],
            ),
            headers=headers,
            verify=ssl_verify,
        )
        if response.status_code == 201:
            break
    else:
        console.print("Error retrieving an API key")
        raise AuthenticationError
    return response.json()["api_key"]


def _api_key_is_valid(config: AnacondaAuthConfig) -> bool:
    try:
        valid = not TokenInfo.load(config.domain).expired
    except TokenNotFoundError:
        valid = False

    return valid


def login(
    config: Optional[AnacondaAuthConfig] = None,
    basic: bool = False,
    force: bool = False,
    ssl_verify: bool = True,
) -> None:
    """Log into anaconda.com and store the token information in the keyring."""
    if config is None:
        config = AnacondaAuthConfig(ssl_verify=ssl_verify)

    if force or not _api_key_is_valid(config=config):
        _do_login(config=config, basic=basic)


def logout(config: Optional[AnacondaAuthConfig] = None) -> None:
    """Log out of anaconda.com."""
    if config is None:
        config = AnacondaAuthConfig()

    try:
        token_info = TokenInfo.load(domain=config.domain)
        token_info.delete()
    except TokenNotFoundError:
        pass

    if config.domain != "anaconda.com":
        # Since anaconda.com is the default, don't do anything special if
        # User explicitly overrode the configured domain.
        return

    # If the request was for anaconda.com (the default), also remove
    # anaconda.cloud if it exists. This is just an edge case for the
    # likely rare scenario where a user has a stored token for both
    # domains.
    try:
        token_info = TokenInfo.load(domain="anaconda.cloud")
        token_info.delete()
    except TokenNotFoundError:
        pass


def is_logged_in() -> bool:
    config = AnacondaAuthConfig()
    try:
        token_info = TokenInfo.load(domain=config.domain)
    except TokenNotFoundError:
        token_info = None

    return token_info is not None
