"""Defines an auth handler to inject an Authorization header into each request.

Tokens are assumed to be installed onto a user's system via a separate CLI command.

"""

from functools import lru_cache
from typing import Any
from typing import NamedTuple
from typing import Optional
from urllib.parse import ParseResult
from urllib.parse import urlparse

from conda import CondaError
from conda.plugins.types import ChannelAuthBase
from requests import PreparedRequest
from requests import Response

from anaconda_auth._conda import repo_config
from anaconda_auth._conda.config import TOKEN_DOMAIN_MAP
from anaconda_auth._conda.config import CredentialType
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.exceptions import TokenNotFoundError
from anaconda_auth.token import TokenInfo

URI_PREFIX = "/repo/"


class AccessCredential(NamedTuple):
    """Represents a typed string containing an access credential (of CredentialType)."""

    # This is essentially a tagged union, which felt lightweight and appropriate for our needs
    value: str
    type: CredentialType


class AnacondaAuthError(CondaError):
    """
    A generic error to raise that is a subclass of CondaError so we don't trigger the unhandled exception traceback.
    """


class AnacondaAuthHandler(ChannelAuthBase):
    def _load_token_domain(self, parsed_url: ParseResult) -> tuple[str, CredentialType]:
        """Select the appropriate domain for token lookup based on a parsed URL.

        We also determine whether to use API key or legacy repo token. This method
        handles a default set of rules, as well as user overrides via conda
        channel_settings.

        """
        channel_domain = parsed_url.netloc.lower()

        # Set defaults for behavior when not overridden by configuration
        token_domain = channel_domain
        credential_type = CredentialType.REPO_TOKEN

        # For specific channel domains, we override the defaults
        if channel_domain in TOKEN_DOMAIN_MAP:
            token_domain, credential_type, _ = TOKEN_DOMAIN_MAP[channel_domain]
        else:
            token_domain, credential_type = channel_domain, CredentialType.REPO_TOKEN

        # Allow users to override default via configuration
        config = AnacondaAuthConfig(domain=token_domain)
        if config.use_unified_repo_api_key:
            credential_type = CredentialType.API_KEY

        return token_domain, credential_type

    def _load_token_from_keyring(self, url: str) -> Optional[AccessCredential]:
        """Attempt to load an appropriate token from the keyring.

        We parse the requested URL, extract what may be an organization ID, and first
        attempt to load the token for that specific organization. If that fails, we
        then simply return the first token in the keyring (since this is in all likelihood
        one of the default channels ('main', 'r', etc.).

        If no token can be found in the keyring, we return None, which means that
        the token will attempt to be read from via conda-token instead.

        """
        parsed_url = urlparse(url)
        token_domain, credential_type = self._load_token_domain(parsed_url)

        try:
            token_info = TokenInfo.load(token_domain)
        except TokenNotFoundError:
            # Fallback to conda-token if the token is not found in the keyring
            return None

        # Check configuration to use unified api key,
        # otherwise continue and attempt to utilize repo token
        if token_info.api_key and credential_type == CredentialType.API_KEY:
            return AccessCredential(token_info.api_key, CredentialType.API_KEY)

        # We attempt to parse the URL and extract the org slug (for repo.anaconda.cloud)
        path = parsed_url.path
        if path.startswith(URI_PREFIX):
            path = path[len(URI_PREFIX) :]
        maybe_org, _, _ = path.partition("/")

        # First we attempt to return an organization-specific token
        try:
            return AccessCredential(
                token_info.get_repo_token(maybe_org), CredentialType.REPO_TOKEN
            )
        except TokenNotFoundError:
            pass

        # Return the first one, assuming this is not an org-specific channel
        try:
            return AccessCredential(
                token_info.repo_tokens[0].token, CredentialType.REPO_TOKEN
            )
        except IndexError:
            pass

        return None

    @staticmethod
    def _load_token_via_conda_token(url: str) -> Optional[AccessCredential]:
        domain = urlparse(url).netloc.lower()
        # Try to load the token via conda-token if that is installed
        if repo_config is not None:
            tokens = repo_config.token_list()
            for token_url, token in tokens.items():
                token_netloc = urlparse(token_url).netloc
                if token_netloc.lower() == domain and token is not None:
                    return AccessCredential(token, CredentialType.REPO_TOKEN)
        return None

    @lru_cache
    def _load_token(self, url: str) -> Optional[AccessCredential]:
        """Load the appropriate token based on URL matching.

        First, attempts to load from the keyring. If that fails, we attempt
        to load the legacy repo token via conda-token.

        Cached for performance.

        Args:
            url: The URL for the request.

        Returns:
             The token, if it can be loaded. None, otherwise.

        """

        # First, we try to load the token from the keyring. If it is not found, we fall through
        if token := self._load_token_from_keyring(url):
            return token
        elif token := self._load_token_via_conda_token(url):
            return token
        return None

    def _build_header(self, url: str) -> Optional[str]:
        """Build the Authorization header based on the request URL.

        The result can vary in terms of "token" vs. "Bearer" as well as whether the
        credential is a legacy repo token or an API key.

        """
        try:
            token = self._load_token(url)
            if token is None:
                return None

            if token.type == CredentialType.REPO_TOKEN:
                return f"token {token.value}"

            return f"Bearer {token.value}"
        except Exception:
            # TODO(mattkram): We need to be very resilient about exceptions here for now
            return None

    def handle_missing_token(self, response: Response, **_: Any) -> Response:
        """Raise a nice error message if the authentication token is missing."""
        if response.status_code in {401, 403}:
            raise AnacondaAuthError(
                f"Token not found for {self.channel_name}. Please install token with "
                "`anaconda token install`."
            )
        return response

    def handle_invalid_token(self, response: Response, **_: Any) -> Response:
        """Raise a nice error message if the authentication token is invalid (not missing)."""
        if response.status_code in {401, 403}:
            raise AnacondaAuthError(
                f"Received authentication error ({response.status_code}) when "
                f"accessing {self.channel_name}. "
                "If your token is invalid or expired, please re-install with "
                "`anaconda token install`."
            )
        return response

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        """Inject the token as an Authorization header on each request."""

        # Technically the request URL may not be set yet
        if request.url is None:
            return request

        header = self._build_header(request.url)

        if not header:
            request.register_hook("response", self.handle_missing_token)
            return request

        request.register_hook("response", self.handle_invalid_token)
        request.headers["Authorization"] = header
        return request
