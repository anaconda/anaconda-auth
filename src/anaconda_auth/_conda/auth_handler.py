"""Defines an auth handler to inject an Authorization header into each request.

Tokens are assumed to be installed onto a user's system via a separate CLI command.

"""

from functools import lru_cache
from typing import Any
from typing import Optional
from urllib.parse import urlparse

from conda import CondaError
from conda.plugins.types import ChannelAuthBase
from requests import PreparedRequest
from requests import Response

from anaconda_auth._conda import repo_config
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.exceptions import TokenNotFoundError
from anaconda_auth.token import TokenInfo

URI_PREFIX = "/repo/"

# If the channel netloc matches the key, we look for a token stored under the value
TOKEN_DOMAIN_MAP = {"repo.anaconda.cloud": "anaconda.com"}


class AnacondaAuthError(CondaError):
    """
    A generic error to raise that is a subclass of CondaError so we don't trigger the unhandled exception traceback.
    """


class AnacondaAuthHandler(ChannelAuthBase):
    @staticmethod
    def _load_token_from_keyring(url: str) -> Optional[str]:
        """Attempt to load an appropriate token from the keyring.

        We parse the requested URL, extract what may be an organization ID, and first
        attempt to load the token for that specific organization. If that fails, we
        then simply return the first token in the keyring (since this is in all likelihood
        one of the default channels ('main', 'r', etc.).

        If no token can be found in the keyring, we return None, which means that
        the token will attempt to be read from via conda-token instead.

        """
        parsed_url = urlparse(url)
        channel_domain = parsed_url.netloc.lower()
        token_domain = TOKEN_DOMAIN_MAP.get(channel_domain, channel_domain)
        config = AnacondaAuthConfig()

        try:
            token_info = TokenInfo.load(token_domain)
        except TokenNotFoundError:
            # Fallback to conda-token if the token is not found in the keyring
            return None

        path = parsed_url.path
        if path.startswith(URI_PREFIX):
            path = path[len(URI_PREFIX) :]
        maybe_org, _, _ = path.partition("/")

        # Check configuration to use unified api key,
        #   otherwise continue and attempt to utilize repo token
        api_key = token_info.api_key
        if api_key and config.use_unified_repo_api_key and isinstance(api_key, str):
            return api_key

        # First we attempt to return an organization-specific token
        try:
            return token_info.get_repo_token(maybe_org)
        except TokenNotFoundError:
            pass

        # Return the first one, assuming this is not an org-specific channel
        try:
            return token_info.repo_tokens[0].token
        except IndexError:
            pass

        return None

    @staticmethod
    def _load_token_via_conda_token(url: str) -> Optional[str]:
        domain = urlparse(url).netloc.lower()
        # Try to load the token via conda-token if that is installed
        if repo_config is not None:
            tokens = repo_config.token_list()
            for token_url, token in tokens.items():
                token_netloc = urlparse(token_url).netloc
                if token_netloc.lower() == domain and token is not None:
                    return token
        return None

    @lru_cache
    def _load_token(self, url: str) -> str:
        """Load the appropriate token based on URL matching.

        First, attempts to load from the keyring. If that fails, we attempt
        to load the legacy repo token via conda-token.

        Cached for performance.

        Args:
            url: The URL for the request.

        Raises:
             AnacondaAuthError: If no token is found using either method.

        """

        # First, we try to load the token from the keyring. If it is not found, we fall through
        if token := self._load_token_from_keyring(url):
            return token
        elif token := self._load_token_via_conda_token(url):
            return token
        else:
            raise AnacondaAuthError(
                f"Token not found for {self.channel_name}. Please install token with "
                "`anaconda token install`."
            )

    def handle_invalid_token(self, response: Response, **_: Any) -> Response:
        """Raise a nice error message if the authentication token is invalid (not missing)."""
        if response.status_code == 403:
            raise AnacondaAuthError(
                f"Received authentication error (403) when accessing {self.channel_name}. "
                "If your token is invalid or expired, please re-install with "
                "`anaconda token install`."
            )
        return response

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        """Inject the token as an Authorization header on each request."""
        request.register_hook("response", self.handle_invalid_token)
        token = self._load_token(request.url)

        config = AnacondaAuthConfig()
        if config.use_unified_repo_api_key:
            request.headers["Authorization"] = f"Bearer {token}"
        else:
            request.headers["Authorization"] = f"token {token}"

        return request
