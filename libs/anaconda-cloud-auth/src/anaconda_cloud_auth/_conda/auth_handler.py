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

from anaconda_cloud_auth.exceptions import TokenNotFoundError
from anaconda_cloud_auth.token import TokenInfo

CLOUD_URI_PREFIX = "/repo/"

try:
    from conda_token import repo_config
except ImportError:
    repo_config = None  # type: ignore


class AnacondaCloudAuthError(CondaError):
    """
    A generic error to raise that is a subclass of CondaError so we don't trigger the unhandled exception traceback.
    """


class AnacondaCloudAuthHandler(ChannelAuthBase):
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
        domain = parsed_url.netloc.lower()
        try:
            token_info = TokenInfo.load(domain)
        except TokenNotFoundError:
            # Fallback to conda-token if the token is not found in the keyring
            return None

        path = parsed_url.path
        if path.startswith(CLOUD_URI_PREFIX):
            path = path[len(CLOUD_URI_PREFIX) :]
        maybe_org, _, _ = path.partition("/")

        # First we attempt to return an organization-specific token
        try:
            return token_info.get_repo_token(maybe_org)
        except TokenNotFoundError:
            pass

        # Return the first one, assuming this is not an org-specific channel
        try:
            return token_info.repo_tokens[0].token
        except KeyError:
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
             AnacondaCloudAuthError: If no token is found using either method.

        """

        # First, we try to load the token from the keyring. If it is not found, we fall through
        if token := self._load_token_from_keyring(url):
            return token
        elif token := self._load_token_via_conda_token(url):
            return token
        else:
            raise AnacondaCloudAuthError(
                f"Token not found for {self.channel_name}. Please install token with "
                "`anaconda cloud token install` or install `conda-token` for legacy usage."
            )

    def handle_invalid_token(self, response: Response, **_: Any) -> Response:
        """Raise a nice error message if the authentication token is invalid (not missing)."""
        if response.status_code == 403:
            raise AnacondaCloudAuthError(
                f"Token is invalid for {self.channel_name}. Please re-install token with "
                "`anaconda cloud token install` or install `conda-token` for legacy usage."
            )
        return response

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        """Inject the token as an Authorization header on each request."""
        request.headers["Authorization"] = f"token {self._load_token(request.url)}"
        request.register_hook("response", self.handle_invalid_token)
        return request
