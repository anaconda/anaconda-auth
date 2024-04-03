"""Defines an auth handler to inject an Authorization header into each request.

Tokens are assumed to be installed onto a user's system via a separate CLI command.

"""

from functools import cached_property
from typing import Any
from typing import Optional
from urllib.parse import urlparse

from conda import CondaError
from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase
from requests import PreparedRequest
from requests import Response

from anaconda_cloud_auth.exceptions import TokenNotFoundError
from anaconda_cloud_auth.token import TokenInfo

try:
    from conda_token import repo_config
except ImportError:
    repo_config = None  # type: ignore


class AnacondaCloudAuthError(CondaError):
    """
    A generic error to raise that is a subclass of CondaError so we don't trigger the unhandled exception traceback.
    """


def _get_domain_for_channel(channel_name: str) -> str:
    if channel_name == "defaults":
        # For defaults, we require that the domain for all defaults channels is the same
        default_urls = Channel("defaults").urls()
        domains = [urlparse(url).netloc.lower() for url in default_urls]
        if len(set(domains)) != 1:
            raise AnacondaCloudAuthError(
                "defaults cannot be used with multiple domains"
            )
        domain, *_ = domains
    else:
        # Handle a general URL-based channel name
        channel_url = urlparse(channel_name)
        domain = channel_url.netloc.lower()
    return domain


class AnacondaCloudAuthHandler(ChannelAuthBase):
    @staticmethod
    def _load_token_from_keyring(domain: str) -> Optional[str]:
        try:
            token_info = TokenInfo.load(domain)
        except TokenNotFoundError:
            pass  # Fallback to conda-token if the token is not found in the keyring
        else:
            # We found a keyring entry, but the token may be None
            return token_info.repo_token
        return None

    @staticmethod
    def _load_token_via_conda_token(domain: str) -> Optional[str]:
        # Try to load the token via conda-token if that is installed
        if repo_config is not None:
            tokens = repo_config.token_list()
            for url, token in tokens.items():
                token_netloc = urlparse(url).netloc
                if token_netloc.lower() == domain and token is not None:
                    return token
        return None

    @cached_property
    def token(self) -> str:
        """Load the legacy repo token via conda-token.

        Returns None if token cannot be found.

        """
        domain = _get_domain_for_channel(self.channel_name)

        # First, we try to load the token from the keyring. If it is not found, we fall through
        if token := self._load_token_from_keyring(domain):
            return token
        elif token := self._load_token_via_conda_token(domain):
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
        request.headers["Authorization"] = f"token {self.token}"
        request.register_hook("response", self.handle_invalid_token)
        return request
