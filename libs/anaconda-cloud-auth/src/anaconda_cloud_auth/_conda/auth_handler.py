"""Defines an auth handler to inject an Authorization header into each request.

Tokens are assumed to be installed onto a user's system via a separate CLI command.

"""

from typing import Optional
from urllib.parse import urlparse

from conda.plugins.types import ChannelAuthBase
from requests import PreparedRequest

try:
    from conda_token import repo_config
except ImportError:
    repo_config = None  # type: ignore


class AnacondaCloudAuthHandler(ChannelAuthBase):
    @property
    def token(self) -> Optional[str]:
        """Load the legacy repo token via conda-token.

        Returns None if token cannot be found.

        """
        if repo_config is None:
            return None
        tokens = repo_config.token_list()
        for url, token in tokens.items():
            token_netloc = urlparse(url).netloc
            channel_netloc = urlparse(self.channel_name).netloc
            if token_netloc.lower() == channel_netloc.lower():
                return token
        return None

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        """Inject the token as an Authorization header on each request."""
        if token := self.token:
            request.headers["Authorization"] = f"token {token}"
        return request
