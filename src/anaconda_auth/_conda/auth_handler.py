"""Defines an auth handler to inject an Authorization header into each request.

Tokens are assumed to be installed onto a user's system via a separate CLI command.

"""

from functools import lru_cache
from typing import Any
from typing import NamedTuple
from typing import Optional
from urllib.parse import urlparse

from conda import CondaError
from conda.base.context import context as global_context
from conda.models.channel import Channel
from conda.plugins.types import ChannelAuthBase
from requests import PreparedRequest
from requests import Response

from anaconda_auth._conda import repo_config
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.exceptions import TokenNotFoundError
from anaconda_auth.token import TokenInfo

URI_PREFIX = "/repo/"


# This list is now serving TWO purposes. The keys are used in the conda
# plugin module to determine which hosts should be hardcoded to use
# anaconda-auth for authentication. The values are used to provide the
# keyring domain where the legacy token will be stored, as well as
# whether or not the destination should receive a proper API key.
class TokenDomainSetting(NamedTuple):
    token_domain: str
    default_use_unified_api_key: bool = True


TOKEN_DOMAIN_MAP = {
    "repo.continuum.io": TokenDomainSetting("anaconda.com"),
    "repo.anaconda.com": TokenDomainSetting("anaconda.com"),
    "repo.anaconda.cloud": TokenDomainSetting("anaconda.com", False),
}


class AnacondaAuthError(CondaError):
    """
    A generic error to raise that is a subclass of CondaError so we don't trigger the unhandled exception traceback.
    """


def _load_settings_for_channel(channel_name: str) -> dict[str, str]:
    """Find the correct channel settings from conda's configuration."""
    for settings in global_context.channel_settings:
        settings_channel = settings.get("channel")

        # TODO(mattkram): This is not robust as it assumes the glob pattern
        if settings_channel.endswith("*"):
            prefix = settings_channel[:-1]
            if channel_name.startswith(prefix):
                return settings

    # TODO(mattkram): How should we handle this?
    raise ValueError(f"Couldn't find the settings for channel {channel_name}")


class AnacondaAuthHandler(ChannelAuthBase):
    def __init__(self, channel_name: str, *args: Any, **kwargs: Any):
        super().__init__(channel_name, *args, **kwargs)

        channel = Channel(channel_name)
        self.channel_domain = channel.location

        # TODO(mattkram): We need to load some defaults based on TOKEN_DOMAIN_MAP first, and then allow overrides
        settings = _load_settings_for_channel(channel_name)
        self.auth_domain = (
            settings.get("auth_domain", self.channel_domain) or "anaconda.com"
        )
        self.credential_type = settings.get("credential_type", "api-key")

        # TODO(mattkram): This is brittle, rewrite
        if self.channel_domain and self.channel_domain not in TOKEN_DOMAIN_MAP:
            TOKEN_DOMAIN_MAP[self.channel_domain] = TokenDomainSetting(
                self.auth_domain, self.credential_type == "api-key"
            )
        print(f"{TOKEN_DOMAIN_MAP=}")
        lines = []
        lines.append("\n############################################################")
        lines.append(f"{self.channel_name=}")
        lines.append(f"{self.channel_domain=}")
        lines.append(f"{self.auth_domain=}")
        lines.append(f"{self.credential_type=}")
        lines.append("############################################################\n")
        print("\n".join(lines))

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
        if channel_domain in TOKEN_DOMAIN_MAP:
            token_domain, is_unified = TOKEN_DOMAIN_MAP[channel_domain]
        else:
            token_domain, is_unified = channel_domain, False

        try:
            token_info = TokenInfo.load(token_domain)
        except TokenNotFoundError:
            # Fallback to conda-token if the token is not found in the keyring
            return None

        # Check configuration to use unified api key,
        # otherwise continue and attempt to utilize repo token
        if api_key := token_info.api_key:
            if is_unified:
                return api_key
            try:
                config = AnacondaAuthConfig(domain=token_domain)
                if config.use_unified_repo_api_key:
                    return api_key
            except Exception:
                pass

        path = parsed_url.path
        if path.startswith(URI_PREFIX):
            path = path[len(URI_PREFIX) :]
        maybe_org, _, _ = path.partition("/")

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
    def _load_token(self, url: str) -> Optional[str]:
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
        token = self._load_token(url)
        if token is None:
            return None

        # TODO(mattkram): This is a heuristic to determine whether token or API key but
        #                 we should do it better.
        if len(token) < 200:
            return f"token {token}"

        return f"Bearer {token}"

    def handle_missing_token(self, response: Response, **_: Any) -> Response:
        """Raise a nice error message if the authentication token is missing."""
        if response.status_code in {401, 403}:
            # TODO: We need to make this handle better errors between token vs. api-key instructions
            raise AnacondaAuthError(
                f"Token not found for {self.channel_name}. Please install token with "
                "`anaconda token install`."
            )
        return response

    def handle_invalid_token(self, response: Response, **_: Any) -> Response:
        """Raise a nice error message if the authentication token is invalid (not missing)."""
        if response.status_code in {401, 403}:
            # TODO: We need to make this handle better errors between token vs. api-key instructions
            raise AnacondaAuthError(
                f"Received authentication error ({response.status_code}) when "
                f"accessing {self.channel_name}. "
                "If your token is invalid or expired, please re-install with "
                "`anaconda token install`."
            )
        return response

    def echo_response(self, response: Response, **_: Any) -> Response:
        request = response.request
        lines = [
            "\n###############################",
            f"{request.method=}",
            f"{request.url=}",
            f"{request.headers=}",
            f"{response=}",
        ]
        if response.ok:
            try:
                lines.append(f"{response.json()=}")
            except Exception:
                lines.append("Couldn't parse JSON response but status code was ok ...")
        lines.append("###############################\n")
        print("\n".join(lines))
        return response

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        """Inject the token as an Authorization header on each request."""
        header = self._build_header(request.url) if request.url is not None else None
        if not header:
            request.register_hook("response", self.handle_missing_token)
            return request

        if header is not None:
            request.headers["Authorization"] = header

        request.register_hook("response", self.handle_invalid_token)
        # TODO(mattkram): Remove debug print
        # request.register_hook("response", self.echo_response)
        return request
