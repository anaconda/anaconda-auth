from functools import cached_property
from typing import Dict
from typing import Literal
from typing import Optional
from typing import Union

import requests

from anaconda_auth import __version__ as version
from anaconda_auth.config import OpenIDConfiguration
from anaconda_cli_base.config import AnacondaBaseSettings
from anaconda_cloud_auth import warn

warn()

OIDC_REQUEST_HEADERS = {"User-Agent": f"anaconda-cloud-auth/{version}"}


class AnacondaCloudConfig(AnacondaBaseSettings, plugin_name="cloud"):
    preferred_token_storage: Literal["system", "anaconda-keyring"] = "anaconda-keyring"
    domain: str = "anaconda.cloud"
    api_key: Optional[str] = None
    ssl_verify: bool = True
    extra_headers: Optional[Union[Dict[str, str], str]] = None
    client_id: str = "b4ad7f1d-c784-46b5-a9fe-106e50441f5a"
    redirect_uri: str = "http://127.0.0.1:8000/auth/oidc"
    openid_config_path: str = "api/auth/oauth2/.well-known/openid-configuration"

    @property
    def well_known_url(self: "AnacondaCloudConfig") -> str:
        """The URL from which to load the OpenID configuration."""
        return f"https://{self.domain}/{self.openid_config_path}"

    @property
    def oidc(self) -> "OpenIDConfiguration":
        """The OIDC configuration, cached as a regular instance attribute."""
        res = requests.get(
            self.well_known_url, headers=OIDC_REQUEST_HEADERS, verify=self.ssl_verify
        )
        res.raise_for_status()
        oidc_config = OpenIDConfiguration(**res.json())
        return self.__dict__.setdefault("_oidc", oidc_config)

    @cached_property
    def aau_token(self) -> Union[str, None]:
        # The token is cached in anaconda_anon_usage, so we can also cache here
        try:
            from anaconda_anon_usage.tokens import token_string
        except ImportError:
            return None

        try:
            return token_string()
        except Exception:
            # We don't want this to block user login in any case,
            # so let any Exceptions pass silently.
            return None
