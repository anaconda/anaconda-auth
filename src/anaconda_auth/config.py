from functools import cached_property
from typing import Any
from typing import Dict
from typing import Literal
from typing import Optional
from typing import Union

import requests
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict

from anaconda_auth import __version__ as version
from anaconda_cli_base.config import AnacondaBaseSettings


class AnacondaAuthConfig(AnacondaBaseSettings, plugin_name="auth"):
    def __init__(self, **kwargs: Any):
        if self.__class__ == AnacondaAuthConfig:
            config = AnacondaCloudConfig()
            set_fields = config.model_dump(exclude_unset=True)
            # TODO: Raise Deprecation warning and instruct to use new env vars or config file keys
            kwargs.update(**set_fields)
        super().__init__(**kwargs)

    preferred_token_storage: Literal["system", "anaconda-keyring"] = "anaconda-keyring"
    domain: str = "anaconda.cloud"
    api_key: Optional[str] = None
    ssl_verify: bool = True
    extra_headers: Optional[Union[Dict[str, str], str]] = None
    client_id: str = "b4ad7f1d-c784-46b5-a9fe-106e50441f5a"
    redirect_uri: str = "http://127.0.0.1:8000/auth/oidc"
    openid_config_path: str = "api/auth/oauth2/.well-known/openid-configuration"
    oidc_request_headers: Dict[str, str] = {"User-Agent": f"anaconda-auth/{version}"}

    @property
    def well_known_url(self: "AnacondaAuthConfig") -> str:
        """The URL from which to load the OpenID configuration."""
        return f"https://{self.domain}/{self.openid_config_path}"

    @property
    def oidc(self) -> "OpenIDConfiguration":
        """The OIDC configuration, cached as a regular instance attribute."""
        res = requests.get(
            self.well_known_url,
            headers=self.oidc_request_headers,
            verify=self.ssl_verify,
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


class OpenIDConfiguration(BaseModel):
    authorization_endpoint: str
    token_endpoint: str


_OLD_OIDC_REQUEST_HEADERS = {"User-Agent": f"anaconda-cloud-auth/{version}"}


class AnacondaCloudConfig(AnacondaAuthConfig, plugin_name="cloud"):
    # Here, we explicitly specify the model_config for this class. This is because
    # there is a bug inside AnacondaBaseSettings, where the env_prefix is mutated
    # in that base class. Thus, nested inheritance doesn't quite work as I'd expect.
    # However, if we set this attribute on *this* class, then that problem goes away,
    # Even though the behavior that handles the injecting of the `plugin_name` into
    # the env_prefix is handled in the __init_subclass__ method in that base class.
    model_config = SettingsConfigDict(
        env_file=".env",
        pyproject_toml_table_header=(),
        env_prefix="ANACONDA_",
        env_nested_delimiter="__",
        extra="ignore",
        ignored_types=(cached_property,),
    )
    domain: str = "anaconda.cloud"
    oidc_request_headers: Dict[str, str] = _OLD_OIDC_REQUEST_HEADERS
