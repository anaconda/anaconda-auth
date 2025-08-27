import warnings
from functools import cached_property
from typing import Any
from typing import Dict
from typing import Literal
from typing import Optional
from typing import Union
from urllib.parse import urljoin

import requests
from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict

from anaconda_auth import __version__ as version
from anaconda_cli_base.config import AnacondaBaseSettings
from anaconda_cli_base.console import console


def _raise_deprecated_field_set_warning(set_fields: Dict[str, Any]) -> None:
    fields_str = ", ".join(sorted(f'"{s}"' for s in set_fields.keys()))
    warning_text = (
        "The following fields have been set using legacy environment variables "
        + "prefixed with 'ANACONDA_CLOUD_` or in the `plugins.cloud` section "
        + f"of `~/.anaconda/config.toml`: {fields_str}\n\n"
        + "Please either rename environment variables to the corresponding "
        + "`ANACONDA_AUTH_` version, or replace the `plugins.cloud` section "
        + "of the config file with `plugins.auth`."
    )
    console.print(f"[red]{warning_text}[/red]")
    warnings.warn(
        warning_text,
        DeprecationWarning,
    )


class AnacondaAuthConfig(AnacondaBaseSettings, plugin_name="auth"):
    preferred_token_storage: Literal["system", "anaconda-keyring"] = "anaconda-keyring"
    domain: str = "anaconda.com"
    auth_domain_override: Optional[str] = None
    api_key: Optional[str] = None
    ssl_verify: bool = True
    extra_headers: Optional[Union[Dict[str, str], str]] = None
    client_id: str = "b4ad7f1d-c784-46b5-a9fe-106e50441f5a"
    redirect_uri: str = "http://127.0.0.1:8000/auth/oidc"
    openid_config_path: str = "/.well-known/openid-configuration"
    oidc_request_headers: Dict[str, str] = {"User-Agent": f"anaconda-auth/{version}"}
    login_success_path: str = "/app/local-login-success"
    login_error_path: str = "/app/local-login-error"
    use_unified_repo_api_key: bool = False
    hash_hostname: bool = True

    def __init__(self, **kwargs: Any):
        if self.__class__ == AnacondaAuthConfig:
            config = AnacondaCloudConfig(raise_deprecation_warning=False)
            set_fields = config.model_dump(exclude_unset=True)
            if set_fields:
                _raise_deprecated_field_set_warning(set_fields)

                # Merge dictionaries, ensuring that any duplicate keys in kwargs wins
                kwargs = {**set_fields, **kwargs}
        super().__init__(**kwargs)

    @property
    def auth_domain(self) -> str:
        """The authentication domain base URL.

        Defaults to the `auth` subdomain of the main domain.

        """
        if self.auth_domain_override:
            return self.auth_domain_override
        return f"auth.{self.domain}"

    @property
    def well_known_url(self) -> str:
        """The URL from which to load the OpenID configuration."""
        return urljoin(f"https://{self.auth_domain}", self.openid_config_path)

    @property
    def login_success_url(self) -> str:
        """The location to redirect after auth flow, if successful."""
        return urljoin(f"https://{self.domain}", self.login_success_path)

    @property
    def login_error_url(self) -> str:
        """The location to redirect after auth flow, if there is an error."""
        return urljoin(f"https://{self.domain}", self.login_error_path)

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
    oidc_request_headers: Dict[str, str] = _OLD_OIDC_REQUEST_HEADERS

    def __init__(self, raise_deprecation_warning: bool = True, **kwargs: Any):
        if raise_deprecation_warning:
            warnings.warn(
                "AnacondaCloudConfig is deprecated, please use AnacondaAuthConfig instead.",
                DeprecationWarning,
            )

        super().__init__(**kwargs)
