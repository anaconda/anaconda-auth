import warnings
from functools import cached_property
from typing import Any
from typing import ClassVar
from typing import Dict
from typing import List
from typing import Literal
from typing import MutableMapping
from typing import Optional
from typing import Tuple
from typing import Union
from urllib.parse import urljoin

import requests
from pydantic import BaseModel
from pydantic import RootModel
from pydantic_settings import PydanticBaseSettingsSource

from anaconda_auth import __version__ as version
from anaconda_auth.exceptions import UnknownSiteName
from anaconda_cli_base.config import AnacondaBaseSettings
from anaconda_cli_base.config import anaconda_config_path
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


class AnacondaAuthSite(BaseModel):
    preferred_token_storage: Literal["system", "anaconda-keyring"] = "anaconda-keyring"
    domain: str = "anaconda.com"
    auth_domain_override: Optional[str] = None
    api_key: Optional[str] = None
    keyring: Optional[Dict[str, Dict[str, str]]] = None
    ssl_verify: Union[bool, Literal["truststore"]] = True
    extra_headers: Optional[Union[Dict[str, str], str]] = None
    client_id: str = "b4ad7f1d-c784-46b5-a9fe-106e50441f5a"
    redirect_uri: str = "http://127.0.0.1:8000/auth/oidc"
    openid_config_path: str = "/.well-known/openid-configuration"
    oidc_request_headers: Dict[str, str] = {"User-Agent": f"anaconda-auth/{version}"}
    login_success_path: str = "/app/local-login-success"
    login_error_path: str = "/app/local-login-error"
    use_unified_repo_api_key: bool = False
    hash_hostname: bool = True
    proxy_servers: Optional[MutableMapping[str, str]] = None
    client_cert: Optional[str] = None
    client_cert_key: Optional[str] = None
    use_device_flow: bool = False
    _merged: bool = False

    @property
    def auth_domain(self) -> str:
        """The authentication domain base URL.

        Defaults to the `auth` subdomain of the main domain.

        """
        if self.auth_domain_override:
            return self.auth_domain_override
        return self.domain

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


class AnacondaAuthConfig(AnacondaAuthSite, AnacondaBaseSettings, plugin_name="auth"):
    _dump: ClassVar[Dict[str, Any]] = {}
    _part: ClassVar[str] = "both"

    def __init_subclass__(cls, part: Optional[str] = None, **kwargs: Any):
        cls._part = part or "both"
        return super().__init_subclass__(**kwargs)

    @classmethod
    def settings_customise_sources(
        cls, *args: Any, **kwargs: Any
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        settings = super().settings_customise_sources(*args, **kwargs)
        if cls._part == "env":
            return settings[:-1]
        elif cls._part == "toml":
            return (settings[-1],)
        return settings

    @classmethod
    def values(cls) -> Dict[str, Any]:
        if cls._dump is None:
            cls._dump = cls().model_dump(exclude_unset=True)
        return cls._dump


# An AnacondaAuthConfig object constructed only from environment
class AnacondaEnvPart(AnacondaAuthConfig, part="env"): ...


# An AnacondaAuthConfig object constructed only from the TOML settings
class AnacondaAuthPart(AnacondaAuthConfig, part="toml"): ...


class OpenIDConfiguration(BaseModel):
    authorization_endpoint: str
    token_endpoint: str
    device_authorization_endpoint: Optional[str] = None


_OLD_OIDC_REQUEST_HEADERS = {"User-Agent": f"anaconda-cloud-auth/{version}"}


class AnacondaCloudConfig(AnacondaAuthConfig, plugin_name="cloud"):
    oidc_request_headers: Dict[str, str] = _OLD_OIDC_REQUEST_HEADERS

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        set_fields = self.model_dump(exclude_unset=True)
        if set_fields:
            _raise_deprecated_field_set_warning(set_fields)


# An AnacondaCloudConfig object constructed only from the TOML settings
class AnacondaCloudPart(AnacondaCloudConfig, part="toml"): ...


def _backfill_from_auth_config(
    config: AnacondaAuthSite, include_env: bool
) -> AnacondaAuthSite:
    config_dump = config.model_dump(exclude_unset=True)
    env_config = AnacondaEnvPart.values() if include_env else {}
    auth_config = AnacondaAuthPart.values()
    cloud_config = AnacondaCloudPart.values()
    merged = {**cloud_config, **auth_config, **config_dump, **env_config}
    return AnacondaAuthSite(**merged)


class Sites(RootModel[Dict[str, AnacondaAuthSite]]):
    def __getitem__(self, key: str) -> AnacondaAuthSite:
        config = self.root.get(key)
        if config is None:
            matches = [
                (skey, site) for skey, site in self.root.items() if site.domain == key
            ]
            if len(matches) == 1:
                key, config = matches[0]
            elif matches:
                mstr = ", ".join(skey for skey, _ in matches)
                raise ValueError(
                    f"The domain {key} matches more than one configured site ({mstr})"
                )
            elif key == "anaconda.com":
                config = AnacondaAuthSite()
            else:
                raise UnknownSiteName(
                    f"The site name or domain {key} has not been configured in {anaconda_config_path()}"
                )
        if not config._merged:
            is_default = key == AnacondaAuthSitesConfig().default_site
            config = _backfill_from_auth_config(config, is_default)
            config._merged = True
        self.root[key] = config
        return config


class AnacondaAuthSitesConfig(AnacondaBaseSettings, plugin_name=None):
    _instance: ClassVar[Optional["AnacondaAuthSitesConfig"]] = None

    default_site: Optional[str] = None
    sites: Sites = Sites({})

    def __new__(cls) -> "AnacondaAuthSitesConfig":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if self.default_site is None:
            if self.sites.root:
                self.default_site = next(iter(self.sites.root))
            else:
                self.default_site = "anaconda.com"

    @classmethod
    def all_sites(cls) -> List[str]:
        return list(cls().sites.root)

    @classmethod
    def load_site(cls, site: Optional[str] = None) -> AnacondaAuthSite:
        """Load the site configuration object (site=None loads default_site)"""
        config = cls()
        sstr: str = site or config.default_site or "anaconda.com"
        return config.sites[sstr]
