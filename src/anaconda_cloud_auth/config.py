from functools import cached_property
from typing import Dict

from pydantic_settings import SettingsConfigDict

from anaconda_auth import __version__ as version
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_cloud_auth import warn

warn()

OIDC_REQUEST_HEADERS = {"User-Agent": f"anaconda-cloud-auth/{version}"}


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
    oidc_request_headers: Dict[str, str] = OIDC_REQUEST_HEADERS
