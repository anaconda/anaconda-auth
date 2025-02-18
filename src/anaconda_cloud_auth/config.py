import requests

from anaconda_auth import __version__ as version
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.config import OpenIDConfiguration
from anaconda_cloud_auth import warn

warn()

OIDC_REQUEST_HEADERS = {"User-Agent": f"anaconda-cloud-auth/{version}"}


class AnacondaCloudConfig(AnacondaAuthConfig, plugin_name="cloud"):
    domain: str = "anaconda.cloud"

    @property
    def oidc(self) -> "OpenIDConfiguration":
        """The OIDC configuration, cached as a regular instance attribute."""
        res = requests.get(
            self.well_known_url, headers=OIDC_REQUEST_HEADERS, verify=self.ssl_verify
        )
        res.raise_for_status()
        oidc_config = OpenIDConfiguration(**res.json())
        return self.__dict__.setdefault("_oidc", oidc_config)
