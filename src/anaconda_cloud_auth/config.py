from anaconda_auth import __version__ as version
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_cloud_auth import warn

warn()

OIDC_REQUEST_HEADERS = {"User-Agent": f"anaconda-cloud-auth/{version}"}


class AnacondaCloudConfig(AnacondaAuthConfig, plugin_name="cloud"):
    domain: str = "anaconda.cloud"
    oidc_request_headers: dict[str, str] = OIDC_REQUEST_HEADERS
