try:
    from anaconda_cloud_auth._version import version as __version__
except ImportError:  # pragma: nocover
    __version__ = "unknown"

# We must ensure we load all environment variables before the config is loaded
from dotenv import load_dotenv

load_dotenv()

from anaconda_cloud_auth.actions import login  # noqa: E402
from anaconda_cloud_auth.actions import logout  # noqa: E402
from anaconda_cloud_auth.client import Client  # noqa: E402

__all__ = ["__version__", "login", "logout", "Client"]
