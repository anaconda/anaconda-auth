try:
    from anaconda_cloud_auth._version import version as __version__
except ImportError:  # pragma: nocover
    __version__ = "unknown"

from anaconda_cloud_auth.actions import login
from anaconda_cloud_auth.actions import logout
from anaconda_cloud_auth.client import Client

__all__ = ["__version__", "login", "logout", "Client"]
