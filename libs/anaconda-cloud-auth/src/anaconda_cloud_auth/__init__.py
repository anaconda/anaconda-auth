from importlib.metadata import PackageNotFoundError
from importlib.metadata import version

from anaconda_cloud_auth.actions import login
from anaconda_cloud_auth.actions import logout
from anaconda_cloud_auth.client import Client

__all__ = ["__version__", "login", "logout", "Client"]
try:
    __version__ = version("anaconda-cloud-auth")
except PackageNotFoundError:
    __version__ = "unknown"
