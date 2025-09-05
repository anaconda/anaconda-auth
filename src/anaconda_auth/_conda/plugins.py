"""Definitions for conda plugins.

This file should not be imported directly, but instead the parent package will
conditionally import it in case conda is not installed in the user's environment.

"""

from typing import Iterable

from conda import plugins

from anaconda_auth._conda.auth_handler import AnacondaAuthHandler

__all__ = ["conda_auth_handlers"]


@plugins.hookimpl
def conda_auth_handlers() -> Iterable[plugins.CondaAuthHandler]:
    """Defines the auth handler that can be used for specific channels.

    The following shows an example for how to configure a specific channel inside .condarc:

    ```yaml
    channel_settings:
      - channel: https://repo.anaconda.cloud/*
        auth: anaconda-auth
    ```

    """
    yield plugins.CondaAuthHandler(
        name="anaconda-auth",
        handler=AnacondaAuthHandler,
    )
