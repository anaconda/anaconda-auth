"""Definitions for conda plugins.

This file should not be imported directly, but instead the parent package will
conditionally import it in case conda is not installed in the user's environment.

"""

from typing import Iterable
from typing import Optional

from conda import plugins
from conda.plugins.types import CondaAuthHandler
from conda.plugins.types import CondaSubcommand

from anaconda_auth._conda.auth_handler import AnacondaAuthHandler
from anaconda_auth._conda.conda_token import cli
from anaconda_auth.config import AnacondaAuthConfig

__all__ = ["conda_subcommands", "conda_auth_handlers", "conda_pre_commands"]

# DEFAULT_CHANNEL_AUTH = ("https://repo.anaconda.com/", "https://repo.anaconda.cloud/")


def _cli_wrapper(argv: Optional[list[str]] = None) -> int:  # type: ignore
    # If argv is empty tuple, we need to set it back to None
    return cli(argv=argv or None)


# def merge_auth_configs(command):
#     """Implements default auth settings for Anaconda channels, respecting overrides.
#     If the .condarc file already has an "auth" entry for a given channel, it is left
#     unchanged; but all other channels in the list DEFAULT_CHANNEL_AUTH are pointed
#     to this plugin for authentication.
#     """
#     from conda.base.context import context

#     result = []
#     wildcards = set(DEFAULT_CHANNEL_AUTH)
#     for orec in context.channel_settings:
#         channel = orec.get("channel")
#         if channel is None:
#             break

#         for c in DEFAULT_CHANNEL_AUTH:
#             if channel.startswith(c):
#                 if channel == c + "*":
#                     wildcards.discard(c)
#                 if "auth" not in orec:
#                     orec = frozendict([*orec.items(), ("auth", "anaconda-auth")])
#                 break
#         result.append(orec)

#     for channel in wildcards:
#         result.append(
#             frozendict([("channel", channel + "*"), ("auth", "anaconda-auth")])
#         )
#     context.channel_settings = tuple(result)


@plugins.hookimpl
def conda_pre_commands():
    yield plugins.CondaPreCommand(
        name="anaconda-auth",
        action=AnacondaAuthConfig.merge_auth_configs,
        run_for={"config", "install", "create", "uninstall", "env_create", "search"},
    )


@plugins.hookimpl
def conda_subcommands() -> Iterable[CondaSubcommand]:
    """Defines subcommands into conda itself (not `anaconda` CLI)."""
    yield CondaSubcommand(
        name="token",
        summary="Set repository access token and configure default_channels",
        action=_cli_wrapper,  # type: ignore
    )


@plugins.hookimpl
def conda_auth_handlers() -> Iterable[CondaAuthHandler]:
    """Defines the auth handler that can be used for specific channels.

    The following shows an example for how to configure a specific channel inside .condarc:

    ```yaml
    channel_settings:
      - channel: https://repo.anaconda.cloud/*
        auth: anaconda-auth
    ```

    """
    yield CondaAuthHandler(
        name="anaconda-auth",
        handler=AnacondaAuthHandler,
    )
