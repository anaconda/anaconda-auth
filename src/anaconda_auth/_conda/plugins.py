"""Definitions for conda plugins.

This file should not be imported directly, but instead the parent package will
conditionally import it in case conda is not installed in the user's environment.

"""

from typing import Iterable

from conda import plugins
from frozendict import frozendict

from anaconda_auth._conda.auth_handler import AnacondaAuthHandler

__all__ = ["conda_auth_handlers", "conda_pre_commands", "conda_post_commands"]


DEFAULT_CHANNEL_AUTH = ("https://repo.anaconda.com/", "https://repo.anaconda.cloud/")


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


def display_messages(command: str) -> None:
    from anaconda_auth._conda.auth_handler import MESSAGES
    from anaconda_cli_base.console import console

    if MESSAGES:
        console.print("")

    for message in MESSAGES:
        console.print(message)


def merge_auth_configs(command):
    """Implements default auth settings for Anaconda channels, respecting overrides.
    If the .condarc file already has an "auth" entry for a given channel, it is left
    unchanged; but all other channels in the list DEFAULT_CHANNEL_AUTH are pointed
    to this plugin for authentication.
    """
    from conda.base.context import context
    result = []
    wildcards = set(DEFAULT_CHANNEL_AUTH)
    for orec in context.channel_settings:
        channel = orec.get("channel")
        for c in DEFAULT_CHANNEL_AUTH:
            if channel.startswith(c):
                if channel == c + '*':
                    wildcards.discard(c)
                if "auth" not in orec:
                    orec = frozendict([*orec.items(), ("auth", "anaconda-auth")])
                break
        result.append(orec)
    for channel in wildcards:
        result.append(frozendict([("channel", channel + '*'), ("auth", "anaconda-auth")]))
    context.channel_settings = tuple(result)


@plugins.hookimpl
def conda_pre_commands():
    yield plugins.CondaPreCommand(
        name="anaconda-auth",
        action=merge_auth_configs,
        run_for={"config", "install", "create", "uninstall", "env_create", "search"},
    )


@plugins.hookimpl
def conda_post_commands() -> Iterable[plugins.CondaPostCommand]:
    yield plugins.CondaPostCommand(
        "anaconda-post-command-messager",
        action=display_messages,
        run_for={"search", "install"},
    )
