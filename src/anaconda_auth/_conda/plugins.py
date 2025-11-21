"""Definitions for conda plugins.

This file should not be imported directly, but instead the parent package will
conditionally import it in case conda is not installed in the user's environment.

"""

from typing import Iterable
from typing import Optional

from conda import plugins
from conda.plugins.types import CondaAuthHandler
from conda.plugins.types import CondaPreCommand
from conda.plugins.types import CondaSubcommand
from frozendict import frozendict

from anaconda_auth._conda.auth_handler import TOKEN_DOMAIN_MAP
from anaconda_auth._conda.auth_handler import AnacondaAuthHandler
from anaconda_auth._conda.conda_token import cli
from anaconda_auth.config import AnacondaAuthSitesConfig

__all__ = ["conda_subcommands", "conda_auth_handlers", "conda_pre_commands"]


def _cli_wrapper(argv: Optional[list[str]] = None) -> int:  # type: ignore
    # If argv is empty tuple, we need to set it back to None
    return cli(argv=argv or None)


def merge_auth_configs(command: str) -> None:
    """Implements default auth settings for Anaconda channels, respecting overrides.
    If the .condarc file already has an "auth" entry for a given channel, it is left
    unchanged; but all other channels in the list TOKEN_DOMAIN_MAP are pointed
    to this plugin for authentication.
    """
    from conda.base.context import context

    result = []
    hosts = {f"https://{host}/" for host in TOKEN_DOMAIN_MAP}
    for site in AnacondaAuthSitesConfig().sites.root.values():
        hosts.add(f"https://{site.domain}/")
    wildcards = set(hosts)
    for orec in context.channel_settings:
        channel = orec.get("channel")
        if channel is None:
            break
        for c in hosts:
            if channel.startswith(c):
                if channel == c + "*":
                    wildcards.discard(c)
                if "auth" not in orec:
                    orec = frozendict([*orec.items(), ("auth", "anaconda-auth")])
                break
        result.append(orec)
    for channel in wildcards:
        result.append(
            frozendict([("channel", channel + "*"), ("auth", "anaconda-auth")])
        )
    context.channel_settings = tuple(result)


class AlwaysContains:
    def __contains__(self, item):
        return True


@plugins.hookimpl
def conda_pre_commands() -> Iterable[CondaPreCommand]:
    yield CondaPreCommand(
        name="anaconda-auth",
        action=merge_auth_configs,
        run_for=AlwaysContains(),
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
