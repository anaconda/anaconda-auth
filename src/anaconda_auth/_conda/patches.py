from fnmatch import fnmatch
from functools import cache

from conda.base.context import context
from conda.gateways.connection import session
from conda.gateways.connection.session import CondaSession
from conda.gateways.connection.session import get_channel_name_from_url
from conda.gateways.connection.session import urlparse

DEFAULT_CHANNEL_SETTINGS = [
    {
        "channel": "https://repo.anaconda.com/*",
        "auth": "anaconda-auth",
    }
]


@cache
def new_get_session(url: str):
    """
    Function that determines the correct Session object to be returned
    based on the URL that is passed in.
    """
    channel_name = get_channel_name_from_url(url)

    # If for whatever reason a channel name can't be determined, (should be unlikely)
    # we just return the default session object.
    if channel_name is None:
        return CondaSession()

    # We ensure here if there are duplicates defined, we choose the last one
    channel_settings = {}
    for settings in [*context.channel_settings, *DEFAULT_CHANNEL_SETTINGS]:
        channel = settings.get("channel", "")
        if channel == channel_name:
            # First we check for exact match
            channel_settings = settings
            continue

        # If we don't have an exact match, we attempt to match a URL pattern
        parsed_url = urlparse(url)
        parsed_setting = urlparse(channel)

        # We require that the schemes must be identical to prevent downgrade attacks.
        # This includes the case of a scheme-less pattern like "*", which is not allowed.
        if parsed_setting.scheme != parsed_url.scheme:
            continue

        url_without_schema = parsed_url.netloc + parsed_url.path
        pattern = parsed_setting.netloc + parsed_setting.path
        if fnmatch(url_without_schema, pattern):
            channel_settings = settings

    auth_handler = channel_settings.get("auth", "").strip() or None

    # Return default session object
    if auth_handler is None:
        return CondaSession()

    auth_handler_cls = context.plugin_manager.get_auth_handler(auth_handler)

    if not auth_handler_cls:
        return CondaSession()

    return CondaSession(auth=auth_handler_cls(channel_name))


def apply() -> None:
    session.get_session = new_get_session
