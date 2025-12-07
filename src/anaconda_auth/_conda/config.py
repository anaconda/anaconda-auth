"""Configuration manager for the conda plugin.

This file is used as a central location to manage global configuration
settings and deliver them to the locations where they are needed, including
other modules and YAML configuration files. It is designed to be callable as
a standalone script or as a module. It can install a conda configuration file
in the prefix, and to verify its existence and expected behavioral impact.
These functions are both used by the conda recipe itself.

It is imperative that this module not include any other anaconda_auth imports
so that it can be run during the conda build process
"""

import json
import sys
from pathlib import Path
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Set
from typing import Union

__all__ = []


PREFIX_CONDARC_PATH = Path(sys.prefix) / "condarc.d" / "anaconda-auth.yml"


# This list is now serving THREE purposes. The keys are used in the conda
# plugin module to determine which hosts should be hardcoded to use
# anaconda-auth for authentication. The values are used to provide the
# keyring domain where the legacy token will be stored, as well as
# whether or not the destination should receive a proper API key.
# Finally, the list is used to generate the master anaconda-auth.yml
# configuration for conda.
class TokenDomainSetting(NamedTuple):
    token_domain: str
    default_use_unified_api_key: bool = True


TOKEN_DOMAIN_MAP = {
    "repo.continuum.io": TokenDomainSetting("anaconda.com"),
    "repo.anaconda.com": TokenDomainSetting("anaconda.com"),
    "repo.anaconda.cloud": TokenDomainSetting("anaconda.com", False),
}


def _channel_settings(
    include_defaults: bool = True, include_sites: bool = True
) -> List[Dict[str, str]]:
    hosts: Set[str] = set()
    if include_defaults:
        hosts.update(TOKEN_DOMAIN_MAP)
        hosts.update(t.token_domain for t in TOKEN_DOMAIN_MAP.values())
    if include_sites:
        # We are delaying this import so this file can be run standalone
        from anaconda_auth.config import AnacondaAuthSitesConfig

        hosts.update(s.domain for s in AnacondaAuthSitesConfig().sites.root.values())
    return [{"channel": f"https://{host}/*", "auth": "anaconda-auth"} for host in hosts]


def _write_channel_settings(
    fpath: Union[Path, str],
    include_defaults: bool = True,
    include_sites: bool = True,
    overwrite: bool = False,
) -> None:
    settings = _channel_settings(include_defaults, include_sites)
    with Path(fpath).open(mode="w" if overwrite else "x") as fp:
        json.dump({"channel_settings": settings}, fp)


def _write_condarc_d_settings() -> None:
    PREFIX_CONDARC_PATH.parent.mkdir(parents=True, exist_ok=True)
    _write_channel_settings(PREFIX_CONDARC_PATH, include_sites=False)


def _verify_channel_settings() -> None:
    assert PREFIX_CONDARC_PATH.exists()
    expected = {
        c["channel"]: c.get("auth") for c in _channel_settings(include_sites=False)
    }
    data = json.loads(PREFIX_CONDARC_PATH.read_text())
    found = {c["channel"]: c.get("auth") for c in data["channel_settings"]}
    assert expected == found

    try:
        from conda.base.context import context
    except ImportError:
        return

    context.__init__()
    found = {
        c["channel"]: c.get("auth")
        for c in context.channel_settings
        if c["channel"] in expected
    }
    assert expected == found


if __name__ == "__main__":
    import sys

    if "--install" in sys.argv:
        _write_condarc_d_settings()
    if "--verify" in sys.argv:
        _verify_channel_settings()
