from __future__ import annotations

import os
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml import YAMLError

yaml = YAML()


class CondaRCError(Exception):
    pass


class CondaRC:
    def __init__(self, condarc_path: Path | None = None):
        """
        Initializes the CondaRC object by attempting to open and load the contents
        of the condarc file found in the user's home directory.
        """
        self.condarc_path = condarc_path or Path(os.path.expanduser("~/.condarc"))

        try:
            self.condarc_path.touch()
            with self.condarc_path.open("r") as fp:
                contents = fp.read()
        except OSError as exc:
            raise CondaRCError(f"Could not open condarc file: {exc}")

        try:
            self.loaded_yaml = yaml.load(contents) or {}
        except YAMLError as exc:
            raise CondaRCError(f"Could not parse condarc: {exc}")

    def update_channel_settings(
        self, channel: str, auth_type: str, username: str | None = None
    ):
        """
        Update the condarc file's "channel_settings" section
        """
        if username is None:
            updated_settings = {"channel": channel, "auth": auth_type}
        else:
            updated_settings = {
                "channel": channel,
                "auth": auth_type,
                "username": username,
            }

        channel_settings = self.loaded_yaml.get("channel_settings", []) or []

        # Filter out the existing channel's entry if it's there
        filter_settings = [
            settings
            for settings in channel_settings
            if settings.get("channel") != channel
        ]

        # Add the updated settings map
        filter_settings.append(updated_settings)

        self.loaded_yaml["channel_settings"] = filter_settings

    def save(self):
        """Save the condarc file"""
        try:
            with self.condarc_path.open("w") as fp:
                yaml.dump(self.loaded_yaml, fp)
        except OSError as exc:
            raise CondaRCError(f"Could not save file: {exc}")
