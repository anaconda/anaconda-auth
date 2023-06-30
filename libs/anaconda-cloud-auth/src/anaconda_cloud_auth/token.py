import base64
import json
import logging
from pathlib import Path
from typing import Dict
from typing import Union

import keyring
from jaraco.classes.properties import classproperty
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from keyring.errors import PasswordSetError
from pydantic import BaseModel

from anaconda_cloud_auth.console import console
from anaconda_cloud_auth.exceptions import TokenNotFoundError

logger = logging.getLogger(__name__)

KEYRING_NAME = "Anaconda Cloud"
KEYRING_CLIENT = "anaconda_cloud_auth"


LocalKeyringData = Dict[str, Dict[str, str]]


def _as_base64_string(payload: str) -> str:
    """Encode a string to a base64 string"""
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")


class NavigatorFallback(KeyringBackend):
    priority = 0.1  # type: ignore

    @classproperty
    def viable(cls) -> bool:
        try:
            import anaconda_navigator  # noqa: F401

            return True
        except ModuleNotFoundError:
            return False

    def set_password(self, service: str, username: str, password: str) -> None:
        raise PasswordSetError("This keyring cannot set passwords")

    def get_password(self, service: str, username: str) -> Union[str, None]:
        try:
            from anaconda_navigator.api.nucleus.token import NucleusToken
        except ImportError:
            return None

        if service != KEYRING_NAME and username != KEYRING_CLIENT:
            return None
        else:
            token = NucleusToken.from_file()
            if token is not None:
                from anaconda_cloud_auth.actions import _get_api_key

                api_key = _get_api_key(token.access_token)
                token_info = {"username": token.username, "api_key": api_key}
                payload = json.dumps(token_info)
                encoded = _as_base64_string(payload)
                return encoded
            else:
                return None


class AnacondaKeyring(KeyringBackend):
    keyring_path = Path("~/.anaconda/keyring").expanduser()
    priority = 0.2  # type: ignore

    def _read(self) -> LocalKeyringData:
        if not self.keyring_path.exists():
            return {}

        with self.keyring_path.open("r") as fp:
            data = json.load(fp)
        return data

    def _save(self, data: LocalKeyringData) -> None:
        self.keyring_path.parent.mkdir(exist_ok=True, parents=True)

        with self.keyring_path.open("w") as fp:
            json.dump(data, fp)

    def set_password(self, service: str, username: str, password: str) -> None:
        data = self._read()

        if service not in data:
            data[service] = {}

        data[service][username] = password

        self._save(data)

    def get_password(self, service: str, username: str) -> Union[str, None]:
        data = self._read()
        return data.get(service, {}).get(username, None)

    def delete_password(self, service: str, username: str) -> None:
        data = self._read()
        try:
            data.get(service, {}).pop(username)
        except KeyError:
            raise PasswordDeleteError


class TokenInfo(BaseModel):
    api_key: Union[str, None] = None
    username: Union[str, None] = None

    @classmethod
    def load(cls) -> "TokenInfo":
        """Load the token information from the system keyring."""
        keyring_data = keyring.get_password(KEYRING_NAME, KEYRING_CLIENT)
        if keyring_data is None:
            raise TokenNotFoundError

        decoded_bytes = base64.b64decode(keyring_data)
        decoded_dict = json.loads(decoded_bytes)
        logger.debug("🔓 Token has been successfully retrieved from system keychain 🎉")
        return TokenInfo(**decoded_dict)

    def save(self) -> None:
        """Write the token information to the system keyring."""
        payload = self.json()
        encoded = _as_base64_string(payload)
        keyring.set_password(KEYRING_NAME, KEYRING_CLIENT, encoded)
        logger.debug("🔒 Token has been safely stored in system keychain 🎉")

    @staticmethod
    def delete() -> None:
        """Delete the token information from the system keyring."""
        try:
            keyring.delete_password(KEYRING_NAME, KEYRING_CLIENT)
        except PasswordDeleteError:
            raise TokenNotFoundError

    def get_access_token(self) -> str:
        """Get the access token, ensuring login and refresh if necessary."""
        if self.api_key is None:
            try:
                new_token_info = TokenInfo.load()
            except TokenNotFoundError:
                message = "No token found, please login with `anaconda login`"
                console.print(message)
                raise TokenNotFoundError(message)

            # Store the new token information for later retrieval
            self.username = new_token_info.username
            self.api_key = new_token_info.api_key

        assert self.api_key is not None
        return self.api_key
