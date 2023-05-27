import base64
import json
import logging
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path

import keyring
import requests
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from pydantic import BaseModel

from anaconda_cloud_auth.config import get_config
from anaconda_cloud_auth.console import console
from anaconda_cloud_auth.exceptions import TokenNotFoundError

logger = logging.getLogger(__name__)

KEYRING_NAME = "Anaconda Cloud"
KEYRING_CLIENT = "anaconda_cloud_auth"


LocalKeyringData = dict[str, dict[str, str]]


class AnacondaKeyring(KeyringBackend):
    keyring_path = Path("~/.anaconda/keyring").expanduser()
    priority = 0.1

    def _read(self) -> LocalKeyringData:
        if not self.keyring_path.exists():
            return {}

        with self.keyring_path.open("r") as fp:
            data = json.load(fp)
        return data

    def _write(self, data: LocalKeyringData) -> None:
        self.keyring_path.parent.mkdir(exist_ok=True, parents=True)

        with self.keyring_path.open("w") as fp:
            json.dump(data, fp)

    def set_password(self, service: str, username: str, password: str) -> None:
        data = self._read()

        if service not in data:
            data[service] = {}

        data[service][username] = password

        self._write(data)

    def get_password(self, service: str, username: str) -> str | None:
        data = self._read()
        return data.get(service, {}).get(username, None)

    def delete_password(self, service: str, username: str) -> None:
        data = self._read()
        try:
            data.get(service, {}).pop(username)
        except KeyError:
            raise PasswordDeleteError


class TokenInfo(BaseModel):
    access_token: str | None = None
    refresh_token: str | None = None
    expires_at: datetime = datetime(1, 1, 1, tzinfo=timezone.utc)
    username: str | None = None
    id_token: str | None = None

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

    @property
    def is_expired(self) -> bool:
        return self.expires_at < datetime.now(timezone.utc)

    def write(self) -> None:
        """Write the token information to the system keyring."""
        payload = self.json()
        encoded = base64.b64encode(payload.encode("utf-8")).decode("utf-8")
        keyring.set_password(KEYRING_NAME, KEYRING_CLIENT, encoded)
        logger.debug("🔒 Token has been safely stored in system keychain 🎉")

    @staticmethod
    def delete() -> None:
        """Delete the token information from the system keyring."""
        try:
            keyring.delete_password(KEYRING_NAME, KEYRING_CLIENT)
        except PasswordDeleteError:
            raise TokenNotFoundError

    def check(self) -> None:
        from anaconda_cloud_auth.actions import _validate_token_info

        _validate_token_info(self)

    def refresh(self) -> None:
        """Refresh and save the tokens."""
        config = get_config()
        response = requests.post(
            config.oidc.token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": config.client_id,
            },
        )
        response.raise_for_status()
        response_data = response.json()

        self.access_token = response_data["access_token"]

        refresh_token = response_data["refresh_token"]
        if refresh_token != "HttpOnly":
            # Ory assigns a new refresh_token, legacy does not
            self.refresh_token = refresh_token
        self.id_token = response_data.get("id_token")
        self.expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=response_data["expires_in"]
        )

        self.write()

    def get_access_token(self) -> str:
        """Get the access token, ensuring login and refresh if necessary."""
        if not self.is_expired and self.access_token is not None:
            return self.access_token

        if self.access_token is None:
            # Try to load from the keyring, otherwise go to the login flow
            try:
                new_token_info = TokenInfo.load()
            except TokenNotFoundError:
                message = "No token found, please login with `acli auth login`"
                console.print(message)
                raise TokenNotFoundError(message)

            # Store the new token information for later retrieval
            self.access_token = new_token_info.access_token
            self.expires_at = new_token_info.expires_at
            self.refresh_token = new_token_info.refresh_token
            self.id_token = new_token_info.id_token

        if self.is_expired:
            # We have already loaded from the keychain, we don't need to do it again
            # Instead, we just check to see whether we need to refresh the access token
            self.refresh()

        assert self.access_token is not None
        return self.access_token
