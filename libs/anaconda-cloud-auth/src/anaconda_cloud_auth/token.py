import base64
import hashlib
import json
import logging
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path
from typing import Dict
from typing import Union

import jwt
import keyring
import requests
from jaraco.classes.properties import classproperty
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from keyring.errors import PasswordSetError
from pydantic import BaseModel

from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.console import console
from anaconda_cloud_auth.exceptions import InvalidTokenError
from anaconda_cloud_auth.exceptions import TokenNotFoundError
from anaconda_cloud_auth.jwt import JWKClient

logger = logging.getLogger(__name__)

KEYRING_NAME = "Anaconda Cloud"
KEYRING_CLIENT = "anaconda_cloud_auth"


LocalKeyringData = Dict[str, Dict[str, str]]


def _as_base64_string(payload: str) -> str:
    """Encode a string to a base64 string"""
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")


def _validate_access_token(
    access_token: str, algorithm_used: str, expected_hash: str
) -> None:
    """Validate the JWT token.

    We need to compute the hash of the access token and compare it with the hash that is present in the JWT.
    This is to ensure that the token is not tampered with.

    """

    # Get the standard name for the hash alg instead of the OIDC name
    hashlib_alg_name = jwt.get_algorithm_by_name(algorithm_used).hash_alg.name  # type: ignore

    hash = hashlib.new(hashlib_alg_name)
    hash.update(access_token.encode("utf-8"))
    digest = hash.digest()

    # The left half of the total hash contains the expected hash we are
    # looking for.
    # See https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.6
    digest_truncated = digest[: (len(digest) // 2)]

    # digest_truncated is bytes, so we decode and remove the == padding in base64
    computed_hash = (
        base64.urlsafe_b64encode(digest_truncated).decode("utf-8").rstrip("=")
    )

    if computed_hash != expected_hash:
        raise jwt.InvalidSignatureError()


def _validate_token_info(token_info: "TokenInfo") -> None:
    if token_info.id_token is None:
        # TODO: legacy IAM doesn't work w/ these validations
        return

    auth_config = AuthConfig()
    jwks_client = JWKClient(auth_config.oidc.jwks_uri)
    signing_key = jwks_client.get_signing_key_from_jwt(token_info.id_token)

    try:
        # parse JWT token and verify signature
        id_info = jwt.decode(
            token_info.id_token,
            key=signing_key.key,
            algorithms=auth_config.oidc.id_token_signing_alg_values_supported,
            audience=auth_config.client_id,
        )
    except jwt.exceptions.PyJWTError as e:
        raise InvalidTokenError(f"Error decoding token: {e}")

    # at this point, the jwt token should be verified and good to go
    # but we still need to verify the access token
    algorithm_used = jwt.get_unverified_header(token_info.id_token)["alg"]

    if token_info.access_token is None:
        raise TokenNotFoundError("No access token found to validate")

    try:
        _validate_access_token(
            token_info.access_token, algorithm_used, id_info["at_hash"]
        )
    except jwt.InvalidSignatureError:
        raise InvalidTokenError("Access token has an invalid hash.")


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
                token_info = {
                    "access_token": token.access_token,
                    "refresh_token": token.refresh_token,
                    "expires_at": token.expiration_date.astimezone().isoformat(),
                    "username": token.username,
                    "id_token": None,
                }
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
    access_token: Union[str, None] = None
    refresh_token: Union[str, None] = None
    expires_at: datetime = datetime(1, 1, 1, tzinfo=timezone.utc)
    username: Union[str, None] = None
    id_token: Union[str, None] = None

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

    def check(self) -> None:
        _validate_token_info(self)

    def refresh(self) -> None:
        """Refresh and save the tokens."""
        config = AuthConfig()
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
