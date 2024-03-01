import json
import warnings
from functools import cached_property
from hashlib import md5
from typing import Any
from typing import Dict
from typing import Optional
from typing import Union
from typing import cast
from urllib.parse import urljoin

import requests
from requests import PreparedRequest
from requests import Response
from requests.auth import AuthBase

from anaconda_cloud_auth import __version__ as version
from anaconda_cloud_auth.config import APIConfig
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.exceptions import LoginRequiredError
from anaconda_cloud_auth.exceptions import TokenNotFoundError
from anaconda_cloud_auth.token import TokenInfo

# VersionInfo was renamed and is deprecated in semver>=3
try:
    from semver.version import Version
except ImportError:
    # In semver<3, it's called VersionInfo
    from semver import VersionInfo as Version


class BearerAuth(AuthBase):
    def __init__(
        self, domain: Optional[str] = None, api_key: Optional[str] = None
    ) -> None:
        self.api_key = api_key
        if domain is None:
            domain = AuthConfig().domain

        self._token_info = TokenInfo(domain=domain)

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        if not self.api_key:
            try:
                r.headers["Authorization"] = (
                    f"Bearer {self._token_info.get_access_token()}"
                )
            except TokenNotFoundError:
                pass
        else:
            r.headers["Authorization"] = f"Bearer {self.api_key}"
        return r


class BaseClient(requests.Session):
    _user_agent: str = f"anaconda-cloud-auth/{version}"
    _api_version: Optional[str] = None

    def __init__(
        self,
        base_uri: Optional[str] = None,
        domain: Optional[str] = None,
        api_key: Optional[str] = None,
        user_agent: Optional[str] = None,
        api_version: Optional[str] = None,
        ssl_verify: Optional[bool] = None,
        extra_headers: Optional[Union[str, dict]] = None,
    ):
        super().__init__()

        if base_uri and domain:
            raise ValueError("Can only specify one of `domain` or `base_uri` argument")

        kwargs: Dict[str, Any] = {}
        if domain is not None:
            kwargs["domain"] = domain
        if api_key is not None:
            kwargs["key"] = api_key
        if ssl_verify is not None:
            kwargs["ssl_verify"] = ssl_verify
        if extra_headers is not None:
            kwargs["extra_headers"] = extra_headers

        # kwargs in the client init take precedence over default
        # values or env vars
        self.config = APIConfig(**kwargs)

        # base_url overrides domain
        self._base_uri = base_uri or f"https://{self.config.domain}"
        self.headers["User-Agent"] = user_agent or self._user_agent
        self.api_version = api_version or self._api_version
        if self.api_version:
            self.headers["Api-Version"] = self.api_version

        if self.config.extra_headers is not None:
            if isinstance(self.config.extra_headers, str):
                try:
                    self.config.extra_headers = cast(
                        dict, json.loads(self.config.extra_headers)
                    )
                except json.decoder.JSONDecodeError:
                    raise ValueError(
                        f"{repr(self.config.extra_headers)} is not valid JSON."
                    )

            keys_to_add = self.config.extra_headers.keys() - self.headers.keys()
            for k in keys_to_add:
                self.headers[k] = self.config.extra_headers[k]

        self.auth = BearerAuth(api_key=self.config.key)

    def urljoin(self, url: str) -> str:
        return urljoin(self._base_uri, url)

    def request(
        self,
        method: Union[str, bytes],
        url: Union[str, bytes],
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        joined_url = self.urljoin(str(url))

        # Ensure we don't set `verify` twice. If it is passed as a kwarg to this method,
        # that becomes the value. Otherwise, we use the value in `self.config.ssl_verify`.
        kwargs.setdefault("verify", self.config.ssl_verify)

        response = super().request(method, joined_url, *args, **kwargs)
        if response.status_code == 401 or response.status_code == 403:
            if response.request.headers.get("Authorization") is None:
                raise LoginRequiredError(
                    f"{response.status_code} {response.reason}:\n"
                    f"You must login before using this API endpoint using\n"
                    f"  anaconda login\n"
                    f"or provide an api_key to your client."
                )
            elif response.json().get("error", {}).get("code", "") == "auth_required":
                raise LoginRequiredError(
                    f"{response.status_code} {response.reason}:\n"
                    f"The provided API key or login token is invalid.\n"
                    f"You may login again using\n"
                    f"  anaconda login\n"
                    f"or update the api_key provided to your client."
                )

        self._validate_api_version(response.headers.get("Min-Api-Version"))

        return response

    @cached_property
    def account(self) -> dict:
        res = self.get("/api/account")
        res.raise_for_status()
        account = res.json()
        return account

    @property
    def name(self) -> str:
        user = self.account.get("user", {})

        first_name = user.get("first_name", "")
        last_name = user.get("last_name", "")
        if not first_name and not last_name:
            return self.email
        else:
            return f"{first_name} {last_name}".strip()

    @property
    def email(self) -> str:
        value = self.account.get("user", {}).get("email")
        if value is None:
            raise ValueError(
                "Something is wrong with your account. An email address could not be found."
            )
        else:
            return value

    @cached_property
    def avatar(self) -> Union[bytes, None]:
        hashed = md5(self.email.encode("utf-8")).hexdigest()
        res = requests.get(
            f"https://gravatar.com/avatar/{hashed}.png?size=120&d=404",
            verify=self.config.ssl_verify,
        )
        if res.ok:
            return res.content
        else:
            return None

    def _validate_api_version(self, min_api_version_string: Optional[str]) -> None:
        """Validate that the client API version against the min API version from the service."""
        if min_api_version_string is None or self.api_version is None:
            return None

        # Convert to optional Version objects
        api_version = _parse_semver_string(self.api_version)
        min_api_version = _parse_semver_string(min_api_version_string)

        if api_version is None or min_api_version is None:
            return None

        if api_version < min_api_version:
            warnings.warn(
                f"Client API version is {self.api_version}, minimum supported API version is {min_api_version_string}. "
                "You may need to update your client.",
                DeprecationWarning,
            )


def _parse_semver_string(version: str) -> Optional[Version]:
    """Parse a version string into a semver Version object, stripping off any leading zeros from the components.

    If the version string is invalid, returns None.

    """
    norm_version = ".".join(s.lstrip("0") for s in version.split("."))
    try:
        return Version.parse(norm_version)
    except ValueError:
        return None


def client_factory(
    user_agent: Optional[str], api_version: Optional[str] = None
) -> BaseClient:
    return BaseClient(user_agent=user_agent, api_version=api_version)
