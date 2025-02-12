import json
import warnings
from functools import cached_property
from hashlib import md5
from typing import Any
from typing import Dict
from typing import Optional
from typing import Union
from typing import cast
from typing import overload
from typing import Literal

import niquests
from niquests import Response, PreparedRequest, AsyncResponse
from niquests.auth import BearerTokenAuth, AuthBase
from niquests.structures import CaseInsensitiveDict
from niquests._typing import HttpMethodType, HookCallableType

from anaconda_auth import __version__ as version
from anaconda_auth.config import AnacondaCloudConfig
from anaconda_auth.exceptions import TokenExpiredError
from anaconda_auth.exceptions import TokenNotFoundError
from anaconda_auth.token import TokenInfo

# VersionInfo was renamed and is deprecated in semver>=3
try:
    from semver.version import Version
except ImportError:
    # In semver<3, it's called VersionInfo
    from semver import VersionInfo as Version


def login_required(response: Response, *args: Any, **kwargs: Any) -> Union[PreparedRequest, Response]:
    if response.request is None:
        return response

    if response.request.headers is None:
        return response

    has_auth_header = response.request.headers.get("Authorization", False)

    if response.status_code in [401, 403]:
        try:
            error_code = response.json().get("error", {}).get("code", "")
        except niquests.JSONDecodeError:
            error_code = ""

        if error_code == "auth_required":
            if has_auth_header:
                response.reason = "Your API key or login token is invalid."
            else:
                response.reason = (
                    "You must login before using this API endpoint"
                    " or provide an api_key to your client."
                )

    return response

class TokenInfoAuth(AuthBase):
    def __init__(
        self, token_info: TokenInfo
    ) -> None:
        self._token_info = token_info

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        if r.headers is None:
            r.headers = CaseInsensitiveDict()
        try:
            r.headers["Authorization"] = (
                f"Bearer {self._token_info.get_access_token()}"
            )
        except (TokenNotFoundError, TokenExpiredError):
            pass
        return r

class AnacondaClientMixin():
    _user_agent: str = f"anaconda-auth/{version}"
    _api_version: Optional[str] = None
    token_info: Optional[TokenInfo] = None
    headers: Any
    hooks: Any
    auth: Any
    base_url: Any

    def _initialize(
        self,
        domain: Optional[str] = None,
        api_key: Optional[str] = None,
        user_agent: Optional[str] = None,
        api_version: Optional[str] = None,
        ssl_verify: Optional[bool] = None,
        extra_headers: Optional[Union[str, dict]] = None,
    ) -> None:
        config_kwargs: Dict[str, Any] = {}
        if domain is not None:
            config_kwargs["domain"] = domain
        if api_key is not None:
            config_kwargs["api_key"] = api_key
        if ssl_verify is not None:
            config_kwargs["ssl_verify"] = ssl_verify
        if extra_headers is not None:
            config_kwargs["extra_headers"] = extra_headers

        self.config = AnacondaCloudConfig(**config_kwargs)

        self.base_url = f"https://{self.config.domain}"
        self.headers["User-Agent"] = user_agent or self._user_agent
        self.verify = self.config.ssl_verify
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

        self.hooks["response"].append(cast(HookCallableType, login_required))

        if self.config.api_key:
            self.auth = BearerTokenAuth(self.config.api_key)
        else:
            self.token_info = TokenInfo(domain=self.config.domain)
            self.auth = TokenInfoAuth(self.token_info)

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


class BaseClient(niquests.Session, AnacondaClientMixin):
    def __init__(
        self,
        domain: Optional[str] = None,
        api_key: Optional[str] = None,
        user_agent: Optional[str] = None,
        api_version: Optional[str] = None,
        ssl_verify: Optional[bool] = None,
        extra_headers: Optional[Union[str, dict]] = None,
        **session_kwargs: Any
    ):
        super().__init__(**session_kwargs)
        self._initialize(
            domain=domain,
            api_key=api_key,
            user_agent=user_agent,
            api_version=api_version,
            ssl_verify=ssl_verify,
            extra_headers=extra_headers
        )

    def request(
        self,
        method: HttpMethodType,
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        # Ensure we don't set `verify` twice. If it is passed as a kwarg to this method,
        # that becomes the value. Otherwise, we use the value in `self.config.ssl_verify`.
        if kwargs.get("verify") is None:
            kwargs["verify"] = self.config.ssl_verify

        response = super().request(method, *args, **kwargs)

        min_api_version_string = response.headers.get("Min-Api-Version")
        self._validate_api_version(min_api_version_string)

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
        res = niquests.get(
            f"https://gravatar.com/avatar/{hashed}.png?size=120&d=404",
            verify=self.config.ssl_verify,
        )
        if res.ok:
            return res.content
        else:
            return None


class BaseAsyncClient(niquests.AsyncSession, AnacondaClientMixin):
    def __init__(
        self,
        domain: Optional[str] = None,
        api_key: Optional[str] = None,
        user_agent: Optional[str] = None,
        api_version: Optional[str] = None,
        ssl_verify: Optional[bool] = None,
        extra_headers: Optional[Union[str, dict]] = None,
    ):
        super().__init__()
        self._initialize(
            domain=domain,
            api_key=api_key,
            user_agent=user_agent,
            api_version=api_version,
            ssl_verify=ssl_verify,
            extra_headers=extra_headers
        )

    async def request(  # type: ignore[override]
        self,
        method: HttpMethodType,
        *args: Any,
        **kwargs: Any,
    ) -> Union[AsyncResponse, Response]:
        # Ensure we don't set `verify` twice. If it is passed as a kwarg to this method,
        # that becomes the value. Otherwise, we use the value in `self.config.ssl_verify`.
        if kwargs.get("verify") is None:
            kwargs["verify"] = self.config.ssl_verify

        response = await super().request(method, *args, **kwargs)

        min_api_version_string = response.headers.get("Min-Api-Version")
        self._validate_api_version(min_api_version_string)

        return response


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
