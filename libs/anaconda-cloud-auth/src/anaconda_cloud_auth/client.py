from typing import Any
from typing import Optional
from typing import Union
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
                r.headers[
                    "Authorization"
                ] = f"Bearer {self._token_info.get_access_token()}"
            except TokenNotFoundError:
                pass
        else:
            r.headers["Authorization"] = f"Bearer {self.api_key}"
        return r


class BaseClient(requests.Session):
    _user_agent: str = f"anaconda-cloud-auth/{version}"

    def __init__(
        self,
        domain: Optional[str] = None,
        api_key: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        super().__init__()

        kwargs = {}
        if domain is not None:
            kwargs["domain"] = domain
        if api_key is not None:
            kwargs["key"] = api_key

        self.config = APIConfig(**kwargs)
        self._base_url = f"https://{self.config.domain}"
        self.headers["User-Agent"] = user_agent or self._user_agent
        self.auth = BearerAuth(api_key=self.config.key)

    def request(
        self,
        method: Union[str, bytes],
        url: Union[str, bytes],
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        joined_url = urljoin(self._base_url, str(url))
        response = super().request(method, joined_url, *args, **kwargs)
        if response.status_code == 401 or response.status_code == 403:
            if response.request.headers.get("Authorization") is None:
                raise LoginRequiredError(
                    f"{response.reason}: You must login before using this API endpoint using\n"
                    f"  anaconda login"
                )
        return response


def client_factory(user_agent: Optional[str]) -> BaseClient:
    return BaseClient(user_agent=user_agent)
