from typing import Any
from typing import Optional
from typing import Union
from urllib.parse import urljoin

import requests
from requests import PreparedRequest
from requests import Response
from requests.auth import AuthBase

from anaconda_cloud_auth.config import APIConfig
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.token import TokenInfo


class BearerAuth(AuthBase):
    def __init__(self, domain: Optional[str] = None) -> None:
        if domain is None:
            domain = AuthConfig().domain

        self._token_info = TokenInfo(domain=domain)

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        r.headers["Authorization"] = f"Bearer {self._token_info.get_access_token()}"
        return r


class Client(requests.Session):
    def __init__(self, domain: Optional[str] = None):
        super().__init__()

        kwargs = {"domain": domain} if domain else {}
        self.config = APIConfig(**kwargs)
        self._base_url = f"https://{self.config.domain}"
        self.auth = BearerAuth()

    def request(
        self,
        method: Union[str, bytes],
        url: Union[str, bytes],
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        joined_url = urljoin(self._base_url, str(url))
        return super().request(method, joined_url, *args, **kwargs)
