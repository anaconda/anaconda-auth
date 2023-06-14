import os
from typing import Any
from typing import Union
from urllib.parse import urljoin

import requests
from requests import PreparedRequest
from requests import Response
from requests.auth import AuthBase

from anaconda_cloud_auth.token import TokenInfo


class BearerAuth(AuthBase):
    def __init__(self) -> None:
        self._token_info = TokenInfo()

    def __call__(self, r: PreparedRequest) -> PreparedRequest:
        r.headers["Authorization"] = f"Bearer {self._token_info.get_access_token()}"
        return r


class Client(requests.Session):
    def __init__(self, base_url: Union[str, None] = None):
        super().__init__()
        self.base_url = base_url or os.getenv("BASE_URL", "https://anaconda.cloud")
        self.auth = BearerAuth()

    def request(
        self,
        method: Union[str, bytes],
        url: Union[str, bytes],
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        if self.base_url is not None:
            joined_url = urljoin(self.base_url, str(url))
        else:
            joined_url = str(url)
        return super().request(method, joined_url, *args, **kwargs)
