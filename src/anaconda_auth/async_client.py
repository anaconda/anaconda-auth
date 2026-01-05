from functools import cached_property
from typing import Any
from typing import Union

from niquests import PreparedRequest
from niquests import Request
from niquests import Response
from niquests.adapters import AsyncHTTPAdapter
from niquests.async_api import AsyncSession

from anaconda_auth.adapters import _SSLContextAdapterMixin
from anaconda_auth.client import BaseClient


class NiHTTPAdapter(_SSLContextAdapterMixin, AsyncHTTPAdapter):
    pass


# add BaseClient superclass to pick up properties
class AsyncBaseClient(AsyncSession, BaseClient):
    """Version of client.BaseClient for use in async contexts.

    This uses the niquests library for IO, importing of which
    may have side effects. You must therefore explicitly import
    this module in order to use the async client. Otherwise,
    normal Session methods (get, post, etc.) will be async
    but otherwise work the same as their requests counterparts.
    """

    def __init__(self, **kwargs):
        super().__init__()
        # account must be known immediately - use requests
        sync_client = BaseClient(**kwargs)
        self._account = sync_client.account
        BaseClient.__init__(self, **kwargs)

    def mounting(self, ssl_context) -> None:
        http_adapter = NiHTTPAdapter(ssl_context=ssl_context)

        self.mount("http://", http_adapter)
        self.mount("https://", http_adapter)

    @cached_property
    def account(self) -> dict:
        return self._account

    def prepare_request(self, request: Request) -> PreparedRequest:
        request.url = self.urljoin(str(request.url))
        return super().prepare_request(request)

    async def request(
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

        response = await super().request(method, joined_url, *args, **kwargs)

        min_api_version_string = response.headers.get("Min-Api-Version")
        self._validate_api_version(min_api_version_string)

        return response
