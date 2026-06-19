from __future__ import annotations

from pytest import MonkeyPatch

from anaconda_auth.adapters import HTTPAdapter
from anaconda_auth.client import BaseClient

from .conftest import SKIP_IF_TRUSTSTORE_UNSUPPORTED


class _Sentinel:
    """Stand-in for an SSLContext; identity is all the adapter cares about."""


def test_init_poolmanager_forwards_ssl_context() -> None:
    sentinel = _Sentinel()
    adapter = HTTPAdapter(ssl_context=sentinel)

    assert adapter.poolmanager.connection_pool_kw.get("ssl_context") is sentinel


def test_proxy_manager_for_forwards_ssl_context() -> None:
    """The proxy connection pool must carry the same ssl_context as the direct
    pool. Regression for `ssl_verify: truststore` being silently dropped on the
    proxy path because `requests` builds a separate ProxyManager that never sees
    the adapter's pool kwargs."""
    sentinel = _Sentinel()
    adapter = HTTPAdapter(ssl_context=sentinel)

    proxy_manager = adapter.proxy_manager_for("http://proxy:8080")
    assert proxy_manager.connection_pool_kw.get("ssl_context") is sentinel


def test_proxy_manager_for_no_ssl_context_unchanged() -> None:
    """With no ssl_context (default ssl_verify True/False), the key must not be
    injected so the default proxy path is untouched."""
    adapter = HTTPAdapter(ssl_context=None)

    proxy_manager = adapter.proxy_manager_for("http://proxy:8080")
    assert "ssl_context" not in proxy_manager.connection_pool_kw


def test_init_poolmanager_no_ssl_context_unchanged() -> None:
    adapter = HTTPAdapter(ssl_context=None)

    assert "ssl_context" not in adapter.poolmanager.connection_pool_kw


@SKIP_IF_TRUSTSTORE_UNSUPPORTED
def test_client_truststore_ssl_context_reaches_proxy(monkeypatch: MonkeyPatch) -> None:
    """End-to-end at the client level: with `ssl_verify: truststore` and proxies
    in the environment, the mounted https adapter forwards the truststore
    SSLContext onto its proxy manager."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")

    client = BaseClient(ssl_verify="truststore", api_key="foo")
    assert client._ssl is not None

    adapter = client.get_adapter(
        "https://anaconda.com/.well-known/openid-configuration"
    )
    proxy_manager = adapter.proxy_manager_for("http://127.0.0.1:8080")

    assert proxy_manager.connection_pool_kw.get("ssl_context") is client._ssl
    # the direct pool must still carry it too
    assert adapter.poolmanager.connection_pool_kw.get("ssl_context") is client._ssl
