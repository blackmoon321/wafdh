from __future__ import annotations

import socket
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

import httpx2

from wafdh.models import FetchFailure, FetchOk, FetchResult, ResponseSnapshot

_BODY_LIMIT = 4096


class HttpFetcher(Protocol):
    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> FetchResult: ...


@dataclass(frozen=True, slots=True)
class HttpClientConfig:
    timeout_seconds: float


class HttpClient:
    def __init__(self, client: httpx2.AsyncClient) -> None:
        self._client: httpx2.AsyncClient = client

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> FetchResult:
        try:
            response = await self._client.get(url, headers=headers, params=params)
        except httpx2.RequestError as exc:
            return FetchFailure(url=url, reason=str(exc))
        return FetchOk(response=_snapshot(response, url))


def create_async_client(config: HttpClientConfig) -> httpx2.AsyncClient:
    limits = httpx2.Limits(
        max_connections=200,
        max_keepalive_connections=40,
        keepalive_expiry=30.0,
    )
    timeout = httpx2.Timeout(
        connect=5.0,
        read=config.timeout_seconds,
        write=10.0,
        pool=10.0,
    )
    transport = httpx2.AsyncHTTPTransport(
        http2=True,
        retries=3,
        limits=limits,
        socket_options=[(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)],
    )
    return httpx2.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "wafdh/0.1 WAF detection probe"},
    )


def _snapshot(response: httpx2.Response, request_url: str) -> ResponseSnapshot:
    headers = tuple((key.lower(), value) for key, value in response.headers.items())
    return ResponseSnapshot(
        request_url=request_url,
        final_url=str(response.url),
        status_code=response.status_code,
        reason_phrase=response.reason_phrase,
        headers=headers,
        body_excerpt=response.text[:_BODY_LIMIT],
    )
