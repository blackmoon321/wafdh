from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from typing import override
from urllib.parse import parse_qsl, urljoin, urlparse

from wafdh.http_client import HttpFetcher
from wafdh.models import FetchFailure, FetchOk, ParameterSeed, ResponseSnapshot


class LinkAndFormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self._base_url: str = base_url
        self.links: list[str] = []
        self.parameters: list[ParameterSeed] = []

    @override
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value for key, value in attrs if value is not None}
        match tag.lower():
            case "a":
                href = attributes.get("href")
                if href is not None:
                    self.links.append(urljoin(self._base_url, href))
            case "form":
                action = attributes.get("action", self._base_url)
                self.links.append(urljoin(self._base_url, action))
            case "input" | "select" | "textarea":
                name = attributes.get("name")
                if name is not None:
                    self.parameters.append(ParameterSeed(url=self._base_url, name=name))
            case _:
                return


async def crawl_same_origin(
    *,
    fetcher: HttpFetcher,
    start: ResponseSnapshot,
    max_pages: int,
) -> tuple[ParameterSeed, ...]:
    if not _same_host(str(start.request_url), str(start.final_url)):
        return ()

    seen: set[str] = set()
    queue: deque[str] = deque([str(start.final_url)])
    discovered: list[ParameterSeed] = []

    while len(seen) < max_pages and len(queue) > 0:
        url = queue.popleft()
        if url in seen or not _same_host(str(start.request_url), url):
            continue
        seen.add(url)
        result = await fetcher.get(url)
        match result:
            case FetchOk(response=response):
                parser = LinkAndFormParser(str(response.final_url))
                parser.feed(response.body_excerpt)
                discovered.extend(_query_parameters(str(response.final_url)))
                discovered.extend(parser.parameters)
                queue.extend(
                    link for link in parser.links if _same_host(str(start.request_url), link)
                )
            case FetchFailure():
                continue
    return tuple(_dedupe(discovered))


def can_crawl_target(initial_url: str, final_url: str) -> bool:
    return _same_host(initial_url, final_url)


def _query_parameters(url: str) -> tuple[ParameterSeed, ...]:
    pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    return tuple(ParameterSeed(url=url, name=name) for name, _value in pairs)


def _same_host(left: str, right: str) -> bool:
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return left_parsed.hostname == right_parsed.hostname


def _dedupe(parameters: list[ParameterSeed]) -> list[ParameterSeed]:
    seen: set[tuple[str, str]] = set()
    deduped: list[ParameterSeed] = []
    for parameter in parameters:
        key = (parameter.url, parameter.name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(parameter)
    return deduped
