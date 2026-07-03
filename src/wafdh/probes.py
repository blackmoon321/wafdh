from __future__ import annotations

from dataclasses import dataclass

from wafdh.crawler import can_crawl_target
from wafdh.http_client import HttpFetcher
from wafdh.models import FetchFailure, FetchOk, ParameterSeed, PayloadEvidence
from wafdh.payloads import DEFAULT_PARAMETER, DEFAULT_PAYLOADS


@dataclass(frozen=True, slots=True)
class PayloadRun:
    fetcher: HttpFetcher
    baseline_url: str
    seeds: tuple[ParameterSeed, ...]
    max_payloads: int


async def run_payloads(run: PayloadRun) -> tuple[PayloadEvidence, ...]:
    evidence: list[PayloadEvidence] = []
    for seed in run.seeds:
        for payload in DEFAULT_PAYLOADS:
            if len(evidence) >= run.max_payloads:
                return tuple(evidence)
            result = await run.fetcher.get(seed.url, params={seed.name: payload.value})
            match result:
                case FetchOk(response=response):
                    evidence.append(
                        PayloadEvidence(
                            name=payload.name,
                            target_url=seed.url,
                            parameter=seed.name,
                            response=response,
                            error=None,
                        )
                    )
                case FetchFailure(reason=reason):
                    evidence.append(
                        PayloadEvidence(
                            name=payload.name,
                            target_url=run.baseline_url,
                            parameter=seed.name,
                            response=None,
                            error=reason,
                        )
                    )
    return tuple(evidence)


def payload_seeds(
    target_url: str,
    final_url: str,
    discovered: tuple[ParameterSeed, ...],
) -> tuple[ParameterSeed, ...]:
    if not can_crawl_target(target_url, final_url):
        return (ParameterSeed(url=target_url, name=DEFAULT_PARAMETER),)
    if len(discovered) == 0:
        return (ParameterSeed(url=final_url, name=DEFAULT_PARAMETER),)
    return discovered
