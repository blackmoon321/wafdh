from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from wafdh.config import ScanConfig
from wafdh.crawler import can_crawl_target, crawl_same_origin
from wafdh.detector import WafDetector
from wafdh.http_client import HttpClient, HttpClientConfig, HttpFetcher, create_async_client
from wafdh.llm import LlmClassificationError, LlmConfig
from wafdh.llm_codex import CodexLlmAnalyzer
from wafdh.models import (
    Detection,
    DetectionSource,
    FetchFailure,
    FetchOk,
    FinalVerdict,
    LlmProvider,
    LlmVerdict,
    ScanReport,
    Target,
    TargetReport,
    WafStatus,
)
from wafdh.probes import PayloadRun, payload_seeds, run_controls, run_payloads
from wafdh.signatures import SignatureMatcher, load_rules
from wafdh.verdicts import resolve_final_verdict

type ScanProgressCallback = Callable[[TargetReport], None]


class LlmClassifier(Protocol):
    async def analyze(self, partial_report: TargetReport) -> LlmVerdict: ...


@dataclass(frozen=True, slots=True)
class AgentRuntime:
    config: ScanConfig
    fetcher: HttpFetcher
    detector: WafDetector
    llm: LlmClassifier | None


@dataclass(frozen=True, slots=True)
class ScanWorker:
    worker_id: int
    runtime: AgentRuntime

    async def scan(self, target: Target) -> TargetReport:
        baseline_result = await self.runtime.fetcher.get(str(target.url))
        match baseline_result:
            case FetchFailure(reason=reason):
                return _failed_report(target, reason)
            case FetchOk(response=baseline):
                discovered = await crawl_same_origin(
                    fetcher=self.runtime.fetcher,
                    start=baseline,
                    max_pages=self.runtime.config.max_pages,
                )
                seeds = payload_seeds(str(target.url), str(baseline.final_url), discovered)
                payload_run = PayloadRun(
                    fetcher=self.runtime.fetcher,
                    baseline_url=str(baseline.final_url),
                    seeds=seeds,
                    max_payloads=self.runtime.config.max_payloads_per_target,
                )
                controls = await run_controls(payload_run)
                payloads = await run_payloads(payload_run)
                detections = self.runtime.detector.detect(
                    baseline=baseline,
                    controls=controls,
                    payloads=payloads,
                )
                partial = TargetReport(
                    target=str(target.url),
                    final_url=str(baseline.final_url),
                    waf_status=_waf_status(detections, len(payloads)),
                    crawled=can_crawl_target(str(target.url), str(baseline.final_url)),
                    baseline=baseline,
                    controls=controls,
                    discovered_parameters=discovered,
                    detections=detections,
                    payloads=payloads,
                    llm_verdict=None,
                    final_verdict=None,
                    errors=(),
                )
                llm_verdict = (
                    await self.runtime.llm.analyze(partial)
                    if self.runtime.llm is not None
                    else None
                )
                merged_detections = _merge_llm_detection(detections, llm_verdict)
                final_verdict = resolve_final_verdict(
                    detections,
                    llm_verdict,
                    payload_count=len(payloads),
                )
                return TargetReport(
                    target=str(target.url),
                    final_url=str(baseline.final_url),
                    waf_status=_waf_status_from_final(final_verdict, len(payloads)),
                    crawled=partial.crawled,
                    baseline=baseline,
                    controls=controls,
                    discovered_parameters=discovered,
                    detections=merged_detections,
                    payloads=payloads,
                    llm_verdict=llm_verdict,
                    final_verdict=final_verdict,
                    errors=(),
                )


class MainAgent:
    def __init__(self, config: ScanConfig) -> None:
        self._config: ScanConfig = config

    async def scan(
        self,
        targets: tuple[Target, ...],
        progress_callback: ScanProgressCallback | None = None,
    ) -> ScanReport:
        if len(targets) == 0:
            return _scan_report(self._config.worker_count, ())
        async with create_async_client(
            HttpClientConfig(timeout_seconds=self._config.timeout_seconds)
        ) as client:
            fetcher = HttpClient(client)
            matcher = SignatureMatcher(load_rules())
            detector = WafDetector(matcher)
            llm = _llm_analyzer(self._config)
            reports = await _run_workers(
                AgentRuntime(
                    config=self._config,
                    fetcher=fetcher,
                    detector=detector,
                    llm=llm,
                ),
                targets,
                progress_callback,
            )
        return _scan_report(self._config.worker_count, reports)


async def _run_workers(
    runtime: AgentRuntime,
    targets: tuple[Target, ...],
    progress_callback: ScanProgressCallback | None,
) -> tuple[TargetReport, ...]:
    target_sender, target_receiver = anyio.create_memory_object_stream[Target](len(targets))
    report_sender, report_receiver = anyio.create_memory_object_stream[TargetReport](len(targets))
    reports: list[TargetReport] = []
    async with anyio.create_task_group() as task_group:
        for worker_id in range(1, runtime.config.worker_count + 1):
            scan_worker = ScanWorker(worker_id, runtime)
            _ = task_group.start_soon(
                _worker_loop,
                scan_worker,
                target_receiver.clone(),
                report_sender.clone(),
            )
        await target_receiver.aclose()
        await report_sender.aclose()
        async with target_sender:
            for target in targets:
                await target_sender.send(target)
        for _target in targets:
            report = await report_receiver.receive()
            reports.append(report)
            if progress_callback is not None:
                progress_callback(report)
        await report_receiver.aclose()
    return tuple(reports)


async def _worker_loop(
    scan_worker: ScanWorker,
    receiver: MemoryObjectReceiveStream[Target],
    sender: MemoryObjectSendStream[TargetReport],
) -> None:
    async with receiver, sender:
        async for target in receiver:
            try:
                report = await scan_worker.scan(target)
            except LlmClassificationError:
                raise
            except Exception as exc:  # noqa: BLE001
                report = _failed_report(
                    target,
                    f"Unhandled target scan error: {type(exc).__name__}: {exc}",
                )
            await sender.send(report)


def _failed_report(target: Target, reason: str) -> TargetReport:
    return TargetReport(
        target=str(target.url),
        final_url=None,
        waf_status=WafStatus.SCAN_FAILED,
        crawled=False,
        baseline=None,
        controls=(),
        discovered_parameters=(),
        detections=(),
        payloads=(),
        llm_verdict=None,
        final_verdict=None,
        errors=(reason,),
    )


def _llm_analyzer(config: ScanConfig) -> LlmClassifier | None:
    llm_config = LlmConfig(
        model=config.codex_model,
        primary_reasoning_effort=config.codex_primary_reasoning_effort,
        escalation_reasoning_effort=config.codex_escalation_reasoning_effort,
        concurrency=config.codex_concurrency,
        turn_timeout_seconds=config.codex_turn_timeout_seconds,
        max_attempts=config.codex_max_attempts,
    )
    match config.llm_provider:
        case LlmProvider.CODEX:
            return CodexLlmAnalyzer(config=llm_config)
        case LlmProvider.OFF:
            return None


def _merge_llm_detection(
    detections: tuple[Detection, ...],
    verdict: LlmVerdict | None,
) -> tuple[Detection, ...]:
    if verdict is None or not verdict.detected or verdict.waf_name is None:
        return detections
    llm_detection = Detection(
        source=DetectionSource.LLM,
        name=verdict.waf_name,
        manufacturer="Custom or unknown",
        confidence=verdict.confidence,
        reason=verdict.rationale,
    )
    return (llm_detection, *detections)


def _waf_status(detections: tuple[Detection, ...], payload_count: int) -> WafStatus:
    if len(detections) > 0:
        return WafStatus.DETECTED
    if payload_count == 0:
        return WafStatus.UNKNOWN
    return WafStatus.NOT_DETECTED


def _waf_status_from_final(verdict: FinalVerdict, payload_count: int) -> WafStatus:
    if verdict.detected:
        return WafStatus.DETECTED
    if payload_count == 0:
        return WafStatus.UNKNOWN
    return WafStatus.NOT_DETECTED


def _scan_report(worker_count: int, targets: tuple[TargetReport, ...]) -> ScanReport:
    return ScanReport(
        generated_at=datetime.now(tz=UTC).isoformat(),
        worker_count=worker_count,
        target_count=len(targets),
        targets=targets,
    )
