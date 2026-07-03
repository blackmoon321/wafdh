from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, assert_never
from urllib.parse import urlparse

from wafdh.models import LlmProvider, Target, TargetUrl

MAX_WORKER_COUNT: Final = 64
MAX_CODEX_CONCURRENCY: Final = 4
WORKER_COUNT_BUCKETS: Final[tuple[tuple[int, int], ...]] = (
    (1, 1),
    (10, 4),
    (100, 10),
    (1_000, 25),
    (10_000, 50),
)


@dataclass(frozen=True, slots=True)
class ScanConfig:
    worker_count: int = 1
    timeout_seconds: float = 7.0
    max_pages: int = 4
    max_payloads_per_target: int = 12
    codex_model: str = "gpt-5.5"
    codex_primary_reasoning_effort: str = "high"
    codex_escalation_reasoning_effort: str = "xhigh"
    codex_concurrency: int = 1
    llm_provider: LlmProvider = LlmProvider.CODEX


@dataclass(frozen=True, slots=True)
class CliScanOptions:
    worker_count: int
    timeout_seconds: float
    max_pages: int
    max_payloads_per_target: int
    llm_provider: LlmProvider


def build_config(options: CliScanOptions) -> ScanConfig:
    return ScanConfig(
        worker_count=options.worker_count,
        timeout_seconds=options.timeout_seconds,
        max_pages=options.max_pages,
        max_payloads_per_target=options.max_payloads_per_target,
        codex_concurrency=select_codex_concurrency(options.worker_count),
        llm_provider=options.llm_provider,
    )


def select_worker_count(submitted_target_count: int, llm_provider: LlmProvider) -> int:
    effective_target_count = max(1, submitted_target_count)
    for max_targets, worker_count in WORKER_COUNT_BUCKETS:
        if effective_target_count <= max_targets:
            return _cap_worker_count(min(effective_target_count, worker_count), llm_provider)
    return _cap_worker_count(min(effective_target_count, MAX_WORKER_COUNT), llm_provider)


def count_submitted_targets(raw_targets: tuple[str, ...]) -> int:
    return sum(1 for raw_target in raw_targets if raw_target.strip() != "")


def select_codex_concurrency(worker_count: int) -> int:
    return min(max(1, worker_count), MAX_CODEX_CONCURRENCY)


def _cap_worker_count(worker_count: int, llm_provider: LlmProvider) -> int:
    match llm_provider:
        case LlmProvider.CODEX:
            return min(worker_count, MAX_CODEX_CONCURRENCY)
        case LlmProvider.OFF:
            return worker_count
    assert_never(llm_provider)


def expand_targets(raw_targets: tuple[str, ...]) -> tuple[Target, ...]:
    targets: list[Target] = []
    for raw_target in raw_targets:
        cleaned = raw_target.strip()
        if cleaned == "":
            continue
        parsed = urlparse(cleaned)
        if parsed.scheme in {"http", "https"}:
            targets.append(Target(TargetUrl(cleaned)))
            continue
        if parsed.scheme != "":
            continue
        targets.append(Target(TargetUrl(f"https://{cleaned}")))
        targets.append(Target(TargetUrl(f"http://{cleaned}")))
    return tuple(targets)


def read_target_file(path: Path) -> tuple[str, ...]:
    return tuple(line.strip() for line in path.read_text(encoding="utf-8").splitlines())
