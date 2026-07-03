from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, NewType

from pydantic import BaseModel, ConfigDict, Field

TargetUrl = NewType("TargetUrl", str)


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DetectionSource(StrEnum):
    SIGNATURE = "signature"
    GENERIC = "generic"
    LLM = "llm"


class LlmProvider(StrEnum):
    CODEX = "codex"
    OFF = "off"


class WafStatus(StrEnum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    UNKNOWN = "unknown"
    SCAN_FAILED = "scan_failed"


@dataclass(frozen=True, slots=True)
class Target:
    url: TargetUrl


@dataclass(frozen=True, slots=True)
class ParameterSeed:
    url: str
    name: str


class ResponseSnapshot(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    request_url: str
    final_url: str
    status_code: int
    reason_phrase: str
    headers: tuple[tuple[str, str], ...]
    body_excerpt: str = Field(max_length=16384)
    redirects: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FetchOk:
    response: ResponseSnapshot


@dataclass(frozen=True, slots=True)
class FetchFailure:
    url: str
    reason: str


type FetchResult = FetchOk | FetchFailure


class PayloadEvidence(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    name: str
    target_url: str
    parameter: str | None
    response: ResponseSnapshot | None
    error: str | None


class Detection(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    source: DetectionSource
    name: str
    manufacturer: str
    confidence: Confidence
    reason: str


class LlmVerdict(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    enabled: bool
    model: str
    reasoning_effort: str | None = None
    detected: bool
    waf_name: str | None
    confidence: Confidence
    rationale: str
    suggested_rule: str | None = None


class FinalVerdict(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    source: DetectionSource | None
    detected: bool
    waf_name: str | None
    confidence: Confidence
    rationale: str


class TargetReport(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    target: str
    final_url: str | None
    waf_status: WafStatus
    crawled: bool
    baseline: ResponseSnapshot | None = None
    controls: tuple[PayloadEvidence, ...] = ()
    discovered_parameters: tuple[ParameterSeed, ...]
    detections: tuple[Detection, ...]
    payloads: tuple[PayloadEvidence, ...]
    llm_verdict: LlmVerdict | None
    final_verdict: FinalVerdict | None = None
    errors: tuple[str, ...]


class ScanReport(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    generated_at: str
    worker_count: int
    target_count: int
    targets: tuple[TargetReport, ...]
