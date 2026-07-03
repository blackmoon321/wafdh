from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from wafdh.models import Confidence, LlmVerdict, PayloadEvidence, TargetReport

type JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


class LlmJsonVerdict(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    detected: bool
    waf_name: str | None
    confidence: Confidence
    rationale: str = Field(max_length=1000)
    suggested_rule: str | None = None


@dataclass(frozen=True, slots=True)
class LlmConfig:
    model: str
    primary_reasoning_effort: str
    escalation_reasoning_effort: str
    concurrency: int


def build_codex_prompt(report: TargetReport, previous: LlmVerdict | None = None) -> str:
    return _classifier_prompt(report, previous)


def _classifier_prompt(report: TargetReport, previous: LlmVerdict | None) -> str:
    base = (
        "You are a WAF detection classifier for authorized defensive testing.\n"
        "Return JSON only. Do not include markdown.\n"
        "Classify the evidence into the schema fields: detected, waf_name, confidence, "
        "rationale, suggested_rule.\n"
        "Use known WAF signatures as evidence, but decide the final WAF name yourself. "
        "For custom WAFs, infer the most specific product name supported by headers, cookies, "
        "block-page text, redirects, and payload-vs-baseline differences. If evidence is "
        "insufficient, set detected=false and waf_name=null.\n\n"
        f"{_evidence_text(report)}"
    )
    if previous is None:
        return base
    return f"{base}\n\nPrevious verdict:\n{previous.model_dump_json()}\nReview and correct it."


def parse_codex_response_text(raw_text: str, model: str) -> LlmVerdict:
    try:
        parsed = LlmJsonVerdict.model_validate_json(raw_text.strip())
    except ValidationError as exc:
        return LlmVerdict(
            enabled=True,
            model=model,
            detected=False,
            waf_name=None,
            confidence=Confidence.LOW,
            rationale=f"Codex response parsing failed: {exc}",
        )
    return LlmVerdict(
        enabled=True,
        model=model,
        detected=parsed.detected,
        waf_name=parsed.waf_name,
        confidence=parsed.confidence,
        rationale=parsed.rationale,
        suggested_rule=parsed.suggested_rule,
    )


def _evidence_text(report: TargetReport) -> str:
    payload_lines = "\n".join(_payload_line(payload) for payload in report.payloads)
    detection_lines = "\n".join(
        f"- {detection.source}: {detection.name} / {detection.reason}"
        for detection in report.detections
    )
    return (
        f"Target: {report.target}\n"
        f"Final URL: {report.final_url}\n"
        f"Crawled: {report.crawled}\n"
        f"Deterministic detections:\n{detection_lines}\n"
        f"Payload evidence:\n{payload_lines}"
    )


def _payload_line(payload: PayloadEvidence) -> str:
    response = payload.response
    if response is None:
        return f"- {payload.name} {payload.target_url}: error={payload.error}"
    headers = "; ".join(f"{key}={value[:80]}" for key, value in response.headers[:8])
    return (
        f"- {payload.name} status={response.status_code} final={response.final_url} "
        f"headers={headers} body={response.body_excerpt[:300]!r}"
    )


def llm_error_verdict(model: str, rationale: str) -> LlmVerdict:
    return LlmVerdict(
        enabled=True,
        model=model,
        detected=False,
        waf_name=None,
        confidence=Confidence.LOW,
        rationale=rationale,
    )


def verdict_schema() -> dict[str, JsonValue]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "detected": {"type": "boolean"},
            "waf_name": {"type": ["string", "null"]},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "rationale": {"type": "string"},
            "suggested_rule": {"type": ["string", "null"]},
        },
        "required": [
            "detected",
            "waf_name",
            "confidence",
            "rationale",
            "suggested_rule",
        ],
    }
