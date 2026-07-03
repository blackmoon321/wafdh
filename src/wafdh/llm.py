from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from typing import ClassVar, override

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from wafdh.models import (
    Confidence,
    LlmVerdict,
    PayloadEvidence,
    ResponseSnapshot,
    TargetReport,
)

type JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]

_INTERESTING_HEADER_NAMES = {
    "server",
    "set-cookie",
    "cf-ray",
    "cf-cache-status",
    "cf-mitigated",
    "x-iinfo",
    "x-amzn-waf-action",
    "x-amzn-errortype",
    "x-blocked-by-waf",
    "x-sucuri-id",
    "x-sucuri-block",
    "x-sucuri-cache",
    "x-request-id",
    "x-dealeron-backend",
    "x-dealeron-original-url",
    "x-loopia-node",
    "x-sl-compstate",
    "x-data-origin",
    "x-safe-firewall",
    "x-protected-by",
    "x-cdn",
    "secured",
    "x-transip-backend",
    "x-transip-balancer",
    "via",
    "content-type",
    "content-length",
    "cache-control",
}
_INTERESTING_HEADER_PREFIXES = (
    "x-amzn-waf-",
    "x-akamai-",
    "x-azure-",
    "x-sucuri-",
    "cf-",
)
_BODY_MARKER_PATTERNS = (
    r"attention required! \| cloudflare",
    r"__cf\$cv\$params",
    r"incapsula incident id",
    r"_incapsula_resource",
    r"the requested url was rejected",
    r"support id",
    r"web firewall security policies",
    r"hmg cloud waf",
    r"detect client ip",
    r"mod.?security",
    r"wordfence",
    r"webknight",
    r"fortiwafsid",
    r"security provided by datadog",
    r"forbidden - id:\s*[0-9a-f]{16,}",
    r"microsoft-azure-application-gateway",
    r"perimeterx",
    r"barracuda",
    r"radware",
    r"reblaze",
    r"distilcaptchaform",
    r"blocked by naxsi",
    r"zscaler",
    r"stackpath",
    r"bitninja",
    r"sonicwall",
    r"palo alto next generation",
    r"malcare",
    r"secupress",
    r"safe3waf",
    r"safedog",
    r"godaddy website firewall",
    r"shieldon",
    r"access denied",
    r"request rejected",
    r"security policy",
    r"blocked",
)


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
    turn_timeout_seconds: float
    max_attempts: int


@dataclass(frozen=True, slots=True)
class LlmClassificationError(Exception):
    model: str
    failures: tuple[str, ...]

    @override
    def __str__(self) -> str:
        return (
            f"required LLM classification failed for {self.model} "
            f"after {len(self.failures)} attempts: {'; '.join(self.failures)}"
        )


def build_codex_prompt(report: TargetReport, previous: LlmVerdict | None = None) -> str:
    return _classifier_prompt(report, previous)


def _classifier_prompt(report: TargetReport, previous: LlmVerdict | None) -> str:
    base = (
        "You are a WAF detection classifier for authorized defensive testing.\n"
        "Return JSON only. Do not include markdown.\n"
        "Classify the evidence into the schema fields: detected, waf_name, confidence, "
        "rationale, suggested_rule.\n"
        "Use known WAF signatures as evidence, but keep attribution conservative. "
        "Do not turn CDN, load balancer, hosting, appliance login, or plain server headers "
        "into a named WAF unless a vendor-specific block/challenge marker is present. "
        "Compare baseline, benign control, and malicious payload responses. If the benign "
        "control is blocked the same way as malicious payloads, do not treat that response as "
        "payload-specific WAF evidence. For custom WAFs, use the most specific supported "
        "generic/platform label when no public product marker exists. For Korean WAF candidates, "
        "consider names such as WAPPLES, Cloudbric, AIONCLOUD/AIWAF, WEBFRONT-K, F1-WebCastle, "
        "WINS SNIPER, eWalker, WEBS-RAY, or Samsung SDS WAF only when explicit response markers "
        "support them; never infer them from product-list text alone. If evidence is "
        "insufficient for WAF behavior, set detected=false and waf_name=null.\n\n"
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
    baseline_line = (
        _response_line("baseline", report.baseline) if report.baseline is not None else "- missing"
    )
    control_lines = "\n".join(_payload_line(payload) for payload in report.controls)
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
        f"Baseline response:\n{baseline_line}\n"
        f"Control evidence:\n{control_lines}\n"
        f"Payload evidence:\n{payload_lines}"
    )


def _payload_line(payload: PayloadEvidence) -> str:
    response = payload.response
    if response is None:
        return f"- {payload.name} {payload.target_url}: error={payload.error}"
    return _response_line(payload.name, response)


def _response_line(label: str, response: ResponseSnapshot) -> str:
    redirects = " -> ".join(response.redirects)
    redirect_text = f" redirects={redirects}" if redirects != "" else ""
    return (
        f"- {label} status={response.status_code} reason={response.reason_phrase!r} "
        f"final={response.final_url}{redirect_text} "
        f"headers={_headers_text(response.headers)} "
        f"body_len={len(response.body_excerpt)} "
        f"body_sha256={_body_hash(response.body_excerpt)} "
        f"body={_body_text(response.body_excerpt)!r}"
    )


def _headers_text(headers: tuple[tuple[str, str], ...]) -> str:
    selected = tuple(_interesting_headers(headers))
    if len(selected) == 0:
        selected = headers[:12]
    return "; ".join(f"{key}={value[:160]}" for key, value in selected)


def _interesting_headers(headers: tuple[tuple[str, str], ...]) -> Iterable[tuple[str, str]]:
    for key, value in headers:
        if key in _INTERESTING_HEADER_NAMES or key.startswith(_INTERESTING_HEADER_PREFIXES):
            yield key, value


def _body_hash(body: str) -> str:
    return sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]


def _body_text(body: str) -> str:
    snippets = tuple(_marker_snippets(body))
    if len(snippets) > 0:
        return " ... ".join(snippets)[:1200]
    return body[:700]


def _marker_snippets(body: str) -> Iterable[str]:
    compact = re.sub(r"\s+", " ", body)
    for pattern in _BODY_MARKER_PATTERNS:
        match = re.search(pattern, compact, re.IGNORECASE)
        if match is None:
            continue
        start = max(match.start() - 120, 0)
        end = min(match.end() + 220, len(compact))
        yield compact[start:end]


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
