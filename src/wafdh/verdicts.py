from __future__ import annotations

from typing import Final, assert_never

from wafdh.models import Confidence, Detection, DetectionSource, FinalVerdict, LlmVerdict

GENERIC_WAF_NAME_MARKERS: Final[tuple[str, ...]] = (
    "apache",
    "application load balancer",
    "alb",
    "custom",
    "edge filtering",
    "filter",
    "filtering",
    "generic",
    "iis",
    "nginx",
    "request filtering",
    "security filter",
    "security gateway",
    "unknown",
    "unspecified",
)


def resolve_final_verdict(
    detections: tuple[Detection, ...],
    verdict: LlmVerdict | None,
    *,
    payload_count: int,
) -> FinalVerdict:
    protected_signature = _primary_specific_high_detection(detections)
    if verdict is not None:
        return _resolve_with_llm(verdict, protected_signature)
    primary = primary_detection(detections)
    if primary is not None:
        return _from_detection(primary)
    return _empty_verdict(payload_count)


def primary_detection(detections: tuple[Detection, ...]) -> Detection | None:
    specific = tuple(detection for detection in detections if not is_generic_detection(detection))
    if len(specific) > 0:
        return specific[0]
    if len(detections) > 0:
        return detections[0]
    return None


def is_generic_detection(detection: Detection) -> bool:
    match detection.source:
        case DetectionSource.GENERIC:
            return True
        case DetectionSource.SIGNATURE | DetectionSource.LLM:
            return is_generic_waf_name(detection.name)
    assert_never(detection.source)


def is_generic_waf_name(name: str | None) -> bool:
    if name is None:
        return True
    normalized = name.casefold()
    return any(marker in normalized for marker in GENERIC_WAF_NAME_MARKERS)


def _resolve_with_llm(verdict: LlmVerdict, protected_signature: Detection | None) -> FinalVerdict:
    if verdict.detected and verdict.waf_name is not None:
        if protected_signature is not None and is_generic_waf_name(verdict.waf_name):
            return _from_detection(protected_signature)
        return _from_llm(verdict)
    if protected_signature is not None:
        return _from_detection(protected_signature)
    return _from_llm(verdict)


def _primary_specific_high_detection(detections: tuple[Detection, ...]) -> Detection | None:
    for detection in detections:
        if is_generic_detection(detection):
            continue
        if not _is_high_confidence(detection.confidence):
            continue
        return detection
    return None


def _is_high_confidence(confidence: Confidence) -> bool:
    match confidence:
        case Confidence.HIGH:
            return True
        case Confidence.MEDIUM | Confidence.LOW:
            return False
    assert_never(confidence)


def _from_detection(detection: Detection) -> FinalVerdict:
    return FinalVerdict(
        source=detection.source,
        detected=True,
        waf_name=detection.name,
        confidence=detection.confidence,
        rationale=detection.reason,
    )


def _from_llm(verdict: LlmVerdict) -> FinalVerdict:
    return FinalVerdict(
        source=DetectionSource.LLM,
        detected=verdict.detected,
        waf_name=verdict.waf_name,
        confidence=verdict.confidence,
        rationale=verdict.rationale,
    )


def _empty_verdict(payload_count: int) -> FinalVerdict:
    rationale = (
        "Insufficient probe evidence."
        if payload_count == 0
        else "No WAF signature or block response was observed."
    )
    return FinalVerdict(
        source=None,
        detected=False,
        waf_name=None,
        confidence=Confidence.LOW,
        rationale=rationale,
    )
