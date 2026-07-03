from __future__ import annotations

from wafdh.models import Confidence, Detection, DetectionSource, LlmVerdict
from wafdh.verdicts import resolve_final_verdict


def _detection(
    name: str,
    source: DetectionSource,
    confidence: Confidence,
) -> Detection:
    return Detection(
        source=source,
        name=name,
        manufacturer="Test",
        confidence=confidence,
        reason="deterministic evidence",
    )


def _llm_verdict(
    *,
    detected: bool,
    waf_name: str | None,
    confidence: Confidence,
) -> LlmVerdict:
    return LlmVerdict(
        enabled=True,
        model="gpt-5.5",
        reasoning_effort="xhigh",
        detected=detected,
        waf_name=waf_name,
        confidence=confidence,
        rationale="codex evidence review",
    )


def test_final_verdict_uses_codex_when_only_generic_detection_exists() -> None:
    detections = (
        _detection("Generic WAF or security gateway", DetectionSource.GENERIC, Confidence.MEDIUM),
    )
    verdict = resolve_final_verdict(
        detections,
        _llm_verdict(detected=True, waf_name="AIONCLOUD WAF", confidence=Confidence.HIGH),
        payload_count=3,
    )

    assert verdict.detected is True
    assert verdict.waf_name == "AIONCLOUD WAF"
    assert verdict.source == DetectionSource.LLM


def test_final_verdict_keeps_specific_signature_when_codex_is_negative() -> None:
    detections = (_detection("Penta Security WAPPLES", DetectionSource.SIGNATURE, Confidence.HIGH),)
    verdict = resolve_final_verdict(
        detections,
        _llm_verdict(detected=False, waf_name=None, confidence=Confidence.MEDIUM),
        payload_count=3,
    )

    assert verdict.detected is True
    assert verdict.waf_name == "Penta Security WAPPLES"
    assert verdict.source == DetectionSource.SIGNATURE


def test_final_verdict_lets_codex_veto_weak_generic_detection() -> None:
    detections = (
        _detection("Generic WAF or security gateway", DetectionSource.GENERIC, Confidence.MEDIUM),
    )
    verdict = resolve_final_verdict(
        detections,
        _llm_verdict(detected=False, waf_name=None, confidence=Confidence.HIGH),
        payload_count=3,
    )

    assert verdict.detected is False
    assert verdict.waf_name is None
    assert verdict.source == DetectionSource.LLM
