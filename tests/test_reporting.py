from __future__ import annotations

from wafdh.models import (
    Confidence,
    Detection,
    DetectionSource,
    FinalVerdict,
    TargetReport,
    WafStatus,
)
from wafdh.reporting import identification_reason, summary_waf_names


def _detection(name: str, source: DetectionSource) -> Detection:
    return Detection(
        source=source,
        name=name,
        manufacturer="Unknown",
        confidence=Confidence.MEDIUM,
        reason="test",
    )


def test_summary_prefers_specific_signature_over_llm_generic_name() -> None:
    report = TargetReport(
        target="https://example.test/",
        final_url="https://example.test/",
        waf_status=WafStatus.DETECTED,
        crawled=True,
        discovered_parameters=(),
        detections=(
            _detection("Generic nginx WAF/security gateway", DetectionSource.LLM),
            _detection("Penta Security WAPPLES", DetectionSource.SIGNATURE),
        ),
        payloads=(),
        llm_verdict=None,
        errors=(),
    )

    assert summary_waf_names(report) == "Penta Security WAPPLES"


def test_summary_uses_final_verdict_when_codex_resolves_generic_detection() -> None:
    report = TargetReport(
        target="https://example.test/",
        final_url="https://example.test/",
        waf_status=WafStatus.DETECTED,
        crawled=True,
        discovered_parameters=(),
        detections=(_detection("Generic WAF or security gateway", DetectionSource.GENERIC),),
        payloads=(),
        llm_verdict=None,
        final_verdict=FinalVerdict(
            source=DetectionSource.LLM,
            detected=True,
            waf_name="AIONCLOUD WAF",
            confidence=Confidence.HIGH,
            rationale="Codex matched branded challenge evidence.",
        ),
        errors=(),
    )

    assert summary_waf_names(report) == "AIONCLOUD WAF"
    assert (
        identification_reason(report) == "AIONCLOUD WAF: Codex matched branded challenge evidence."
    )
