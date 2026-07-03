from __future__ import annotations

from wafdh.models import Confidence, Detection, DetectionSource, TargetReport, WafStatus
from wafdh.reporting import summary_waf_names


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
