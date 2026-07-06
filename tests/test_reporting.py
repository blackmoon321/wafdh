from __future__ import annotations

from pathlib import Path

from wafdh.models import (
    Confidence,
    Detection,
    DetectionSource,
    FinalVerdict,
    ScanReport,
    TargetReport,
    WafStatus,
)
from wafdh.reporting import ReportArtifacts, emit_report, identification_reason, summary_waf_names


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


def test_emit_report_writes_excel_readable_utf8_csv(tmp_path: Path) -> None:
    left_quote = chr(0x2018)
    right_quote = chr(0x2019)
    report = TargetReport(
        target="https://209.136.139.170",
        final_url=None,
        waf_status=WafStatus.SCAN_FAILED,
        crawled=False,
        discovered_parameters=(),
        detections=(),
        payloads=(),
        llm_verdict=None,
        errors=(
            f"('{left_quote}HMAMLyncApp01.hmagucc.autoeveramerica.com"
            f"{right_quote} 인증서는 표준을 준수하지 않음',)",
        ),
    )
    scan = ScanReport(
        generated_at="2026-07-06T00:00:00+00:00",
        worker_count=1,
        target_count=1,
        targets=(report,),
    )
    csv_path = tmp_path / "summary.csv"

    emit_report(
        scan,
        csv_path,
        ReportArtifacts(
            json_path=tmp_path / "report.json",
            checkpoint_path=tmp_path / "report.partial.jsonl",
        ),
    )

    csv_bytes = csv_path.read_bytes()
    assert csv_bytes.startswith(b"\xef\xbb\xbf")
    assert "인증서는 표준을 준수하지 않음".encode() in csv_bytes
