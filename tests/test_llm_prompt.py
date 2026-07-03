from __future__ import annotations

from wafdh.llm import build_codex_prompt
from wafdh.models import (
    Confidence,
    Detection,
    DetectionSource,
    PayloadEvidence,
    ResponseSnapshot,
    TargetReport,
    WafStatus,
)


def _snapshot(
    *,
    status_code: int,
    headers: tuple[tuple[str, str], ...],
    body: str,
) -> ResponseSnapshot:
    return ResponseSnapshot(
        request_url="https://example.test/",
        final_url="https://example.test/",
        status_code=status_code,
        reason_phrase="OK",
        headers=headers,
        body_excerpt=body,
    )


def _payload(name: str, response: ResponseSnapshot) -> PayloadEvidence:
    return PayloadEvidence(
        name=name,
        target_url="https://example.test/",
        parameter="wafdh_probe",
        response=response,
        error=None,
    )


def test_prompt_includes_baseline_control_and_late_interesting_headers() -> None:
    baseline = _snapshot(status_code=200, headers=(("server", "origin"),), body="normal")
    control = _snapshot(status_code=200, headers=(("server", "origin"),), body="normal")
    blocked = _snapshot(
        status_code=403,
        headers=(
            ("h1", "ignored"),
            ("h2", "ignored"),
            ("h3", "ignored"),
            ("h4", "ignored"),
            ("h5", "ignored"),
            ("h6", "ignored"),
            ("h7", "ignored"),
            ("h8", "ignored"),
            ("x-iinfo", "12-345"),
        ),
        body="Incapsula incident ID 123",
    )
    report = TargetReport(
        target="https://example.test/",
        final_url="https://example.test/",
        waf_status=WafStatus.DETECTED,
        crawled=True,
        baseline=baseline,
        controls=(_payload("benign-control", control),),
        discovered_parameters=(),
        detections=(
            Detection(
                source=DetectionSource.SIGNATURE,
                name="Imperva Incapsula",
                manufacturer="Imperva",
                confidence=Confidence.HIGH,
                reason="Imperva header signature matched",
            ),
        ),
        payloads=(_payload("xss", blocked),),
        llm_verdict=None,
        errors=(),
    )

    prompt = build_codex_prompt(report)

    assert "Baseline response:" in prompt
    assert "Control evidence:" in prompt
    assert "Payload evidence:" in prompt
    assert "x-iinfo=12-345" in prompt
    assert "Incapsula incident ID" in prompt
    assert "Do not turn CDN, load balancer, hosting, appliance login" in prompt
