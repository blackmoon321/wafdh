from __future__ import annotations

from wafdh.detector import WafDetector
from wafdh.models import DetectionSource, PayloadEvidence, ResponseSnapshot
from wafdh.signatures import SignatureMatcher


def _snapshot(
    *,
    status_code: int,
    body: str,
    headers: tuple[tuple[str, str], ...] = (),
    final_url: str = "https://example.test/",
) -> ResponseSnapshot:
    return ResponseSnapshot(
        request_url="https://example.test/",
        final_url=final_url,
        status_code=status_code,
        reason_phrase="OK",
        headers=headers,
        body_excerpt=body,
    )


def _payload(response: ResponseSnapshot, name: str = "xss") -> PayloadEvidence:
    return PayloadEvidence(
        name=name,
        target_url="https://example.test/",
        parameter="wafdh_probe",
        response=response,
        error=None,
    )


def test_generic_detection_uses_clean_control_as_comparator() -> None:
    detector = WafDetector(SignatureMatcher(()))
    baseline = _snapshot(status_code=200, body="normal page")
    control = _payload(_snapshot(status_code=200, body="normal page"), "benign-control")
    blocked = _payload(_snapshot(status_code=403, body="Forbidden"), "xss")

    detections = detector.detect(
        baseline=baseline,
        controls=(control,),
        payloads=(blocked,),
    )

    assert tuple(d.source for d in detections) == (DetectionSource.GENERIC,)


def test_generic_detection_ignores_unconditional_blocking_control() -> None:
    detector = WafDetector(SignatureMatcher(()))
    baseline = _snapshot(status_code=200, body="normal page")
    control = _payload(_snapshot(status_code=403, body="Forbidden"), "benign-control")
    blocked = _payload(_snapshot(status_code=403, body="Forbidden"), "xss")

    detections = detector.detect(
        baseline=baseline,
        controls=(control,),
        payloads=(blocked,),
    )

    assert detections == ()
