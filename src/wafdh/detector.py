from __future__ import annotations

from wafdh.models import (
    Confidence,
    Detection,
    DetectionSource,
    PayloadEvidence,
    ResponseSnapshot,
)
from wafdh.signatures import SignatureMatcher

_BLOCK_STATUS_CODES = {403, 406, 409, 418, 429, 451, 503}
_GENERIC_BODY_MARKERS = (
    "access denied",
    "blocked",
    "forbidden",
    "incident id",
    "request rejected",
    "security policy",
)


class WafDetector:
    def __init__(self, matcher: SignatureMatcher) -> None:
        self._matcher: SignatureMatcher = matcher

    def detect(
        self,
        *,
        baseline: ResponseSnapshot,
        payloads: tuple[PayloadEvidence, ...],
    ) -> tuple[Detection, ...]:
        responses = tuple(
            evidence.response for evidence in payloads if evidence.response is not None
        )
        signatures = self._matcher.match((baseline, *responses))
        generic = _generic_detection(baseline, payloads)
        return (*signatures, *generic)


def _generic_detection(
    baseline: ResponseSnapshot,
    payloads: tuple[PayloadEvidence, ...],
) -> tuple[Detection, ...]:
    detections: list[Detection] = []
    for payload in payloads:
        response = payload.response
        if response is None:
            continue
        reason = _generic_reason(baseline, response, payload.name)
        if reason is None:
            continue
        detections.append(
            Detection(
                source=DetectionSource.GENERIC,
                name="Generic WAF or security gateway",
                manufacturer="Unknown",
                confidence=Confidence.MEDIUM,
                reason=reason,
            )
        )
        break
    return tuple(detections)


def _generic_reason(
    baseline: ResponseSnapshot,
    response: ResponseSnapshot,
    payload_name: str,
) -> str | None:
    if baseline.status_code != response.status_code and response.status_code in _BLOCK_STATUS_CODES:
        return (
            f"{payload_name} changed status from {baseline.status_code} "
            f"to blocked status {response.status_code}"
        )
    baseline_server = _header_value(baseline, "server")
    response_server = _header_value(response, "server")
    if response_server not in (baseline_server, ""):
        return f"{payload_name} changed server header from {baseline_server} to {response_server}"
    lower_body = response.body_excerpt.lower()
    for marker in _GENERIC_BODY_MARKERS:
        if marker in lower_body:
            return f"{payload_name} response contains WAF marker {marker!r}"
    return None


def _header_value(response: ResponseSnapshot, name: str) -> str:
    for key, value in response.headers:
        if key == name:
            return value
    return ""
