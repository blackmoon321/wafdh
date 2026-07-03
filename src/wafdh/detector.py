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
        controls: tuple[PayloadEvidence, ...] = (),
        payloads: tuple[PayloadEvidence, ...],
    ) -> tuple[Detection, ...]:
        responses = tuple(
            evidence.response
            for evidence in (*controls, *payloads)
            if evidence.response is not None
        )
        signatures = self._matcher.match((baseline, *responses))
        generic = _generic_detection(baseline, controls, payloads)
        return (*signatures, *generic)


def _generic_detection(
    baseline: ResponseSnapshot,
    controls: tuple[PayloadEvidence, ...],
    payloads: tuple[PayloadEvidence, ...],
) -> tuple[Detection, ...]:
    detections: list[Detection] = []
    for payload in payloads:
        response = payload.response
        if response is None:
            continue
        reason = _generic_reason(
            baseline,
            response,
            payload.name,
            _matching_control(controls, payload),
        )
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
    control: ResponseSnapshot | None,
) -> str | None:
    if _is_payload_only_block(baseline, control, response):
        return (
            f"{payload_name} changed status from {baseline.status_code} "
            f"to blocked status {response.status_code}"
        )
    baseline_server = _header_value(baseline, "server")
    control_server = _header_value(control, "server") if control is not None else baseline_server
    response_server = _header_value(response, "server")
    if response_server not in (baseline_server, control_server, ""):
        return f"{payload_name} changed server header from {baseline_server} to {response_server}"
    lower_body = response.body_excerpt.lower()
    for marker in _GENERIC_BODY_MARKERS:
        if marker in lower_body and not _marker_seen(marker, baseline, control):
            return f"{payload_name} response contains WAF marker {marker!r}"
    return None


def _matching_control(
    controls: tuple[PayloadEvidence, ...],
    payload: PayloadEvidence,
) -> ResponseSnapshot | None:
    for control in controls:
        if control.target_url != payload.target_url or control.parameter != payload.parameter:
            continue
        return control.response
    return None


def _is_payload_only_block(
    baseline: ResponseSnapshot,
    control: ResponseSnapshot | None,
    response: ResponseSnapshot,
) -> bool:
    if response.status_code not in _BLOCK_STATUS_CODES:
        return False
    if baseline.status_code == response.status_code:
        return False
    if control is None:
        return True
    return control.status_code != response.status_code


def _marker_seen(
    marker: str,
    baseline: ResponseSnapshot,
    control: ResponseSnapshot | None,
) -> bool:
    if marker in baseline.body_excerpt.lower():
        return True
    return control is not None and marker in control.body_excerpt.lower()


def _header_value(response: ResponseSnapshot | None, name: str) -> str:
    if response is None:
        return ""
    for key, value in response.headers:
        if key == name:
            return value
    return ""
