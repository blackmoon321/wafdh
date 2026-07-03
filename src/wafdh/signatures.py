from __future__ import annotations

import re

from wafdh.models import Detection, DetectionSource, ResponseSnapshot
from wafdh.signature_rules_core import BUILTIN_CORE_RULES
from wafdh.signature_rules_extended import BUILTIN_EXTENDED_RULES
from wafdh.signature_types import WafRule


class SignatureMatcher:
    def __init__(self, rules: tuple[WafRule, ...]) -> None:
        self._rules: tuple[WafRule, ...] = rules

    @property
    def rules(self) -> tuple[WafRule, ...]:
        return self._rules

    def match(self, responses: tuple[ResponseSnapshot, ...]) -> tuple[Detection, ...]:
        detections: list[Detection] = []
        for rule in self._rules:
            reason = _match_rule(rule, responses)
            if reason is None:
                continue
            detections.append(
                Detection(
                    source=DetectionSource.SIGNATURE,
                    name=rule.name,
                    manufacturer=rule.manufacturer,
                    confidence=rule.confidence,
                    reason=reason,
                )
            )
        return tuple(detections)


def load_rules() -> tuple[WafRule, ...]:
    return (*BUILTIN_CORE_RULES, *BUILTIN_EXTENDED_RULES)


def _match_rule(rule: WafRule, responses: tuple[ResponseSnapshot, ...]) -> str | None:
    for response in responses:
        reason = _match_response(rule, response)
        if reason is not None:
            return reason
    return None


def _has_content_patterns(rule: WafRule) -> bool:
    return (
        len(rule.url_patterns)
        + len(rule.header_patterns)
        + len(rule.cookie_patterns)
        + len(rule.body_patterns)
        + len(rule.required_patterns)
        > 0
    )


def _match_response(rule: WafRule, response: ResponseSnapshot) -> str | None:
    response_blob = _response_blob(response)
    if _matches(rule.negative_patterns, response_blob):
        return None
    header_blob = "\n".join(f"{key}: {value}" for key, value in response.headers)
    cookie_blob = "\n".join(value for key, value in response.headers if key == "set-cookie")
    url_blob = "\n".join((response.request_url, response.final_url, *response.redirects))
    checks = (
        (
            len(rule.required_patterns) > 0 and _matches_all(rule.required_patterns, response_blob),
            "combined",
        ),
        (_matches(rule.url_patterns, url_blob), "URL"),
        (_matches(rule.header_patterns, header_blob), "header"),
        (_matches(rule.cookie_patterns, cookie_blob), "cookie"),
        (_matches(rule.body_patterns, response.body_excerpt), "body"),
        (
            response.status_code in rule.status_codes and not _has_content_patterns(rule),
            f"status code {response.status_code}",
        ),
    )
    for matched, label in checks:
        if matched:
            return f"{rule.name} {label} signature matched"
    return None


def _matches(patterns: tuple[str, ...], text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) is not None for pattern in patterns)


def _matches_all(patterns: tuple[str, ...], text: str) -> bool:
    return all(re.search(pattern, text, re.IGNORECASE) is not None for pattern in patterns)


def _response_blob(response: ResponseSnapshot) -> str:
    header_blob = "\n".join(f"{key}: {value}" for key, value in response.headers)
    url_blob = "\n".join((response.request_url, response.final_url, *response.redirects))
    return "\n".join(
        (
            f"status:{response.status_code}",
            f"reason:{response.reason_phrase}",
            url_blob,
            header_blob,
            response.body_excerpt,
        )
    )
