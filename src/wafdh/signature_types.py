from __future__ import annotations

from dataclasses import dataclass

from wafdh.models import Confidence


@dataclass(frozen=True, slots=True)
class WafRule:
    name: str
    manufacturer: str
    confidence: Confidence
    url_patterns: tuple[str, ...] = ()
    header_patterns: tuple[str, ...] = ()
    cookie_patterns: tuple[str, ...] = ()
    body_patterns: tuple[str, ...] = ()
    required_patterns: tuple[str, ...] = ()
    negative_patterns: tuple[str, ...] = ()
    status_codes: tuple[int, ...] = ()
