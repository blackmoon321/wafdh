from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PayloadCase:
    name: str
    parameter: str
    value: str


DEFAULT_PARAMETER = "wafdh_probe"
BENIGN_CONTROL_PAYLOAD = PayloadCase("benign-control", DEFAULT_PARAMETER, "wafdh-benign-control")

DEFAULT_PAYLOADS: tuple[PayloadCase, ...] = (
    PayloadCase("xss", DEFAULT_PARAMETER, "<script>alert(1)</script>"),
    PayloadCase("sqli", DEFAULT_PARAMETER, "' UNION SELECT ALL FROM information_schema--"),
    PayloadCase("lfi", DEFAULT_PARAMETER, "../../../../etc/passwd"),
    PayloadCase("xxe", DEFAULT_PARAMETER, "]>&wafdh;"),
    PayloadCase("osci", DEFAULT_PARAMETER, ";cat /etc/passwd;id"),
    PayloadCase(
        "central",
        DEFAULT_PARAMETER,
        "<script>alert(1)</script> ' UNION SELECT ALL FROM users-- ../../etc/passwd",
    ),
)
