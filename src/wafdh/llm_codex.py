from __future__ import annotations

from typing import Final

import anyio
from openai_codex import ApprovalMode, AsyncCodex, CodexError, Sandbox
from openai_codex.types import ReasoningEffort

from wafdh.llm import (
    LlmClassificationError,
    LlmConfig,
    build_codex_prompt,
    parse_codex_response_text,
    verdict_schema,
)
from wafdh.models import Confidence, LlmVerdict, TargetReport

_CODEX_CLOSE_TIMEOUT_SECONDS: Final[float] = 10.0
_AMBIGUOUS_WAF_NAME_MARKERS: Final[tuple[str, ...]] = (
    "apache",
    "application load balancer",
    "alb",
    "custom",
    "edge filtering",
    "filter",
    "filtering",
    "generic",
    "iis",
    "nginx",
    "request filtering",
    "security filter",
    "unknown",
    "security gateway",
    "unspecified",
    "unclear",
)


class CodexLlmAnalyzer:
    def __init__(self, *, config: LlmConfig) -> None:
        self._config: LlmConfig = config
        self._limiter: anyio.CapacityLimiter = anyio.CapacityLimiter(max(1, config.concurrency))

    async def analyze(self, partial_report: TargetReport) -> LlmVerdict:
        async with self._limiter:
            return await self._analyze(partial_report)

    async def _analyze(self, partial_report: TargetReport) -> LlmVerdict:
        failures: list[str] = []
        max_attempts = max(1, self._config.max_attempts)
        for attempt in range(1, max_attempts + 1):
            try:
                return await self._analyze_attempt(partial_report)
            except TimeoutError:
                failures.append(
                    f"attempt {attempt} timed out after {self._config.turn_timeout_seconds:g}s"
                )
            except (CodexError, RuntimeError) as exc:
                failures.append(f"attempt {attempt} failed: {type(exc).__name__}: {exc}")
            if attempt < max_attempts:
                await anyio.sleep(min(float(attempt), 5.0))
        raise LlmClassificationError(self._config.model, tuple(failures))

    async def _analyze_attempt(self, partial_report: TargetReport) -> LlmVerdict:
        codex = AsyncCodex()
        try:
            with anyio.fail_after(self._config.turn_timeout_seconds):
                _ = await codex.__aenter__()
                thread = await codex.thread_start(
                    approval_mode=ApprovalMode.deny_all,
                    ephemeral=True,
                    model=self._config.model,
                    sandbox=Sandbox.read_only,
                )
                first = await thread.run(
                    build_codex_prompt(partial_report),
                    effort=_reasoning_effort(self._config.primary_reasoning_effort),
                    output_schema=verdict_schema(),
                    sandbox=Sandbox.read_only,
                )
                verdict = _with_reasoning_effort(
                    parse_codex_response_text(first.final_response or "", self._config.model),
                    self._config.primary_reasoning_effort,
                )
                if not _should_escalate(verdict):
                    return verdict
                review = await thread.run(
                    build_codex_prompt(partial_report, verdict),
                    effort=_reasoning_effort(self._config.escalation_reasoning_effort),
                    output_schema=verdict_schema(),
                    sandbox=Sandbox.read_only,
                )
        finally:
            with anyio.move_on_after(_CODEX_CLOSE_TIMEOUT_SECONDS, shield=True):
                await codex.close()
        return _with_reasoning_effort(
            parse_codex_response_text(review.final_response or "", self._config.model),
            self._config.escalation_reasoning_effort,
        )


def _reasoning_effort(value: str) -> ReasoningEffort:
    return ReasoningEffort(value)


def _with_reasoning_effort(verdict: LlmVerdict, reasoning_effort: str) -> LlmVerdict:
    return verdict.model_copy(update={"reasoning_effort": reasoning_effort})


def _should_escalate(verdict: LlmVerdict) -> bool:
    if verdict.confidence != Confidence.HIGH:
        return True
    return verdict.detected and _has_ambiguous_waf_name(verdict.waf_name)


def _has_ambiguous_waf_name(waf_name: str | None) -> bool:
    if waf_name is None:
        return True
    normalized = waf_name.casefold()
    return any(marker in normalized for marker in _AMBIGUOUS_WAF_NAME_MARKERS)
