from __future__ import annotations

from typing import Final

import anyio
from openai_codex import ApprovalMode, AsyncCodex, CodexError, Sandbox
from openai_codex.types import ReasoningEffort

from wafdh.llm import (
    LlmConfig,
    build_codex_prompt,
    llm_error_verdict,
    parse_codex_response_text,
    verdict_schema,
)
from wafdh.models import Confidence, LlmVerdict, TargetReport

_AMBIGUOUS_WAF_NAME_MARKERS: Final[tuple[str, ...]] = (
    "generic",
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
        try:
            async with AsyncCodex() as codex:
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
        except (CodexError, RuntimeError) as exc:
            return llm_error_verdict(self._config.model, f"Codex SDK failed: {exc}")
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
