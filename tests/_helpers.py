"""Shared test helpers and fixtures for the alert-triage-agent test suite.

``CapturingLLM`` is the canonical test double for inspecting rendered prompts
across all test modules.  It wraps a ``FakeLLM`` via composition and records
every ``complete`` call's message list in ``calls`` (a ``list[list[Message]]``)
so a test can assert on the plan prompt (``calls[0]``), the reason prompts, or
the verdict prompt individually — ``FakeLLM.last_messages`` only keeps the most
recent call.

Usage::

    from tests._helpers import CapturingLLM

    capturer = CapturingLLM(FakeLLM([...script...]))
    run_case(case, capturer)
    plan_prompt = "\\n".join(m["content"] for m in capturer.calls[0])
    assert "<recalled_memory>" in plan_prompt
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import BaseModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from triage.llm import Completion, FakeLLM, Message

T = TypeVar("T", bound=BaseModel)


class CapturingLLM:
    """Wraps a ``FakeLLM`` and records EVERY ``complete`` call's messages.

    ``FakeLLM.last_messages`` is overwritten on each call; this capturer keeps
    the full ordered history in ``calls`` so a test can inspect any call
    (e.g. ``calls[0]`` for the plan prompt) without losing earlier calls to
    later ones.

    ``model`` is forwarded from the inner ``FakeLLM`` so the runner's
    model-detection logic (which reads ``completion.model``) stays correct.
    """

    def __init__(self, inner: FakeLLM) -> None:
        """Wrap ``inner`` and start the empty call log."""
        self._inner = inner
        self.model = inner.model
        self.calls: list[list[Message]] = []

    def complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Any = None,
        on_repair: Any = None,
    ) -> Completion[T]:
        """Delegate to the inner LLM and record the message list."""
        self.calls.append(list(messages))
        return self._inner.complete(
            messages,
            response_model,
            on_transport_retry=on_transport_retry,
            on_repair=on_repair,
        )
