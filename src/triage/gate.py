"""The Risk Policy and the Approval Gate (RFC-0001 HITL gate).

The Human-in-the-loop seam, enforced in code — never delegated to LLM judgment.
Three parts:

* ``RiskPolicy`` loads ``config/risk_policy.yaml`` (override via
  ``RISK_POLICY_PATH``) and classifies a Recommended Action by its exact
  ``Action.name``. An unlisted name defaults to ``high_risk`` — the safe default,
  so a new Response Action cannot slip past the gate by omission. A missing,
  malformed, or wrong-shape policy file is a configuration fault: ``ConfigError``.
* ``ApprovalGate`` is the Protocol the run flow consumes; ``CLIGate`` (interactive
  stdin), ``AutoGate`` (config-driven, default-deny — tests / CI), and
  ``DeferredGate`` (the asynchronous-HITL seam — wave 2) implement it.
* ONE gate per Run, after the Verdict: ``request`` takes the Verdict's full
  ``recommended_actions`` plus the ``RiskPolicy``, batches every High-risk Action
  into a single approval request, and returns one of three outcomes — the
  ``GateDecision`` (resolved in-process), ``None`` when nothing is high-risk (a
  **Zero-touch** run, no gate events emitted), or the ``HOLD`` sentinel when the
  gate cannot resolve interactively and the Run must park as ``awaiting_approval``
  for ``--resume --approve|--deny`` (RFC-0001 §Runtime surfaces — the watch adapter
  wires this resume-capable flow). The gate returns the outcome; it never executes
  the actions — executing the approved batch and recording denials is the run
  flow's job (RFC-0001 §Tools).

Both resolving implementations share ``_BaseGate.request`` so the emit ordering
(``gate_requested`` before asking, ``gate_decision`` after) lives in exactly one
place: each impl supplies only how it *obtains* the human decision. ``DeferredGate``
overrides ``request`` to emit ``gate_requested`` and then *stop* — no
``gate_decision`` — which is exactly the journal shape Resume detects as pending.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, Protocol, cast, get_args, runtime_checkable

import yaml

from triage.errors import ConfigError
from triage.models import Action, GateDecision

if TYPE_CHECKING:
    from collections.abc import Sequence

    from triage.journal import Journal


class _Hold:
    """The gate-deferred sentinel: the High-risk batch needs an out-of-band human.

    A distinct type (not ``None`` — that is Zero-touch — and not a ``GateDecision``
    — that is resolved) so the core flow tells the three gate outcomes apart by
    type, never by a magic value. One module-level instance, ``HOLD``, is the only
    value; the class is private so callers compare against ``HOLD`` / ``is_hold``.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        """A stable repr for debugging / test output."""
        return "HOLD"


HOLD: Final[_Hold] = _Hold()
"""The single gate-deferred sentinel — the Run parks as ``awaiting_approval``."""

GateOutcome = GateDecision | _Hold | None
"""What a gate's ``request`` returns: resolved decision, ``HOLD``, or Zero-touch ``None``."""


def is_hold(outcome: GateOutcome) -> bool:
    """Return whether a gate outcome is the deferred ``HOLD`` sentinel."""
    return outcome is HOLD


_DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "risk_policy.yaml"

RiskTier = Literal["high_risk", "low_risk"]
"""An action's risk class assigned by the Risk Policy (minimal — only high gates)."""

_HIGH_RISK: RiskTier = "high_risk"
_VALID_TIERS: frozenset[str] = frozenset(get_args(RiskTier))


def _resolve_policy_path(path: Path | None) -> Path:
    """Pick the explicit path, else ``RISK_POLICY_PATH``, else the shipped default."""
    if path is not None:
        return path
    override = os.environ.get("RISK_POLICY_PATH")
    return Path(override) if override else _DEFAULT_POLICY_PATH


class RiskPolicy:
    """Classifies a Recommended Action's Risk Tier by exact name (RFC-0001 HITL)."""

    def __init__(self, path: Path | None = None) -> None:
        """Load and validate the policy file.

        Args:
            path: An explicit policy file; when ``None``, ``RISK_POLICY_PATH`` is
                consulted, then the shipped ``config/risk_policy.yaml`` default.

        Raises:
            ConfigError: The file is missing, is not valid YAML, or does not have
                the ``{actions: {name: tier}}`` shape with known tier values.
        """
        resolved = _resolve_policy_path(path)
        self._tiers = self._load(resolved)

    @staticmethod
    def _load(path: Path) -> dict[str, RiskTier]:
        """Read, parse, and shape-check the policy file into a name->tier map."""
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"Risk policy file not found or unreadable: {path}"
            raise ConfigError(msg) from exc
        try:
            document = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            msg = f"Risk policy file is not valid YAML: {path}"
            raise ConfigError(msg) from exc
        if not isinstance(document, dict):
            msg = f"Risk policy must be a mapping at the top level: {path}"
            raise ConfigError(msg)
        actions = document.get("actions")
        if not isinstance(actions, dict):
            msg = f"Risk policy must have an 'actions' mapping: {path}"
            raise ConfigError(msg)
        tiers: dict[str, RiskTier] = {}
        for name, tier in actions.items():
            if not isinstance(tier, str) or tier not in _VALID_TIERS:
                msg = (
                    f"Risk policy action '{name}' has an unknown tier "
                    f"'{tier}' (expected one of {sorted(_VALID_TIERS)}): {path}"
                )
                raise ConfigError(msg)
            tiers[str(name)] = cast("RiskTier", tier)  # narrowed by the guard above
        return tiers

    def is_high_risk(self, action: Action) -> bool:
        """Return whether ``action`` requires the Approval Gate.

        An unlisted name defaults to ``high_risk`` — unclassified actions gate.
        """
        return self._tiers.get(action.name, _HIGH_RISK) == _HIGH_RISK

    def high_risk(self, actions: Sequence[Action]) -> list[Action]:
        """Return the High-risk Actions in ``actions``, preserving their order."""
        return [action for action in actions if self.is_high_risk(action)]


@runtime_checkable
class ApprovalGate(Protocol):
    """The single per-Run pause where all High-risk Actions are batched."""

    def request(
        self,
        actions: Sequence[Action],
        policy: RiskPolicy,
    ) -> GateOutcome:
        """Batch the High-risk Actions in ``actions`` into one approval request.

        Args:
            actions: The Verdict's full ``recommended_actions``; the gate filters
                the High-risk ones via ``policy``.
            policy: The Risk Policy that classifies each action.

        Returns:
            One of three outcomes — a ``GateDecision`` (resolved in-process),
            ``None`` for a Zero-touch run (no High-risk Action — no gate events),
            or ``HOLD`` when the decision must come out of band and the Run parks
            as ``awaiting_approval`` (``gate_requested`` emitted, no
            ``gate_decision``). The gate never executes the actions; the run flow
            does.
        """
        ...  # pragma: no cover  # Protocol signature, never executed.


class _BaseGate:
    """Shared batching + emit ordering; subclasses supply only the decision."""

    _by: str

    def __init__(self, journal: Journal) -> None:
        """Bind the Journal the gate events emit to."""
        self._journal = journal

    def request(
        self,
        actions: Sequence[Action],
        policy: RiskPolicy,
    ) -> GateDecision | None:
        """Batch the High-risk Actions and return the decision (or None)."""
        batch = policy.high_risk(actions)
        if not batch:
            return None
        self._journal.emit(
            "gate_requested",
            {"actions": [action.model_dump() for action in batch], "risk": _HIGH_RISK},
        )
        decision = GateDecision(decision=self._decide(batch), by=self._by)
        self._journal.emit(
            "gate_decision",
            {"decision": decision.decision, "by": decision.by},
        )
        return decision

    def _decide(self, batch: Sequence[Action]) -> Literal["approved", "denied"]:
        """Obtain the human decision for the batched High-risk Actions."""
        raise NotImplementedError  # pragma: no cover  # overridden by every impl.


class AutoGate(_BaseGate):
    """A config-driven gate — default-deny, used in tests / CI (RFC-0001 HITL)."""

    _by = "auto"

    def __init__(self, journal: Journal, *, approve: bool = False) -> None:
        """Bind the Journal; ``approve`` flips the default-deny outcome (tests)."""
        super().__init__(journal)
        self._approve = approve

    def _decide(self, batch: Sequence[Action]) -> Literal["approved", "denied"]:  # noqa: ARG002  # batch unused: the outcome is config-driven, but the name matches the base for LSP (ty).
        """Return the configured outcome — denied unless ``approve`` was set."""
        return "approved" if self._approve else "denied"


class CLIGate(_BaseGate):
    """An interactive gate prompting the operator on stdin (RFC-0001 HITL)."""

    _by = "cli"
    _APPROVALS: frozenset[str] = frozenset({"y", "yes"})

    def _decide(self, batch: Sequence[Action]) -> Literal["approved", "denied"]:
        """Prompt once; an explicit yes approves, anything else (or EOF) denies (safe)."""
        names = ", ".join(action.name for action in batch)
        prompt = f"Approve {len(batch)} high-risk action(s) [{names}]? [y/N]: "
        try:
            reply = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            # No terminal / piped stdin / Ctrl-C: treat as a non-approval (safe default).
            return "denied"
        return "approved" if reply in self._APPROVALS else "denied"


class DeferredGate:
    """The asynchronous-HITL gate — defers the decision to a later ``--resume``.

    Used where a Run cannot resolve the gate in-process (RFC-0001 §Runtime
    surfaces: the watch adapter and any non-interactive ingestion). On a High-risk
    batch it emits ``gate_requested`` and then returns ``HOLD`` *without* a
    ``gate_decision`` — so the core flow parks the Run as ``awaiting_approval`` and
    the journal carries exactly the pending shape Resume detects (a
    ``gate_requested`` with no following ``gate_decision``). A Zero-touch run (no
    High-risk Action) returns ``None`` and emits nothing, identical to the resolving
    gates — deferral applies only when there is actually something to approve.

    It does *not* extend ``_BaseGate``: the base couples ``gate_requested`` and
    ``gate_decision`` around one ``_decide`` call, and the whole point here is to
    emit the first and skip the second. Sharing batching is not worth re-coupling
    the two emits the base deliberately pairs.
    """

    def __init__(self, journal: Journal) -> None:
        """Bind the Journal the ``gate_requested`` event emits to."""
        self._journal = journal

    def request(self, actions: Sequence[Action], policy: RiskPolicy) -> GateOutcome:
        """Emit ``gate_requested`` for the High-risk batch and defer (``HOLD``).

        Returns ``None`` (emitting nothing) when the batch is empty — a Zero-touch
        run never parks. Otherwise emits the single ``gate_requested`` and returns
        ``HOLD``; no ``gate_decision`` is emitted, which is the pending journal
        shape Resume completes on ``--approve|--deny``.
        """
        batch = policy.high_risk(actions)
        if not batch:
            return None
        self._journal.emit(
            "gate_requested",
            {"actions": [action.model_dump() for action in batch], "risk": _HIGH_RISK},
        )
        return HOLD
