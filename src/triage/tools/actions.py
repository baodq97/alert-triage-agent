"""Response Actions — post-gate only, NEVER in the ToolRegistry (RFC-0001 §Tools).

A Response Action mutates and runs *only* in the post-Verdict flow:
Verdict -> Risk Policy -> Approval Gate -> approved -> execute (mock). It is not
an investigation Tool and is unreachable through ``ToolRegistry``, so the
executor can never call it mid-loop (triage-conventions §Investigation tools vs
response actions).

``block_user`` is the shipped Response Action and executes a mock here.

**Target invariant seam.** A targeted Response Action must reference an Entity
present in the Alert envelope/Payload; a Verdict whose action target is not an
Alert Entity is rejected *before* the gate. This module owns only the *seam* —
``block_user_target`` extracts the target from the ``Action`` — and reports the
match rule; the *enforcement* (comparing it against the Alert's Entity values)
lands in the gate/core flow, which holds the Alert. The agreed match rule:
the target is valid iff its value appears among ``alert.entities.values()``
(e.g. ``svc-deploy-prod``, ``10.200.3.47``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from triage.models import Action

#: The ``Action.params`` key that names the Entity a ``block_user`` action targets.
BLOCK_USER_TARGET_KEY = "user"

#: Response Actions that reference an Alert Entity and so are subject to the
#: target-entity invariant. A name *not* in this set is an untargeted action
#: (e.g. an advisory ``notify_soc``) with no target to validate — it bypasses the
#: invariant and flows straight to the Risk Policy / Approval Gate. Keep this in
#: sync with the targeted Response Actions as they ship (wave 1: ``block_user``).
TARGETED_ACTIONS: frozenset[str] = frozenset({"block_user"})


def is_targeted(action: Action) -> bool:
    """Return whether ``action`` references an Alert Entity (so the invariant applies).

    Distinguishes an untargeted advisory action (no target to validate, passes
    through to the gate) from a targeted Response Action whose target the core flow
    must check against ``alert.entities.values()`` — including a *malformed* one
    whose target is absent, which is still targeted and so still validated/rejected.
    """
    return action.name in TARGETED_ACTIONS


def block_user_target(action: Action) -> str | None:
    """Return the Entity a ``block_user`` Action targets, or ``None`` if absent.

    The gate/core flow validates the returned value against the Alert's Entity
    values (``alert.entities.values()``) before allowing the action to the gate.
    """
    params = action.params or {}
    target = params.get(BLOCK_USER_TARGET_KEY)
    return target if isinstance(target, str) else None


def block_user(action: Action) -> dict[str, Any]:
    """Execute the ``block_user`` Response Action (mock) and return its result.

    Called only by the post-Verdict gate flow after an approved Gate Decision,
    never by the executor. The real connector (Okta et al.) is roadmap; this
    mock records the blocked target deterministically.
    """
    target = block_user_target(action)
    return {"action": "block_user", "target": target, "status": "blocked", "mock": True}
