"""Entity-scoped memory for the triage agent (RFC-0001 §Memory).

L1 finding atoms persist at verdict time keyed by entity; L2 dossiers are a
deterministic group-by; recall is entity-scoped into the planner context. L3
(threat posture) is a Wave-4 seam — see :mod:`triage.memory.store`.
"""

from triage.memory.atoms import FindingAtom
from triage.memory.store import MemoryStore

__all__ = ["FindingAtom", "MemoryStore"]
