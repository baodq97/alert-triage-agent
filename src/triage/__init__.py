"""Autonomous security alert triage agent.

Investigates security alerts end-to-end: plans an investigation, chains tool
reasoning, produces a structured verdict, and gates high-risk actions behind
human approval. See docs/rfc/RFC-0001-agent-architecture.md for the design.
"""

from triage.core import (
    SCHEMA_VERSION,
    TriageDeps,
    summarize,
    triage,
)
from triage.errors import (
    ConfigError,
    GateError,
    JournalError,
    LLMError,
    ToolError,
    TriageError,
)
from triage.executor import (
    ExecutionResult,
    Executor,
    ObservationEntry,
)
from triage.gate import ApprovalGate, AutoGate, CLIGate, RiskPolicy
from triage.journal import Journal, NoopJournal
from triage.llm import (
    LLM,
    Completion,
    FakeLLM,
    Message,
    OpenAICompatibleLLM,
    prompt_hash,
)
from triage.models import (
    Action,
    Alert,
    Finding,
    GateDecision,
    InvestigationPlan,
    PlanStep,
    ReasonerDecision,
    RunResult,
    Severity,
    TerminatedReason,
    ToolResult,
    Verdict,
)
from triage.planner import Planner
from triage.tools import (
    BLOCK_USER_TARGET_KEY,
    DataSource,
    FixtureDataSource,
    InvestigationTool,
    Tool,
    ToolRegistry,
    block_user,
    block_user_target,
    execute_tool,
)
from triage.verdict import (
    DEGRADED_CONFIDENCE,
    DEGRADED_SEVERITY,
    VerdictSynthesizer,
)

__version__ = "0.1.0"

__all__ = [
    "BLOCK_USER_TARGET_KEY",
    "DEGRADED_CONFIDENCE",
    "DEGRADED_SEVERITY",
    "LLM",
    "SCHEMA_VERSION",
    "Action",
    "Alert",
    "ApprovalGate",
    "AutoGate",
    "CLIGate",
    "Completion",
    "ConfigError",
    "DataSource",
    "ExecutionResult",
    "Executor",
    "FakeLLM",
    "Finding",
    "FixtureDataSource",
    "GateDecision",
    "GateError",
    "InvestigationPlan",
    "InvestigationTool",
    "Journal",
    "JournalError",
    "LLMError",
    "Message",
    "NoopJournal",
    "ObservationEntry",
    "OpenAICompatibleLLM",
    "PlanStep",
    "Planner",
    "ReasonerDecision",
    "RiskPolicy",
    "RunResult",
    "Severity",
    "TerminatedReason",
    "Tool",
    "ToolError",
    "ToolRegistry",
    "ToolResult",
    "TriageDeps",
    "TriageError",
    "Verdict",
    "VerdictSynthesizer",
    "__version__",
    "block_user",
    "block_user_target",
    "execute_tool",
    "prompt_hash",
    "summarize",
    "triage",
]
