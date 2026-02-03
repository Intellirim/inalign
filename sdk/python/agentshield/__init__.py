from agentshield.async_client import AsyncAgentShield
from agentshield.exceptions import (
    AgentShieldError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from agentshield.models import (
    AlertListResponse,
    AlertResponse,
    AnomalyInfo,
    LogActionResponse,
    PIIInfo,
    ReportResponse,
    ScanInputResponse,
    ScanOutputResponse,
    SessionListResponse,
    SessionResponse,
    ThreatInfo,
    # Governance models
    AgentResponse,
    AgentListResponse,
    AgentStatsResponse,
    PolicyResponse,
    PolicyListResponse,
    ProxyResponse,
    ActivityResponse,
    ActivityListResponse,
    EfficiencyReport,
    EfficiencySuggestion,
)
from agentshield.sync_client import AgentShield
from agentshield.governance import (
    GovernanceClient,
    GovernedSession,
    SessionContext,
    governed,
)

__version__ = "0.2.0"

__all__ = [
    # Clients
    "AgentShield",
    "AsyncAgentShield",
    "GovernanceClient",
    "GovernedSession",
    "SessionContext",
    # Decorators
    "governed",
    # Models - Scan
    "ScanInputResponse",
    "ScanOutputResponse",
    "ThreatInfo",
    "PIIInfo",
    "LogActionResponse",
    "AnomalyInfo",
    "SessionResponse",
    "SessionListResponse",
    "ReportResponse",
    "AlertResponse",
    "AlertListResponse",
    # Models - Governance
    "AgentResponse",
    "AgentListResponse",
    "AgentStatsResponse",
    "PolicyResponse",
    "PolicyListResponse",
    "ProxyResponse",
    "ActivityResponse",
    "ActivityListResponse",
    "EfficiencyReport",
    "EfficiencySuggestion",
    # Exceptions
    "AgentShieldError",
    "AuthenticationError",
    "RateLimitError",
    "NotFoundError",
    "ValidationError",
    "ServerError",
    # Meta
    "__version__",
]
