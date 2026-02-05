"""InALign integrations with popular AI agent frameworks."""

# LangChain integration
from inalign.integrations.langchain import (
    InALignCallback,
    create_governed_agent as create_langchain_agent,
)

# CrewAI integration (optional - requires crewai)
try:
    from inalign.integrations.crewai import (
        GovernedCrew,
        govern_agent as govern_crewai_agent,
        create_governed_tool as create_crewai_tool,
    )
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    GovernedCrew = None  # type: ignore
    govern_crewai_agent = None  # type: ignore
    create_crewai_tool = None  # type: ignore

# AutoGPT integration
from inalign.integrations.autogpt import (
    InALignMiddleware,
    GovernedCommandRegistry,
    govern_command,
    ForgeInALignPlugin,
)

__all__ = [
    # LangChain
    "InALignCallback",
    "create_langchain_agent",
    # CrewAI
    "GovernedCrew",
    "govern_crewai_agent",
    "create_crewai_tool",
    "CREWAI_AVAILABLE",
    # AutoGPT
    "InALignMiddleware",
    "GovernedCommandRegistry",
    "govern_command",
    "ForgeInALignPlugin",
]
