"""
Agentic AI Orchestrator — ToolRegistry

Central catalogue of all tools the Orchestrator may call.
Every tool has a validated schema; arguments are checked before dispatch.

Requirements: 2.1–2.6
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Callable

import jsonschema

from agents.exceptions import ToolNotFoundError, ToolArgValidationError
from agents.schemas import ToolSummary


class ToolCategory(str, enum.Enum):
    SYSTEM             = "SYSTEM"
    NETWORK            = "NETWORK"
    SECURITY           = "SECURITY"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    DEVICES            = "DEVICES"
    REPORTING          = "REPORTING"
    MONITORING         = "MONITORING"
    AUTOMATION         = "AUTOMATION"


class RiskLevel(str, enum.Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ToolDefinition:
    """Full descriptor for a registered tool."""
    name: str
    description: str
    category: ToolCategory
    input_schema: dict[str, Any]    # JSON Schema
    output_schema: dict[str, Any]   # JSON Schema
    permission_required: str        # "viewer" | "analyst" | "admin"
    risk_level: RiskLevel
    timeout_seconds: int
    audit_required: bool
    handler: Callable               # async function that performs the real work


class ToolRegistry:
    """
    Catalogue of all registered tools.
    Provides lookup, input-schema validation, and catalogue listing.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, tool: ToolDefinition) -> None:
        """Register a tool. Raises ValueError if the name is already taken."""
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' is already registered.")
        self._tools[tool.name] = tool

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, name: str) -> ToolDefinition:
        """Return the ToolDefinition for `name`. Raises ToolNotFoundError if absent."""
        try:
            return self._tools[name]
        except KeyError:
            raise ToolNotFoundError(f"Tool '{name}' is not registered in the Tool Registry.")

    # ------------------------------------------------------------------
    # Argument validation
    # ------------------------------------------------------------------

    def validate_args(self, tool: ToolDefinition, args: dict[str, Any]) -> None:
        """
        Validate `args` against tool.input_schema using jsonschema.
        Raises ToolArgValidationError if validation fails.
        Called BEFORE the handler is invoked — execution is blocked on error.
        """
        try:
            jsonschema.validate(instance=args, schema=tool.input_schema)
        except jsonschema.ValidationError as exc:
            raise ToolArgValidationError(
                f"Tool '{tool.name}' argument validation failed: {exc.message}"
            ) from exc
        except jsonschema.SchemaError as exc:
            raise ToolArgValidationError(
                f"Tool '{tool.name}' has an invalid input_schema: {exc.message}"
            ) from exc

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def get_catalogue(self) -> list[ToolSummary]:
        """Return lightweight ToolSummary list (no handler references)."""
        return [
            ToolSummary(
                name=t.name,
                description=t.description,
                category=t.category.value,
                risk_level=t.risk_level.value,
                input_schema=t.input_schema,
            )
            for t in self._tools.values()
        ]

    def get_all(self) -> list[ToolDefinition]:
        """Return all registered ToolDefinition objects."""
        return list(self._tools.values())


# ---------------------------------------------------------------------------
# Module-level singleton — populated by _register_all_tools() in task 3.4
# ---------------------------------------------------------------------------

_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Return the module-level ToolRegistry singleton, creating it if needed."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
