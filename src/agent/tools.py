"""
Tool framework for the agent (in-process).

A Tool is a named capability the agent can invoke: it carries a machine-readable
spec (name + description + JSON-schema input) and a run() function. The spec is
deliberately in **Anthropic tool-use format**, so the exact same tools could be
handed to an LLM policy later (hybrid-ready) — today they are called by the
deterministic policy.

`ToolResult.ok` means "the tool executed" (no crash), NOT "the answer was yes".
A rejection from the authorization tool is still `ok=True` with a Decision that
says approved=False — the policy interprets the output.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    ok: bool                     # did the tool run without error?
    output: Any = None           # domain object the tool produced
    summary: str = ""            # one-line human/audit summary
    error: str = ""              # populated when ok=False


class Tool:
    """Base class for a callable capability. Subclasses set name/description/schema."""
    name: str = ""
    description: str = ""
    input_schema: dict = {"type": "object", "properties": {}}

    def run(self, **kwargs) -> ToolResult:
        raise NotImplementedError

    def spec(self) -> dict:
        """Anthropic tool-use compatible spec (what an LLM policy would receive)."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


class ToolRegistry:
    """Holds the agent's tools and invokes them by name."""

    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if not tool.name:
            raise ValueError("tool has no name")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return list(self._tools)

    def list_specs(self) -> list[dict]:
        """The catalogue a policy (rule-based or LLM) sees to choose from."""
        return [t.spec() for t in self._tools.values()]

    def invoke(self, name: str, args: dict) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(False, error=f"unknown tool {name!r}")
        try:
            return tool.run(**args)
        except Exception as e:  # a tool must never crash the agent loop
            return ToolResult(False, error=f"{type(e).__name__}: {e}")
