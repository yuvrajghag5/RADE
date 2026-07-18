"""
The three Layer 1-3 capabilities, wrapped as agent Tools.

Each tool is a thin adapter over the existing layer function, plus a
machine-readable spec. The agent never imports the layers directly — it only
sees these tools through the registry, which is what lets the decision policy
(rule-based today, LLM tomorrow) orchestrate them.
"""
from __future__ import annotations

from src.authorization.authorize import authorize
from src.recon.recon import discover, ReconError
from src.intelligence.select import select_all
from .tools import Tool, ToolResult


class AuthorizeTool(Tool):
    name = "authorize"
    description = (
        "Layer 1 scope firewall. Decide whether a target URL may be scanned at "
        "all: it is approved only if the host+port is on the allowlist and (when "
        "required) is a loopback address. Always call this FIRST; if it rejects, "
        "stop — nothing else may run."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "target_url": {"type": "string", "description": "The target URL to authorize."}
        },
        "required": ["target_url"],
    }

    def run(self, target_url: str) -> ToolResult:
        d = authorize(target_url)
        verb = "approved" if d.approved else "rejected"
        return ToolResult(ok=True, output=d, summary=f"{verb}: {d.reason}")


class ReconTool(Tool):
    name = "recon"
    description = (
        "Layer 2 live reconnaissance. Crawl the AUTHORIZED target (log in if "
        "needed, set security level, parse forms and URL parameters) and return "
        "the injection points discovered. Only call this after authorize approves. "
        "Fails (ok=False) if the target is unreachable."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "target_url": {"type": "string", "description": "Authorized target base URL."},
            "profile": {"type": "string", "description": "Crawl profile name (e.g. 'dvwa', 'pyapp')."},
        },
        "required": ["target_url"],
    }

    def run(self, target_url: str, profile: str = "dvwa") -> ToolResult:
        try:
            points = discover(target_url, profile)
        except ReconError as e:
            return ToolResult(ok=False, error=str(e), summary="recon failed")
        return ToolResult(ok=True, output=points,
                          summary=f"{len(points)} injection points discovered")


class SelectPayloadsTool(Tool):
    name = "select_payloads"
    description = (
        "Layer 3 payload selection. For each discovered injection point, choose "
        "payloads from the labelled arsenal, stratified by technique so no "
        "technique is skipped. Returns (injection_point, [payloads]) pairs. Call "
        "after recon has produced injection points."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "points": {"type": "array", "description": "Injection points from recon."},
            "k_per_type": {"type": "integer", "description": "Payloads per technique (default 2)."},
        },
        "required": ["points"],
    }

    def run(self, points, k_per_type: int = 2) -> ToolResult:
        selection = select_all(points, k_per_type=k_per_type)
        total = sum(len(pl) for _, pl in selection)
        return ToolResult(ok=True, output=selection,
                          summary=f"{total} payloads across {len(points)} injection points")


def build_registry():
    """Register the Layer 1-3 tools and return the registry."""
    from .tools import ToolRegistry
    reg = ToolRegistry()
    reg.register(AuthorizeTool())
    reg.register(ReconTool())
    reg.register(SelectPayloadsTool())
    return reg
