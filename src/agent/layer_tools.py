"""
The seven layers, each wrapped as an agent Tool.

The LangGraph orchestrator never imports the layers directly — it invokes these
tools through the registry. That keeps the design honest to "an agent that
orchestrates tools": the graph decides *when* each tool runs and *whether* it may
(the governance gate, the branches); the tools are the *capabilities*.
"""
from __future__ import annotations

from src.authorization.authorize import authorize
from src.recon.recon import discover, build_session, ReconError
from src.intelligence.select import select_all
from src.governance import govern
from src.execution import baseline
from src.detection import detect
from .tools import Tool, ToolResult, ToolRegistry


def finding_dict(point, payload, conf) -> dict:
    return {
        "point": point.name, "url": point.full_url, "method": point.method,
        "param": point.param, "id": payload["id"],
        "attack_class": payload["attack_class"], "type": payload["type"],
        "severity": payload.get("severity"),
        "payload": payload["payload"], "oracle": conf.oracle,
        "confirmed": conf.confirmed, "confidence": conf.confidence,
        "evidence": conf.evidence,
    }


class AuthorizeTool(Tool):
    name = "authorize"
    description = ("Layer 1 scope firewall. Approve a target URL only if its host+port is "
                   "allowlisted and loopback. Always first; if it rejects, stop.")
    input_schema = {"type": "object",
                    "properties": {"target_url": {"type": "string"}},
                    "required": ["target_url"]}

    def run(self, target_url: str) -> ToolResult:
        d = authorize(target_url)
        return ToolResult(ok=True, output=d,
                          summary=("approved: " if d.approved else "rejected: ") + d.reason)


class ReconTool(Tool):
    name = "recon"
    description = ("Layer 2 live reconnaissance. Crawl the authorized target and return the "
                  "injection points discovered. Fails (ok=False) if unreachable.")
    input_schema = {"type": "object",
                    "properties": {"target_url": {"type": "string"}, "profile": {"type": "string"}},
                    "required": ["target_url"]}

    def run(self, target_url: str, profile: str = "dvwa") -> ToolResult:
        try:
            pts = discover(target_url, profile)
        except ReconError as e:
            return ToolResult(ok=False, error=str(e), summary="recon failed")
        return ToolResult(ok=True, output=pts, summary=f"{len(pts)} injection points discovered")


class SelectTool(Tool):
    name = "select_payloads"
    description = ("Layer 3. For each injection point choose payloads from the arsenal, "
                  "stratified by technique. Returns (point, [payloads]) pairs.")
    input_schema = {"type": "object",
                    "properties": {"points": {"type": "array"}, "k_per_type": {"type": "integer"}},
                    "required": ["points"]}

    def run(self, points, k_per_type: int = 2) -> ToolResult:
        sel = select_all(points, k_per_type=k_per_type)
        total = sum(len(pl) for _, pl in sel)
        return ToolResult(ok=True, output=sel,
                          summary=f"{total} payloads across {len(points)} points")


class GovernTool(Tool):
    name = "govern"
    description = ("Layer 4 governance gate (automated policy, no human review). Approve "
                  "payloads to fire autonomously; flag destructive ones for the audit. "
                  "allow_destructive=False re-imposes an automatic hold; max_per_point caps volume.")
    input_schema = {"type": "object",
                    "properties": {"selection": {"type": "array"},
                                   "allow_destructive": {"type": "boolean"},
                                   "max_per_point": {"type": "integer"}},
                    "required": ["selection"]}

    def run(self, selection, allow_destructive: bool = True,
            max_per_point: int | None = None) -> ToolResult:
        gate = govern(selection, allow_destructive=allow_destructive, max_per_point=max_per_point)
        return ToolResult(ok=True, output=gate, summary=gate.summary())


class ExecuteDetectTool(Tool):
    name = "execute_detect"
    description = ("Layers 5-6. Fire each governance-approved payload at the target and confirm "
                  "real exploits with the per-technique detection oracle.")
    input_schema = {"type": "object",
                    "properties": {"target_url": {"type": "string"}, "profile": {"type": "string"},
                                   "approved": {"type": "array"}},
                    "required": ["target_url", "approved"]}

    def run(self, target_url: str, approved, profile: str = "dvwa") -> ToolResult:
        session = build_session(target_url, profile)
        base_cache: dict = {}
        findings = []
        for point, payload in approved:
            if point.full_url not in base_cache:
                base_cache[point.full_url] = baseline(session, point)
            conf, _ = detect(session, point, payload, base_cache[point.full_url])
            findings.append(finding_dict(point, payload, conf))
        confirmed = sum(1 for f in findings if f["confirmed"] is True)
        return ToolResult(ok=True, output=findings,
                          summary=f"{len(findings)} fired, {confirmed} confirmed")


def build_registry() -> ToolRegistry:
    """Register one tool per layer and return the registry the graph orchestrates."""
    reg = ToolRegistry()
    for tool in (AuthorizeTool(), ReconTool(), SelectTool(),
                 GovernTool(), ExecuteDetectTool()):
        reg.register(tool)
    return reg
