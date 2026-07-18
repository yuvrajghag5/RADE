"""
Open-source LLM client — local model via Ollama.

A thin wrapper over Ollama's /api/chat endpoint (default model qwen2.5:7b on
localhost:11434). Used by the optional LLMPolicy orchestrator and the Layer-7
report generator. Everything runs locally: no API key, no data leaves the box —
consistent with the project's self-hosting stance.

Only the standard library + `requests` (already a dependency) are needed.
"""
from __future__ import annotations
from dataclasses import dataclass

import requests
import yaml

from config.paths import ROOT

LLM_CONFIG = ROOT / "config" / "llm.yaml"


@dataclass
class LLMConfig:
    host: str = "http://localhost:11434"
    model: str = "qwen2.5:7b"
    timeout: int = 120
    temperature: float = 0.2

    @classmethod
    def load(cls) -> "LLMConfig":
        if LLM_CONFIG.exists():
            cfg = yaml.safe_load(LLM_CONFIG.read_text(encoding="utf-8")) or {}
            return cls(host=cfg.get("host", cls.host), model=cfg.get("model", cls.model),
                       timeout=cfg.get("timeout", cls.timeout),
                       temperature=cfg.get("temperature", cls.temperature))
        return cls()


class LLMError(RuntimeError):
    """The local LLM was unreachable or returned an unusable response."""


def to_ollama_tools(specs: list[dict]) -> list[dict]:
    """Adapt our Anthropic-style tool specs to Ollama's function-tool format."""
    return [
        {"type": "function", "function": {
            "name": s["name"],
            "description": s["description"],
            "parameters": s["input_schema"],
        }}
        for s in specs
    ]


class OllamaClient:
    def __init__(self, config: LLMConfig | None = None):
        self.cfg = config or LLMConfig.load()

    def available(self) -> bool:
        try:
            requests.get(f"{self.cfg.host}/api/tags", timeout=5).raise_for_status()
            return True
        except requests.RequestException:
            return False

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """Return the assistant `message` dict (may contain `tool_calls`)."""
        payload = {
            "model": self.cfg.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.cfg.temperature},
        }
        if tools:
            payload["tools"] = tools
        try:
            r = requests.post(f"{self.cfg.host}/api/chat", json=payload,
                              timeout=self.cfg.timeout)
            r.raise_for_status()
        except requests.RequestException as e:
            raise LLMError(f"Ollama call failed ({self.cfg.host}, model "
                           f"{self.cfg.model!r}): {e}") from e
        return r.json().get("message", {})
