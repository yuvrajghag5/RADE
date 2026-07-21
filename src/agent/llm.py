"""
Open-source LLM client — local model via HuggingFace transformers.

Runs a small instruct model (default `Qwen/Qwen2.5-1.5B-Instruct`) in-process for
the Layer-7 report. Everything is local: the model is pulled from the HuggingFace
Hub once and cached, then runs on this machine (CPU or GPU) — no API key, no data
leaves the box, consistent with the project's self-hosting stance.

The model is **lazy-loaded**: importing this module is cheap, and the weights are
only loaded the first time `generate()` is called (i.e. only when `--report` is
used), so ordinary agent runs pay no cost.
"""
from __future__ import annotations
from dataclasses import dataclass

import yaml

from config.paths import ROOT

LLM_CONFIG = ROOT / "config" / "llm.yaml"


@dataclass
class LLMConfig:
    model: str = "Qwen/Qwen2.5-1.5B-Instruct"
    max_new_tokens: int = 500
    temperature: float = 0.3

    @classmethod
    def load(cls) -> "LLMConfig":
        if LLM_CONFIG.exists():
            c = yaml.safe_load(LLM_CONFIG.read_text(encoding="utf-8")) or {}
            return cls(model=c.get("model", cls.model),
                       max_new_tokens=c.get("max_new_tokens", cls.max_new_tokens),
                       temperature=c.get("temperature", cls.temperature))
        return cls()


class LLMError(RuntimeError):
    """The local model could not be loaded or generation failed."""


class HFClient:
    """Lazy wrapper over a transformers text-generation pipeline."""

    def __init__(self, config: LLMConfig | None = None):
        import threading
        self.cfg = config or LLMConfig.load()
        self._pipe = None
        self._lock = threading.Lock()   # so a pre-warm thread + the report thread
        #                                 don't load the model twice at once

    def _ensure(self):
        if self._pipe is not None:
            return
        with self._lock:                 # second caller waits, then sees it's loaded
            if self._pipe is not None:
                return
            try:
                import torch
                from transformers import pipeline
                self._pipe = pipeline(
                    "text-generation",
                    model=self.cfg.model,
                    torch_dtype=(torch.float16 if torch.cuda.is_available() else torch.float32),
                    device_map="auto" if torch.cuda.is_available() else None,
                )
            except Exception as e:
                raise LLMError(f"could not load HF model {self.cfg.model!r}: {e}") from e

    def stream(self, prompt: str, system: str | None = None):
        """Yield generated text chunks as the model produces them (for a live UI)."""
        self._ensure()
        from threading import Thread
        from transformers import TextIteratorStreamer
        tok = self._pipe.tokenizer
        model = self._pipe.model
        messages = ([{"role": "system", "content": system}] if system else []) + \
                   [{"role": "user", "content": prompt}]
        prompt_text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tok(prompt_text, return_tensors="pt").to(model.device)
        streamer = TextIteratorStreamer(tok, skip_prompt=True, skip_special_tokens=True)
        kwargs = dict(**inputs, max_new_tokens=self.cfg.max_new_tokens,
                      do_sample=self.cfg.temperature > 0, pad_token_id=tok.eos_token_id,
                      streamer=streamer)
        if self.cfg.temperature > 0:
            kwargs["temperature"] = self.cfg.temperature
        Thread(target=model.generate, kwargs=kwargs, daemon=True).start()
        for text in streamer:
            if text:
                yield text

    def generate(self, prompt: str, system: str | None = None) -> str:
        self._ensure()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            out = self._pipe(
                messages,
                max_new_tokens=self.cfg.max_new_tokens,
                do_sample=self.cfg.temperature > 0,
                temperature=max(self.cfg.temperature, 0.01),
                return_full_text=False,
            )
            gen = out[0]["generated_text"]
            # transformers returns either a string or the appended chat turn
            if isinstance(gen, list):
                return gen[-1]["content"].strip()
            return str(gen).strip()
        except Exception as e:
            raise LLMError(f"generation failed: {e}") from e
