"""
Layer 1 — Authorization gate.

Answers one question: "am I allowed to touch this target?" A URL is approved only
if its host+port is on the allowlist (config/target_allowlist.yaml) AND, when
`require_loopback` is set, only if the host is a loopback address. Everything else
is rejected with a reason. This is the scope firewall.
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse

import yaml

from config.paths import ROOT

ALLOWLIST = ROOT / "config" / "target_allowlist.yaml"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


@dataclass
class Decision:
    approved: bool
    reason: str
    host: str = ""
    port: int = 0
    profile: str = ""


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def authorize(target_url: str, allowlist_path=ALLOWLIST) -> Decision:
    cfg = yaml.safe_load(allowlist_path.read_text(encoding="utf-8"))
    require_loopback = bool(cfg.get("require_loopback", False))
    allowed = cfg.get("allowed", [])

    parsed = urlparse(target_url if "://" in target_url else "http://" + target_url)
    host = parsed.hostname or ""
    port = parsed.port or _default_port(parsed.scheme)

    if not host:
        return Decision(False, f"could not parse a host from {target_url!r}")

    if require_loopback and host not in LOOPBACK:
        return Decision(False, f"host {host!r} is not loopback (require_loopback=true)",
                        host, port)

    for entry in allowed:
        if entry["host"] == host and port in entry.get("ports", []):
            return Decision(True, f"allowlisted: {entry.get('label', host)}",
                            host, port, entry.get("profile", ""))

    return Decision(False, f"{host}:{port} is not on the allowlist", host, port)
