"""
Layer 2 — Reconnaissance.

Finds the injection points on an authorized target (forms, URL parameters).
A live crawler (requests + BeautifulSoup) is the target design; until it is wired
up, recon loads a declared sandbox profile (config/targets/<profile>.yaml) so the
pipeline runs offline against the known DVWA layout.
"""
from __future__ import annotations
from dataclasses import dataclass

import yaml

from config.paths import ROOT

PROFILE_DIR = ROOT / "config" / "targets"


@dataclass
class InjectionPoint:
    name: str          # human label
    full_url: str      # base_url + path
    method: str        # GET / POST
    param: str         # the parameter to inject into
    bucket: str        # normalised injection-point bucket (matches dataset context_bucket)
    classes: list      # attack classes worth trying here

    def short(self) -> str:
        return f"{self.method:4} {self.full_url}?{self.param}=  [{self.bucket}]"


def discover(profile: str = "dvwa") -> list[InjectionPoint]:
    """Return the injection points for the named sandbox profile."""
    path = PROFILE_DIR / f"{profile}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"no recon profile at {path}")
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    base = cfg["base_url"].rstrip("/")

    points = []
    for ip in cfg["injection_points"]:
        points.append(InjectionPoint(
            name=ip["name"],
            full_url=base + ip["url"],
            method=ip["method"],
            param=ip["param"],
            bucket=ip["bucket"],
            classes=list(ip["classes"]),
        ))
    return points
