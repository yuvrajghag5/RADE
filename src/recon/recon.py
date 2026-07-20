"""
Layer 2 — Reconnaissance (LIVE crawler for DVWA).

Given an authorized base URL, recon actually talks to the running app:

  1. logs in (DVWA CSRF `user_token` + default credentials),
  2. sets the security level to `low` (so the injection points are exploitable),
  3. crawls the vulnerability pages and parses every <form> field and URL
     parameter with BeautifulSoup to DISCOVER injection points,
  4. maps each discovered field to a `context_bucket` + candidate attack
     `classes` via a documented heuristic (so Layer 3 selection can run).

This is LIVE-ONLY: if the target cannot be reached or login fails, recon raises
`ReconError` and the pipeline stops (no silent fallback to a declared profile).
Crawl settings (paths, credentials, security level) come from the target profile
YAML — see config/targets/dvwa.yaml — so a scan's scope is auditable as data.

`discover_from_profile()` remains for offline development only and is never
called by the live path.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs

import requests
import yaml
from bs4 import BeautifulSoup

from config.paths import ROOT

PROFILE_DIR = ROOT / "config" / "targets"

# form fields that are never injection points
SKIP_INPUT_TYPES = {"submit", "hidden", "button", "image", "reset", "file"}
SKIP_NAMES = {"user_token", "login", "seclev_submit", "create_db", "submit"}


class ReconError(RuntimeError):
    """Live recon could not reach or authenticate to the target."""


@dataclass
class InjectionPoint:
    name: str          # human label
    full_url: str      # absolute URL the payload is sent to
    method: str        # GET / POST
    param: str         # the parameter to inject into
    bucket: str        # normalised bucket (matches dataset context_bucket)
    classes: list      # attack classes worth trying here
    source: str = "live"   # "live" (crawled) or "profile" (declared)

    def short(self) -> str:
        return f"{self.method:4} {self.full_url}?{self.param}=  [{self.bucket}]"


# ---------------------------------------------------------------------------
# Heuristic: map a discovered (page, param) to bucket + candidate classes.
# Recon discovers the STRUCTURE live (which URLs/params exist); this step
# assigns meaning. Keyed on the DVWA vulnerability directory + the field name,
# so it is transparent and matches the dataset's context_bucket vocabulary.
# ---------------------------------------------------------------------------
# Parameter-name → (bucket, classes). The field name is the strongest signal of
# what an injection point is for, and this works for any server-rendered app
# (DVWA or our own), not just DVWA's directory names. First substring match wins,
# so order matters (more specific names first).
PARAM_RULES = [
    ("password", ("account_settings", ["csrf"])),
    ("ip",       ("command_exec",     ["cmdi"])),
    ("cmd",      ("command_exec",     ["cmdi"])),
    ("host",     ("command_exec",     ["cmdi"])),
    ("page",     ("ssrf_target",      ["ssrf"])),
    ("url",      ("ssrf_target",      ["ssrf"])),
    ("uri",      ("ssrf_target",      ["ssrf"])),
    ("comment",  ("comment_field",    ["xss", "csrf"])),
    ("message",  ("comment_field",    ["xss", "csrf"])),
    ("body",     ("comment_field",    ["xss", "csrf"])),
    ("user",     ("login_form",       ["sqli"])),
    ("login",    ("login_form",       ["sqli"])),
    ("search",   ("search_field",     ["xss", "sqli"])),
    ("query",    ("search_field",     ["xss", "sqli"])),
    ("keyword",  ("search_field",     ["xss", "sqli"])),
    ("name",     ("search_field",     ["xss", "sqli"])),
    ("id",       ("url_param",        ["sqli"])),
]

# Fallback keyed on the DVWA vulnerability directory (when the field name is generic).
VULN_MAP = {
    "sqli":       ("url_param",     ["sqli"]),
    "sqli_blind": ("url_param",     ["sqli"]),
    "xss_r":      ("search_field",  ["xss", "sqli"]),
    "xss_s":      ("comment_field", ["xss", "csrf"]),
    "xss_d":      ("url_param",     ["xss"]),
    "exec":       ("command_exec",  ["cmdi"]),
    "csrf":       ("account_settings", ["csrf"]),
    "fi":         ("ssrf_target",   ["ssrf"]),
    "brute":      ("login_form",    ["sqli"]),
}


def _vuln_dir(path: str) -> str:
    """Extract the DVWA vulnerability directory, e.g. /vulnerabilities/sqli/ -> 'sqli'."""
    segs = [s for s in path.split("/") if s]
    if "vulnerabilities" in segs:
        i = segs.index("vulnerabilities")
        if i + 1 < len(segs):
            return segs[i + 1]
    return segs[-1] if segs else ""


def classify(path: str, param: str, method: str) -> tuple[str, list]:
    """Return (context_bucket, candidate_classes) for a discovered field."""
    p = param.lower()
    for needle, (bucket, classes) in PARAM_RULES:
        if needle in p:
            return bucket, list(classes)

    # field name was generic — fall back to what kind of page it lives on
    bucket, classes = VULN_MAP.get(_vuln_dir(path),
                                   ("form_field" if method == "POST" else "url_param",
                                    ["sqli", "xss"]))
    return bucket, list(classes)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def _get(session, url, timeout):
    try:
        return session.get(url, timeout=timeout)
    except requests.RequestException as e:
        raise ReconError(f"cannot reach {url} — is DVWA running there? ({e})") from e


def _post(session, url, data, timeout):
    try:
        return session.post(url, data=data, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        raise ReconError(f"cannot reach {url} — is DVWA running there? ({e})") from e


def _csrf_token(html: str) -> str | None:
    tok = BeautifulSoup(html, "html.parser").find("input", {"name": "user_token"})
    return tok.get("value") if tok else None


def _auto_setup(session, base, crawl, timeout):
    """Best-effort: create/reset the DVWA database so a fresh container works."""
    url = base + crawl.get("setup_path", "/setup.php")
    try:
        r = _get(session, url, timeout)
    except ReconError:
        return  # setup is optional; login will surface a real failure
    data = {"create_db": "Create / Reset Database"}
    token = _csrf_token(r.text)
    if token:
        data["user_token"] = token
    session.post(url, data=data, timeout=timeout, allow_redirects=True)


def _login(session, base, crawl, timeout):
    login_url = base + crawl["login_path"]
    page = _get(session, login_url, timeout)
    data = {
        "username": crawl["username"],
        "password": crawl["password"],
        "Login": "Login",
    }
    token = _csrf_token(page.text)
    if token:
        data["user_token"] = token
    resp = _post(session, login_url, data, timeout)

    # DVWA redirects to index.php on success and back to login.php on failure.
    if resp.url.rstrip("/").endswith("login.php") or "login failed" in resp.text.lower():
        raise ReconError(
            f"login failed at {login_url} as {crawl['username']!r} — "
            "check credentials or that the DVWA database is initialised (/setup.php)."
        )


def _set_security(session, base, crawl, timeout):
    level = crawl.get("security_level", "low")
    # DVWA reads the level from the `security` cookie; set it directly …
    host = urlparse(base).hostname
    session.cookies.set("security", level, domain=host)
    # … and submit the form too (belt and braces).
    sec_url = base + crawl.get("security_path", "/security.php")
    page = _get(session, sec_url, timeout)
    data = {"security": level, "seclev_submit": "Submit"}
    token = _csrf_token(page.text)
    if token:
        data["user_token"] = token
    session.post(sec_url, data=data, timeout=timeout, allow_redirects=True)


# ---------------------------------------------------------------------------
# Crawling
# ---------------------------------------------------------------------------
def _discover_vuln_links(session, base, crawl, timeout) -> list[str]:
    """Scan the index page for links to /vulnerabilities/* (auto-discovery)."""
    url = base + crawl.get("index_path", "/index.php")
    try:
        r = _get(session, url, timeout)
    except ReconError:
        return []
    found = set()
    for a in BeautifulSoup(r.text, "html.parser").find_all("a", href=True):
        href = a["href"]
        path = urlparse(urljoin(url, href)).path
        if "/vulnerabilities/" in path:
            vuln = _vuln_dir(path)
            if vuln:
                found.add(f"/vulnerabilities/{vuln}/")
    return sorted(found)


def _points_on_page(session, base, path, timeout) -> list[InjectionPoint]:
    """GET a page and extract injection points from its forms + URL query params."""
    page_url = base + path
    r = _get(session, page_url, timeout)
    soup = BeautifulSoup(r.text, "html.parser")
    points: list[InjectionPoint] = []

    # (a) URL query parameters already present on the seed path (e.g. fi/?page=)
    clean_path = urlparse(path).path
    for param in parse_qs(urlparse(path).query):
        bucket, classes = classify(clean_path, param, "GET")
        points.append(InjectionPoint(_vuln_dir(clean_path) or "root",
                                     page_url.split("?", 1)[0],
                                     "GET", param, bucket, classes))

    # (b) form fields
    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        # action="#" / "" both mean "submit to this same page" — resolve to the
        # page URL and drop any #fragment or ?query so the target URL is clean.
        raw_action = form.get("action")
        target = raw_action if raw_action not in (None, "", "#") else path
        action_url = urljoin(page_url, target).split("#", 1)[0].split("?", 1)[0]
        action_path = urlparse(action_url).path
        for inp in form.find_all(["input", "textarea"]):
            itype = (inp.get("type") or "text").lower()
            name = inp.get("name")
            if not name or itype in SKIP_INPUT_TYPES or name.lower() in SKIP_NAMES:
                continue
            bucket, classes = classify(action_path, name, method)
            points.append(InjectionPoint(_vuln_dir(action_path) or "root",
                                         action_url, method, name, bucket, classes))
    return points


def _load_profile(profile: str) -> dict:
    path = PROFILE_DIR / f"{profile}.yaml"
    if not path.exists():
        raise ReconError(f"no recon profile at {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def build_session(base_url: str, profile: str = "dvwa") -> requests.Session:
    """A ready-to-use HTTP session for the target: logged in + security set when
    the profile needs it (DVWA), or a plain session for a no-auth sandbox.

    Shared by recon (Layer 2) and execution (Layer 5) so payloads are fired in
    the same authenticated context the injection points were discovered in.
    """
    cfg = _load_profile(profile)
    crawl = cfg.get("crawl") or {}
    base = base_url.rstrip("/")
    timeout = crawl.get("request_timeout", 10)
    session = requests.Session()
    # Auth is optional: a no-login sandbox (our Flask target) omits `login_path`.
    if crawl.get("login_path"):
        if crawl.get("auto_setup"):
            _auto_setup(session, base, crawl, timeout)
        _login(session, base, crawl, timeout)
        _set_security(session, base, crawl, timeout)
    return session


def discover_live(base_url: str, profile: str = "dvwa") -> list[InjectionPoint]:
    """Log in, set security, crawl, and return the injection points actually found."""
    cfg = _load_profile(profile)
    crawl = cfg.get("crawl")
    if not crawl:
        raise ReconError(f"profile {profile!r} has no `crawl:` section for live recon")
    base = base_url.rstrip("/")
    timeout = crawl.get("request_timeout", 10)

    session = build_session(base_url, profile)

    # seed paths (always) + links auto-discovered from the index menu
    paths = list(crawl.get("seed_paths", []))
    for p in _discover_vuln_links(session, base, crawl, timeout):
        if p not in {x.split("?", 1)[0] for x in paths}:
            paths.append(p)

    points: list[InjectionPoint] = []
    seen: set[tuple] = set()
    for path in paths:
        for pt in _points_on_page(session, base, path, timeout):
            key = (pt.method, pt.full_url, pt.param)
            if key not in seen:
                seen.add(key)
                points.append(pt)

    if not points:
        raise ReconError(
            f"crawl of {base} reached the app but found no injection points — "
            "check the security level and that the vulnerability pages exist."
        )
    return points


def discover(target_url: str, profile: str = "dvwa") -> list[InjectionPoint]:
    """Live-only entry point (hard-fail if the target is down)."""
    return discover_live(target_url, profile)


# ---------------------------------------------------------------------------
# Offline fallback — declared profile, NOT used by the live path.
# ---------------------------------------------------------------------------
def discover_from_profile(profile: str = "dvwa") -> list[InjectionPoint]:
    cfg = _load_profile(profile)
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
            source="profile",
        ))
    return points
