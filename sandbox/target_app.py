"""
Self-owned vulnerable sandbox — the LIVE target for the Offensive IT-Tester.

A tiny, deliberately vulnerable, server-rendered Flask app that stands in for
DVWA when Docker is not available. It runs with only `flask`, binds to
**loopback only** (127.0.0.1), and exposes one injection point per attack class
so live recon can crawl it and Layer 3 can select payloads against real findings.

    python sandbox/target_app.py            # serves http://127.0.0.1:5000

SAFETY: this is intentionally insecure and must ONLY ever run on localhost in a
throwaway context. It binds to 127.0.0.1 so it is never reachable off-box. The
command-injection endpoint is *simulated* (it never spawns a real shell) so that
running the sandbox cannot execute arbitrary commands on the host — enough for
recon/selection to treat it as a live CMDi point without the real-OS risk.
"""
from __future__ import annotations
import html
import sqlite3

from flask import Flask, request

app = Flask(__name__)

# in-memory demo DB (ephemeral; gone when the process exits)
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.executescript(
    "CREATE TABLE users(id INTEGER, name TEXT, password TEXT);"
    "INSERT INTO users VALUES (1,'admin','s3cr3t'),(2,'alice','wonderland');"
)

# stored-comment store for the stored-XSS point
_comments: list[str] = []

PAGE = """<!doctype html><html><head><title>{title}</title></head><body>
<h2>{title}</h2>
<p><a href="/">home</a></p>
{body}
</body></html>"""


@app.route("/")
def index():
    # links here let recon auto-discover every injection point
    links = [
        ("/sqli?user=admin", "SQL injection (GET user)"),
        ("/xss?name=friend", "Reflected XSS (GET name)"),
        ("/comment", "Stored XSS (POST comment)"),
        ("/exec", "Command injection (POST ip)"),
        ("/account", "CSRF (POST password_new)"),
        ("/fetch?url=http://example.com", "SSRF (GET url)"),
    ]
    body = "<ul>" + "".join(
        f'<li><a href="{href}">{label}</a></li>' for href, label in links
    ) + "</ul>"
    return PAGE.format(title="Vulnerable Sandbox", body=body)


@app.route("/sqli")
def sqli():
    # VULNERABLE: string-concatenated SQL in a STRING context (SQLi via ?user=).
    # A quote breaks the query -> real SQLite error (error_signature oracle); a
    # tautology like ' OR '1'='1 returns every row (differential oracle).
    q = request.args.get("user", request.args.get("id", ""))
    try:
        rows = _db.execute(
            f"SELECT id, name FROM users WHERE name = '{q}'").fetchall()
        out = ("<br>".join(f"id={r[0]} name={html.escape(str(r[1]))}" for r in rows)
               or "no user found")
    except Exception as e:  # the DB error is itself the SQLi oracle signal
        out = f"SQL error: {html.escape(str(e))}"
    form = '<form action="/sqli" method="GET"><input name="user" value="admin">' \
           '<input type="submit" value="Submit"></form>'
    return PAGE.format(title="SQLi", body=form + "<hr>" + out)


@app.route("/xss")
def xss():
    # VULNERABLE: reflects input unescaped (reflected XSS via ?name=)
    name = request.args.get("name", "")
    form = '<form action="/xss" method="GET"><input name="name">' \
           '<input type="submit" value="Search"></form>'
    return PAGE.format(title="Reflected XSS", body=form + f"<hr>Hello {name}")


@app.route("/comment", methods=["GET", "POST"])
def comment():
    # VULNERABLE: stores + renders comments unescaped (stored XSS via POST comment)
    if request.method == "POST":
        _comments.append(request.form.get("comment", ""))
    form = '<form action="/comment" method="POST"><textarea name="comment"></textarea>' \
           '<input type="submit" value="Post"></form>'
    shown = "<hr>" + "<br>".join(_comments)
    return PAGE.format(title="Stored XSS", body=form + shown)


@app.route("/exec", methods=["GET", "POST"])
def exec_cmd():
    # SIMULATED command injection (POST ip). We do NOT spawn a shell — we only
    # echo the input so recon sees a real CMDi-shaped point without host risk.
    ip = request.form.get("ip", "") if request.method == "POST" else ""
    form = '<form action="/exec" method="POST"><input name="ip" value="127.0.0.1">' \
           '<input type="submit" value="Ping"></form>'
    # Simulated: we do NOT run a shell and do NOT echo the input back, so no oracle
    # can (falsely) confirm command execution here — CMDi is honestly unconfirmable.
    out = "<hr><pre>command execution is simulated in this sandbox</pre>" if ip else ""
    return PAGE.format(title="Command Injection", body=form + out)


@app.route("/account", methods=["GET", "POST"])
def account():
    # CSRF-prone: state-changing POST with no anti-CSRF token (password_new)
    msg = ""
    if request.method == "POST":
        msg = f"<hr>password changed to {html.escape(request.form.get('password_new',''))}"
    form = '<form action="/account" method="POST">' \
           '<input name="password_new" type="password">' \
           '<input type="submit" value="Change"></form>'
    return PAGE.format(title="Account (CSRF)", body=form + msg)


@app.route("/fetch")
def fetch():
    # SSRF-shaped: takes a URL to "fetch" (we only echo it — no real request made)
    url = request.args.get("url", "")
    form = '<form action="/fetch" method="GET"><input name="url" value="http://example.com">' \
           '<input type="submit" value="Fetch"></form>'
    # Simulated: no request is made and the URL is not echoed back (SSRF would need
    # a real out-of-band callback server to confirm — honestly unconfirmable here).
    out = "<hr>fetch is simulated in this sandbox (no request made)" if url else ""
    return PAGE.format(title="SSRF", body=form + out)


if __name__ == "__main__":
    # loopback only — never reachable off this machine
    app.run(host="127.0.0.1", port=5000, debug=False)
