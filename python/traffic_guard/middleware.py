"""ASGI and WSGI middleware for traffic-guard."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Pattern

from .crypto import create_client_hash, sign_bot_token, verify_pow
from .gate import BotGate
from .policy import BotGateDecision, GatePolicy


class BotGateMiddleware:
    """ASGI middleware for Starlette, FastAPI, and other ASGI applications."""

    def __init__(
        self,
        app: Any,
        policy: str | GatePolicy | dict[str, Any] | None = None,
        api_key: str | None = None,
        endpoint: str | None = None,
        model: str = "jev-latest",
        timeout: float = 15.0,
        allow_good_bots: bool = True,
        whitelisted_paths: list[str | Pattern] | None = None,
        whitelisted_ips: list[str] | None = None,
        honeypot_paths: list[str] | None = None,
        secret_key: str | None = None,
        tarpit_ms: int = 3000,
        enable_pow_challenge: bool = True,
        fallback: str = "heuristic",
        on_block: Callable[[BotGateDecision, Any], Any] | None = None,
        on_tarpit: Callable[[BotGateDecision, Any], Any] | None = None,
    ) -> None:
        self.app = app
        self.secret_key = secret_key or "traffic-guard-default-secret-key-32b!"
        self.tarpit_ms = tarpit_ms
        self.enable_pow_challenge = enable_pow_challenge
        self.gate = BotGate(
            policy=policy,
            api_key=api_key,
            endpoint=endpoint,
            model=model,
            timeout=timeout,
            allow_good_bots=allow_good_bots,
            whitelisted_paths=whitelisted_paths,
            whitelisted_ips=whitelisted_ips,
            honeypot_paths=honeypot_paths,
            secret_key=self.secret_key,
            tarpit_ms=tarpit_ms,
            enable_pow_challenge=enable_pow_challenge,
            fallback=fallback,
            on_block=on_block,
            on_tarpit=on_tarpit,
        )

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {}
        raw_headers = []
        for k, v in scope.get("headers", []):
            k_str = k.decode("latin1")
            v_str = v.decode("latin1")
            headers[k_str.lower()] = v_str
            raw_headers.append(k_str)

        path = scope.get("path", "/")
        method = scope.get("method", "GET")
        client = scope.get("client")
        ip = client[0] if client else None

        # Handle Proof-of-Work challenge verification route
        if method == "POST" and path == "/__botgate/verify":
            body_bytes = b""
            more_body = True
            while more_body:
                message = await receive()
                body_bytes += message.get("body", b"")
                more_body = message.get("more_body", False)

            try:
                data = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                data = {}

            seed = data.get("seed", "")
            nonce = data.get("nonce", "")
            is_automated = data.get("isAutomated", False)
            return_url = data.get("returnUrl", "/")

            if not is_automated and verify_pow(seed, nonce, expected_difficulty=None, secret=self.secret_key):
                ua = headers.get("user-agent", "")
                chash = create_client_hash(ip or "", ua)
                # Grant 30 minutes verification
                import time
                token = sign_bot_token(
                    {"h": chash, "c": 1, "ws": time.time(), "v": time.time() + 1800.0},
                    self.secret_key,
                )
                cookie_hdr = f"__botgate={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800"
                resp_body = json.dumps({"status": "ok", "redirect": return_url}).encode("utf-8")
                await send({
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"set-cookie", cookie_hdr.encode("latin1")),
                    ],
                })
                await send({"type": "http.response.body", "body": resp_body})
                return
            else:
                resp_body = json.dumps({"error": "Verification failed"}).encode("utf-8")
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-type", b"application/json")],
                })
                await send({"type": "http.response.body", "body": resp_body})
                return

        req_info = {
            "method": method,
            "path": path,
            "headers": headers,
            "raw_headers": raw_headers,
            "ip": ip,
        }

        decision = await self.gate.inspect(req_info)

        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["bot_gate"] = decision

        # Tarpit handling
        if decision.should_tarpit:
            await asyncio.sleep(self.tarpit_ms / 1000.0)
            response_body = json.dumps({
                "error": "Too Many Requests",
                "message": "Velocity burst exceeded threshold",
                "action": "tarpit",
                "reasons": decision.reasons,
            }).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"x-botgate-action", b"tarpit"),
                ],
            })
            await send({"type": "http.response.body", "body": response_body})
            return

        # Block handling
        if decision.should_block:
            response_body = json.dumps(
                {
                    "error": "Forbidden",
                    "message": "Access blocked by BotGate security policy",
                    "action": decision.action,
                    "reasons": decision.reasons,
                    "category": decision.category,
                    "risk_score": decision.risk_score,
                }
            ).encode("utf-8")

            res_headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(response_body)).encode("ascii")),
                (b"x-botgate-action", b"block"),
            ]
            if decision.set_cookie_header:
                res_headers.append((b"set-cookie", decision.set_cookie_header.encode("latin1")))

            await send({"type": "http.response.start", "status": 403, "headers": res_headers})
            await send({"type": "http.response.body", "body": response_body})
            return

        # Challenge handling
        if decision.should_challenge and self.enable_pow_challenge and decision.challenge_html:
            challenge_bytes = decision.challenge_html.encode("utf-8")
            res_headers = [
                (b"content-type", b"text/html; charset=utf-8"),
                (b"content-length", str(len(challenge_bytes)).encode("ascii")),
                (b"x-botgate-action", b"challenge"),
            ]
            if decision.set_cookie_header:
                res_headers.append((b"set-cookie", decision.set_cookie_header.encode("latin1")))
            await send({"type": "http.response.start", "status": 428, "headers": res_headers})
            await send({"type": "http.response.body", "body": challenge_bytes})
            return

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                resp_headers = list(message.get("headers", []))
                action_hdr = b"challenge" if decision.should_challenge else b"allow"
                resp_headers.append((b"x-botgate-action", action_hdr))
                resp_headers.append((b"x-botgate-risk", str(decision.risk_score).encode("ascii")))
                if decision.set_cookie_header:
                    resp_headers.append((b"set-cookie", decision.set_cookie_header.encode("latin1")))
                message["headers"] = resp_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


TrafficGuardMiddleware = BotGateMiddleware
