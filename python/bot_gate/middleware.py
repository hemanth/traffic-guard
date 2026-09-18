"""ASGI and WSGI middleware for bot-gate."""

from __future__ import annotations

import json
from typing import Any, Callable, Pattern

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
        fallback: str = "heuristic",
        on_block: Callable[[BotGateDecision, Any], Any] | None = None,
    ) -> None:
        self.app = app
        self.gate = BotGate(
            policy=policy,
            api_key=api_key,
            endpoint=endpoint,
            model=model,
            timeout=timeout,
            allow_good_bots=allow_good_bots,
            whitelisted_paths=whitelisted_paths,
            whitelisted_ips=whitelisted_ips,
            fallback=fallback,
            on_block=on_block,
        )

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Reconstruct request info from scope
        headers = {}
        for k, v in scope.get("headers", []):
            headers[k.decode("latin1").lower()] = v.decode("latin1")

        path = scope.get("path", "/")
        method = scope.get("method", "GET")
        client = scope.get("client")
        ip = client[0] if client else None

        req_info = {
            "method": method,
            "path": path,
            "headers": headers,
            "ip": ip,
        }

        decision = await self.gate.inspect(req_info)

        # Store decision in scope state if possible
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["bot_gate"] = decision

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

            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(response_body)).encode("ascii")),
                        (b"x-botgate-action", b"block"),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": response_body,
                }
            )
            return

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                resp_headers = list(message.get("headers", []))
                action_hdr = b"challenge" if decision.should_challenge else b"allow"
                resp_headers.append((b"x-botgate-action", action_hdr))
                resp_headers.append((b"x-botgate-risk", str(decision.risk_score).encode("ascii")))
                message["headers"] = resp_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)
