"""Core BotGate implementation for Python."""

from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any, Callable, Pattern

from .battery import AssessmentResult, create_bot_gate_battery, heuristic_assessment
from .crypto import (
    create_client_hash,
    create_pow_challenge,
    generate_challenge_html,
    sign_bot_token,
    verify_bot_token,
)
from .normalizer import normalize_request
from .policy import BotGateDecision, GatePolicy, evaluate_decision, resolve_policy

_sdk_attempted = False
_AsyncTypeSafeClient: Any = None
_TypeSafeClient: Any = None


def _load_typesafe_sdk():
    global _sdk_attempted, _AsyncTypeSafeClient, _TypeSafeClient
    if not _sdk_attempted:
        _sdk_attempted = True
        try:
            from typesafe_sdk import AsyncTypeSafeClient, TypeSafeClient
            _AsyncTypeSafeClient = AsyncTypeSafeClient
            _TypeSafeClient = TypeSafeClient
        except ImportError:
            _AsyncTypeSafeClient = None
            _TypeSafeClient = None
    return _AsyncTypeSafeClient, _TypeSafeClient


class BotGate:
    """AI-powered bot and attack detection gate using TypeSafe System One."""

    def __init__(
        self,
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
        fallback: str = "heuristic",  # "heuristic" | "allow" | "block"
        on_block: Callable[[BotGateDecision, Any], Any] | None = None,
        on_tarpit: Callable[[BotGateDecision, Any], Any] | None = None,
    ) -> None:
        self.policy = resolve_policy(policy)
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY")
        self.endpoint = endpoint or os.environ.get("TYPESAFE_ENDPOINT")
        self.model = model
        self.timeout = timeout
        self.allow_good_bots = allow_good_bots
        self.whitelisted_paths = whitelisted_paths or []
        self.whitelisted_ips = whitelisted_ips or []
        self.honeypot_paths = honeypot_paths or []
        self.secret_key = secret_key or os.environ.get("BOTGATE_SECRET", "bot-gate-default-secret-key-32b!")
        self.tarpit_ms = tarpit_ms
        self.enable_pow_challenge = enable_pow_challenge
        self.fallback = fallback
        self.on_block = on_block
        self.on_tarpit = on_tarpit
        self._battery = create_bot_gate_battery()

    def _is_whitelisted(self, path: str, ip: str | None) -> tuple[bool, str]:
        for pattern in self.whitelisted_paths:
            if isinstance(pattern, str) and path == pattern:
                return True, "Path whitelisted"
            elif hasattr(pattern, "search") and pattern.search(path):
                return True, "Path matched whitelist pattern"
        if ip and self.whitelisted_ips and ip in self.whitelisted_ips:
            return True, "Client IP whitelisted"
        return False, ""

    async def inspect(
        self,
        request_input: Any,
        policy: str | GatePolicy | dict[str, Any] | None = None,
    ) -> BotGateDecision:
        """Asynchronously inspects an incoming request and returns a detection decision."""
        start = time.perf_counter()
        req, ctx = normalize_request(request_input)
        effective_policy = resolve_policy(policy) if policy else self.policy

        whitelisted, reason = self._is_whitelisted(req.path, req.ip)
        if whitelisted:
            return self._allowed_decision(reason, start)

        if self.honeypot_paths and req.path in self.honeypot_paths:
            ctx.is_honeypot = True

        # Stateless HMAC Token & Velocity Tracking (advanced defense pattern)
        user_agent = req.headers.get("user-agent", "")
        client_hash = create_client_hash(req.ip or "", user_agent)
        raw_cookie = req.cookies.get("__botgate")
        now = time.time()

        cookie_payload = verify_bot_token(raw_cookie, self.secret_key) if raw_cookie else None

        # If client previously verified a challenge and token is valid
        if cookie_payload and cookie_payload.h == client_hash and cookie_payload.v and cookie_payload.v > now:
            return self._allowed_decision("Client passed cryptographic verification", start)

        # Velocity tracking in 10-second sliding window
        current_count = 1
        window_start = now
        if cookie_payload and cookie_payload.h == client_hash:
            if now - cookie_payload.ws < 10.0:
                current_count = cookie_payload.c + 1
                window_start = cookie_payload.ws
        ctx.rate_count = current_count

        assessment: AssessmentResult
        AsyncClient, _ = _load_typesafe_sdk()

        if self.api_key and AsyncClient is not None and not ctx.is_honeypot:
            try:
                state = {
                    "request": {
                        "method": req.method,
                        "path": req.path,
                        "headers": req.headers,
                        "query": req.query,
                        "body": req.body,
                        "ip": req.ip,
                    },
                    "context": {
                        "missing_browser_headers": ctx.missing_browser_headers,
                        "suspicious_signatures": ctx.suspicious_signatures,
                        "claims_browser": ctx.claims_browser,
                        "is_known_search_bot": ctx.is_known_search_bot,
                        "header_order_anomaly": ctx.header_order_anomaly,
                        "rate_count": ctx.rate_count,
                    },
                }
                async with AsyncClient(
                    api_key=self.api_key,
                    base_url=self.endpoint,
                    timeout=self.timeout,
                ) as client:
                    resp = await client.system_one(
                        model=self.model,
                        state=state,
                        questions=self._battery,
                    )
                assessment = self._parse_response(resp)
            except Exception:
                if self.fallback == "block":
                    return self._blocked_decision("TypeSafe API unavailable (fallback: block)", start)
                elif self.fallback == "allow":
                    return self._allowed_decision("TypeSafe API unavailable (fallback: allow)", start)
                assessment = heuristic_assessment(req, ctx)
        else:
            assessment = heuristic_assessment(req, ctx)

        duration = round((time.perf_counter() - start) * 1000, 2)
        decision = evaluate_decision(
            assessment=assessment,
            policy=effective_policy,
            allow_good_bots=self.allow_good_bots,
            duration_ms=duration,
            context=ctx,
        )

        # Generate updated cookie token
        updated_token = sign_bot_token(
            {"h": client_hash, "c": current_count, "ws": window_start},
            self.secret_key,
        )
        decision.set_cookie_header = f"__botgate={updated_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"

        # If challenged, attach PoW HTML challenge
        if decision.should_challenge:
            seed, diff = create_pow_challenge(self.secret_key, 4)
            decision.challenge_html = generate_challenge_html(seed, diff, req.url or "/")

        return decision

    def inspect_sync(
        self,
        request_input: Any,
        policy: str | GatePolicy | dict[str, Any] | None = None,
    ) -> BotGateDecision:
        """Synchronously inspects an incoming request and returns a detection decision."""
        start = time.perf_counter()
        req, ctx = normalize_request(request_input)
        effective_policy = resolve_policy(policy) if policy else self.policy

        whitelisted, reason = self._is_whitelisted(req.path, req.ip)
        if whitelisted:
            return self._allowed_decision(reason, start)

        if self.honeypot_paths and req.path in self.honeypot_paths:
            ctx.is_honeypot = True

        # Stateless HMAC Token & Velocity Tracking (advanced defense pattern)
        user_agent = req.headers.get("user-agent", "")
        client_hash = create_client_hash(req.ip or "", user_agent)
        raw_cookie = req.cookies.get("__botgate")
        now = time.time()

        cookie_payload = verify_bot_token(raw_cookie, self.secret_key) if raw_cookie else None

        if cookie_payload and cookie_payload.h == client_hash and cookie_payload.v and cookie_payload.v > now:
            return self._allowed_decision("Client passed cryptographic verification", start)

        current_count = 1
        window_start = now
        if cookie_payload and cookie_payload.h == client_hash:
            if now - cookie_payload.ws < 10.0:
                current_count = cookie_payload.c + 1
                window_start = cookie_payload.ws
        ctx.rate_count = current_count

        assessment: AssessmentResult
        _, SyncClient = _load_typesafe_sdk()

        if self.api_key and SyncClient is not None and not ctx.is_honeypot:
            try:
                state = {
                    "request": {
                        "method": req.method,
                        "path": req.path,
                        "headers": req.headers,
                        "query": req.query,
                        "body": req.body,
                        "ip": req.ip,
                    },
                    "context": {
                        "missing_browser_headers": ctx.missing_browser_headers,
                        "suspicious_signatures": ctx.suspicious_signatures,
                        "claims_browser": ctx.claims_browser,
                        "is_known_search_bot": ctx.is_known_search_bot,
                        "header_order_anomaly": ctx.header_order_anomaly,
                        "rate_count": ctx.rate_count,
                    },
                }
                with SyncClient(
                    api_key=self.api_key,
                    base_url=self.endpoint,
                    timeout=self.timeout,
                ) as client:
                    resp = client.system_one(
                        model=self.model,
                        state=state,
                        questions=self._battery,
                    )
                assessment = self._parse_response(resp)
            except Exception:
                if self.fallback == "block":
                    return self._blocked_decision("TypeSafe API unavailable (fallback: block)", start)
                elif self.fallback == "allow":
                    return self._allowed_decision("TypeSafe API unavailable (fallback: allow)", start)
                assessment = heuristic_assessment(req, ctx)
        else:
            assessment = heuristic_assessment(req, ctx)

        duration = round((time.perf_counter() - start) * 1000, 2)
        decision = evaluate_decision(
            assessment=assessment,
            policy=effective_policy,
            allow_good_bots=self.allow_good_bots,
            duration_ms=duration,
            context=ctx,
        )

        updated_token = sign_bot_token(
            {"h": client_hash, "c": current_count, "ws": window_start},
            self.secret_key,
        )
        decision.set_cookie_header = f"__botgate={updated_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"

        if decision.should_challenge:
            seed, diff = create_pow_challenge(self.secret_key, 4)
            decision.challenge_html = generate_challenge_html(seed, diff, req.url or "/")

        return decision

    def _parse_response(self, resp: Any) -> AssessmentResult:
        answers = resp.answers

        is_bot_prob = getattr(answers.get("is_bot"), "noul", 0.1)
        is_attack_prob = getattr(answers.get("is_attack"), "noul", 0.05)
        is_spoofed_prob = getattr(answers.get("is_spoofed"), "noul", 0.05)

        traffic_answer = answers.get("traffic_type")
        traffic_type = getattr(traffic_answer, "choice", "human")
        traffic_conf = getattr(traffic_answer, "confidence", 0.8)
        traffic_dist = getattr(traffic_answer, "probabilities", {})

        risk_answer = answers.get("risk_level")
        risk_score = getattr(risk_answer, "score", 0.0)
        risk_conf = getattr(risk_answer, "confidence", 0.8)
        risk_dist = getattr(risk_answer, "probabilities", {})

        return AssessmentResult(
            is_bot_probability=is_bot_prob,
            is_attack_probability=is_attack_prob,
            is_spoofed_probability=is_spoofed_prob,
            traffic_type=traffic_type,
            traffic_type_confidence=traffic_conf,
            traffic_type_distribution=traffic_dist,
            risk_score=risk_score,
            risk_confidence=risk_conf,
            risk_level_distribution=risk_dist,
        )

    def _allowed_decision(self, reason: str, start: float) -> BotGateDecision:
        duration = round((time.perf_counter() - start) * 1000, 2)
        return BotGateDecision(
            action="allow",
            should_block=False,
            should_challenge=False,
            should_tarpit=False,
            is_bot=False,
            is_attack=False,
            category="human",
            risk_score=0.0,
            confidence=1.0,
            reasons=[reason],
            duration_ms=duration,
        )

    def _blocked_decision(self, reason: str, start: float) -> BotGateDecision:
        duration = round((time.perf_counter() - start) * 1000, 2)
        return BotGateDecision(
            action="block",
            should_block=True,
            should_challenge=False,
            should_tarpit=False,
            is_bot=True,
            is_attack=True,
            category="attack",
            risk_score=3.0,
            confidence=1.0,
            reasons=[reason],
            duration_ms=duration,
        )
