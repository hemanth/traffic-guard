"""traffic-guard: High-throughput traffic and attack defense gate using TypeSafe System One."""

from __future__ import annotations

from typing import Any

from .battery import AssessmentResult, calculate_shannon_entropy, create_bot_gate_battery, heuristic_assessment
from .crypto import (
    create_client_hash,
    create_pow_challenge,
    generate_challenge_html,
    parse_cookies,
    sign_bot_token,
    verify_bot_token,
    verify_pow,
)
from .gate import BotGate, TrafficGuard
from .middleware import BotGateMiddleware, TrafficGuardMiddleware
from .normalizer import NormalizedRequest, RequestContext, check_header_order_anomaly, normalize_request
from .policy import DEFAULT_POLICIES, BotGateDecision, GatePolicy, TrafficDecision, evaluate_decision, resolve_policy

__version__ = "0.1.0"

_default_guard: TrafficGuard | None = None


def _get_default_guard() -> TrafficGuard:
    global _default_guard
    if _default_guard is None:
        _default_guard = TrafficGuard()
    return _default_guard


async def trafficguard(
    request_input: Any,
    policy: str | GatePolicy | dict[str, Any] | None = None,
    **options: Any,
) -> TrafficDecision:
    """Asynchronously inspect incoming traffic and return a bot/attack detection decision."""
    if options or policy:
        guard = TrafficGuard(policy=policy, **options)
        return await guard.inspect(request_input)
    return await _get_default_guard().inspect(request_input)


def inspect(
    request_input: Any,
    policy: str | GatePolicy | dict[str, Any] | None = None,
    **options: Any,
) -> TrafficDecision:
    """Synchronously inspect incoming traffic and return a bot/attack detection decision."""
    if options or policy:
        guard = TrafficGuard(policy=policy, **options)
        return guard.inspect_sync(request_input)
    return _get_default_guard().inspect_sync(request_input)


def create(
    policy: str | GatePolicy | dict[str, Any] | None = None,
    **options: Any,
) -> TrafficGuard:
    """Factory to create a configured TrafficGuard instance."""
    return TrafficGuard(policy=policy, **options)


trafficguard.inspect = inspect  # type: ignore[attr-defined]
trafficguard.create = create  # type: ignore[attr-defined]
trafficguard.TrafficGuard = TrafficGuard  # type: ignore[attr-defined]
trafficguard.Middleware = TrafficGuardMiddleware  # type: ignore[attr-defined]

# Aliases for ergonomics & backward compatibility
traffic_guard = trafficguard
botgate = trafficguard

__all__ = [
    "trafficguard",
    "traffic_guard",
    "botgate",
    "inspect",
    "create",
    "TrafficGuard",
    "TrafficGuardMiddleware",
    "TrafficDecision",
    "BotGate",
    "BotGateMiddleware",
    "BotGateDecision",
    "GatePolicy",
    "DEFAULT_POLICIES",
    "normalize_request",
    "evaluate_decision",
    "resolve_policy",
    "create_bot_gate_battery",
    "heuristic_assessment",
    "calculate_shannon_entropy",
    "check_header_order_anomaly",
    "create_client_hash",
    "sign_bot_token",
    "verify_bot_token",
    "create_pow_challenge",
    "verify_pow",
    "generate_challenge_html",
    "parse_cookies",
]
