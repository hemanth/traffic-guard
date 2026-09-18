"""bot-gate: AI-powered bot and attack detection gate for web traffic using TypeSafe System One."""

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
from .gate import BotGate
from .middleware import BotGateMiddleware
from .normalizer import NormalizedRequest, RequestContext, check_header_order_anomaly, normalize_request
from .policy import DEFAULT_POLICIES, BotGateDecision, GatePolicy, evaluate_decision, resolve_policy

__version__ = "0.1.0"

_default_gate: BotGate | None = None


def _get_default_gate() -> BotGate:
    global _default_gate
    if _default_gate is None:
        _default_gate = BotGate()
    return _default_gate


async def botgate(
    request_input: Any,
    policy: str | GatePolicy | dict[str, Any] | None = None,
    **options: Any,
) -> BotGateDecision:
    """Asynchronously inspect incoming traffic and return a bot/attack detection decision."""
    if options or policy:
        gate = BotGate(policy=policy, **options)
        return await gate.inspect(request_input)
    return await _get_default_gate().inspect(request_input)


def inspect(
    request_input: Any,
    policy: str | GatePolicy | dict[str, Any] | None = None,
    **options: Any,
) -> BotGateDecision:
    """Synchronously inspect incoming traffic and return a bot/attack detection decision."""
    if options or policy:
        gate = BotGate(policy=policy, **options)
        return gate.inspect_sync(request_input)
    return _get_default_gate().inspect_sync(request_input)


def create(
    policy: str | GatePolicy | dict[str, Any] | None = None,
    **options: Any,
) -> BotGate:
    """Factory to create a configured BotGate instance."""
    return BotGate(policy=policy, **options)


botgate.inspect = inspect  # type: ignore[attr-defined]
botgate.create = create  # type: ignore[attr-defined]
botgate.BotGate = BotGate  # type: ignore[attr-defined]
botgate.Middleware = BotGateMiddleware  # type: ignore[attr-defined]

__all__ = [
    "botgate",
    "inspect",
    "create",
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
