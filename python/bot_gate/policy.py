"""Routing policies and decision engine for bot-gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from .battery import AssessmentResult


@dataclass
class GatePolicy:
    attack_threshold: float = 0.75
    bot_threshold: float = 0.85
    challenge_threshold: float = 0.50
    risk_block: float = 2.2
    risk_challenge: float = 1.4
    spoof_threshold: float = 0.60


DEFAULT_POLICIES: dict[str, GatePolicy] = {
    "balanced": GatePolicy(
        attack_threshold=0.75,
        bot_threshold=0.85,
        challenge_threshold=0.50,
        risk_block=2.2,
        risk_challenge=1.4,
        spoof_threshold=0.60,
    ),
    "strict": GatePolicy(
        attack_threshold=0.60,
        bot_threshold=0.70,
        challenge_threshold=0.35,
        risk_block=1.8,
        risk_challenge=1.0,
        spoof_threshold=0.40,
    ),
    "permissive": GatePolicy(
        attack_threshold=0.88,
        bot_threshold=0.92,
        challenge_threshold=0.70,
        risk_block=2.6,
        risk_challenge=2.0,
        spoof_threshold=0.75,
    ),
}


@dataclass
class BotGateDecision:
    action: str  # "allow" | "challenge" | "block" | "monitor"
    should_block: bool
    should_challenge: bool
    is_bot: bool
    is_attack: bool
    category: str  # "human" | "good_bot" | "bad_bot" | "attack"
    risk_score: float
    confidence: float
    reasons: list[str] = field(default_factory=list)
    assessment: AssessmentResult | None = None
    duration_ms: float = 0.0


def resolve_policy(policy: str | GatePolicy | dict[str, Any] | None) -> GatePolicy:
    if isinstance(policy, GatePolicy):
        return policy
    if isinstance(policy, str):
        return DEFAULT_POLICIES.get(policy, DEFAULT_POLICIES["balanced"])
    if isinstance(policy, dict):
        base = DEFAULT_POLICIES["balanced"]
        return GatePolicy(
            attack_threshold=policy.get("attack_threshold", base.attack_threshold),
            bot_threshold=policy.get("bot_threshold", base.bot_threshold),
            challenge_threshold=policy.get("challenge_threshold", base.challenge_threshold),
            risk_block=policy.get("risk_block", base.risk_block),
            risk_challenge=policy.get("risk_challenge", base.risk_challenge),
            spoof_threshold=policy.get("spoof_threshold", base.spoof_threshold),
        )
    return DEFAULT_POLICIES["balanced"]


def evaluate_decision(
    assessment: AssessmentResult,
    policy: GatePolicy,
    allow_good_bots: bool = True,
    duration_ms: float = 0.0,
) -> BotGateDecision:
    reasons: list[str] = []

    # Verified good bots pass if allow_good_bots is true and no attack detected
    if allow_good_bots and assessment.traffic_type == "good_bot" and assessment.is_attack_probability < 0.4:
        return BotGateDecision(
            action="allow",
            should_block=False,
            should_challenge=False,
            is_bot=True,
            is_attack=False,
            category="good_bot",
            risk_score=assessment.risk_score,
            confidence=assessment.traffic_type_confidence,
            reasons=["Verified legitimate crawler allowed by policy"],
            assessment=assessment,
            duration_ms=duration_ms,
        )

    action = "allow"

    # 1. Attack evaluation (highest precedence)
    if assessment.is_attack_probability >= policy.attack_threshold:
        action = "block"
        reasons.append(
            f"Detected malicious attack payload or exploit attempt (probability: {int(assessment.is_attack_probability * 100)}%)"
        )

    # 2. Risk level evaluation
    if assessment.risk_score >= policy.risk_block:
        action = "block"
        reasons.append(f"High risk severity score ({assessment.risk_score:.2f} >= {policy.risk_block})")
    elif assessment.risk_score >= policy.risk_challenge and action != "block":
        action = "challenge"
        reasons.append(f"Elevated risk severity score ({assessment.risk_score:.2f} >= {policy.risk_challenge})")

    # 3. Bad bot evaluation
    if assessment.is_bot_probability >= policy.bot_threshold and assessment.traffic_type == "bad_bot":
        action = "block"
        reasons.append(
            f"Unapproved automated bot/scraper detected (probability: {int(assessment.is_bot_probability * 100)}%)"
        )
    elif assessment.is_bot_probability >= policy.challenge_threshold and action == "allow":
        action = "challenge"
        reasons.append(
            f"Possible automated traffic requiring verification (probability: {int(assessment.is_bot_probability * 100)}%)"
        )

    # 4. Header spoofing evaluation
    if assessment.is_spoofed_probability >= policy.spoof_threshold and action == "allow":
        action = "challenge"
        reasons.append(
            f"Suspicious header inconsistency or impersonation detected (probability: {int(assessment.is_spoofed_probability * 100)}%)"
        )

    if action == "allow" and not reasons:
        reasons.append("Traffic matches expected legitimate profile")

    return BotGateDecision(
        action=action,
        should_block=(action == "block"),
        should_challenge=(action == "challenge"),
        is_bot=(assessment.is_bot_probability >= 0.5),
        is_attack=(assessment.is_attack_probability >= 0.5),
        category=assessment.traffic_type,
        risk_score=assessment.risk_score,
        confidence=assessment.traffic_type_confidence,
        reasons=reasons,
        assessment=assessment,
        duration_ms=duration_ms,
    )
