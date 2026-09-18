"""Unit and integration tests for bot-gate Python package."""

import pytest
from bot_gate import botgate, BotGate


@pytest.mark.asyncio
async def test_allows_normal_human_browser():
    req = {
        "method": "GET",
        "url": "/products/laptop-pro",
        "headers": {
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        },
    }

    decision = await botgate(req)
    assert decision.action == "allow"
    assert decision.should_block is False
    assert decision.should_challenge is False
    assert decision.is_attack is False
    assert decision.category == "human"
    assert decision.risk_score < 1.0


@pytest.mark.asyncio
async def test_blocks_sqli_attack():
    req = {
        "method": "GET",
        "url": "/search?q=' UNION SELECT username, password FROM users --",
        "headers": {"user-agent": "Mozilla/5.0"},
    }

    decision = await botgate(req)
    assert decision.action == "block"
    assert decision.should_block is True
    assert decision.is_attack is True
    assert decision.risk_score >= 2.0
    assert any("attack" in r.lower() for r in decision.reasons)


@pytest.mark.asyncio
async def test_blocks_known_attack_tools():
    req = {
        "method": "GET",
        "url": "/api/v1/users",
        "headers": {"user-agent": "sqlmap/1.5#stable (http://sqlmap.org)"},
    }

    decision = await botgate(req)
    assert decision.action == "block"
    assert decision.should_block is True
    assert decision.is_bot is True
    assert decision.category == "attack"


@pytest.mark.asyncio
async def test_blocks_sensitive_path_probe():
    req = {
        "method": "GET",
        "url": "/.env",
        "headers": {"user-agent": "python-requests/2.31.0"},
    }

    decision = await botgate(req)
    assert decision.action == "block"
    assert decision.should_block is True
    assert decision.risk_score >= 2.0


@pytest.mark.asyncio
async def test_allows_good_bots():
    req = {
        "method": "GET",
        "url": "/blog/ai-trends",
        "headers": {
            "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        },
    }

    decision = await botgate(req, allow_good_bots=True)
    assert decision.action == "allow"
    assert decision.should_block is False
    assert decision.category == "good_bot"
    assert decision.risk_score < 0.5


@pytest.mark.asyncio
async def test_detects_spoofed_headers():
    req = {
        "method": "GET",
        "url": "/dashboard",
        "headers": {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        },
    }

    decision = await botgate(req)
    assert decision.assessment is not None
    assert decision.assessment.is_spoofed_probability >= 0.5
    assert decision.should_challenge or decision.should_block


def test_sync_inspect():
    req = {
        "method": "GET",
        "url": "/.git/config",
        "headers": {"user-agent": "curl/7.88.1"},
    }

    decision = botgate.inspect(req)
    assert decision.action == "block"
    assert decision.should_block is True


def test_whitelisted_paths():
    gate = BotGate(whitelisted_paths=["/healthz"])
    decision = gate.inspect_sync("/healthz")
    assert decision.action == "allow"
    assert decision.should_block is False
    assert decision.reasons[0] == "Path whitelisted"
