"""Tests for FastAPI / Starlette ASGI middleware with advanced defense patterns."""

import hashlib
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from bot_gate import BotGateMiddleware, create_pow_challenge

app = FastAPI()
app.add_middleware(
    BotGateMiddleware,
    policy="strict",
    whitelisted_paths=["/healthz"],
    honeypot_paths=["/__bg_trap"],
    secret_key="test-secret-key",
    tarpit_ms=10,
)


@app.get("/healthz")
async def health():
    return {"status": "ok"}


@app.get("/api/data")
async def get_data():
    return {"data": "confidential data"}


@pytest.mark.asyncio
async def test_middleware_allows_whitelisted():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_middleware_blocks_attack():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/api/data?q=' UNION SELECT 1, 2 --",
            headers={"user-agent": "sqlmap/1.5"},
        )
        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "Forbidden"
        assert data["action"] == "block"


@pytest.mark.asyncio
async def test_middleware_blocks_honeypot():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/__bg_trap")
        assert resp.status_code == 403
        data = resp.json()
        assert "honeypot" in data["reasons"][0]


@pytest.mark.asyncio
async def test_middleware_pow_verify_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        seed, diff = create_pow_challenge("test-secret-key", 2)
        nonce = 0
        while True:
            h = hashlib.sha256(f"{seed}:{nonce}".encode("utf-8")).hexdigest()
            if h.startswith("00"):
                break
            nonce += 1

        resp = await client.post(
            "/__botgate/verify",
            json={
                "seed": seed,
                "nonce": str(nonce),
                "isAutomated": False,
                "returnUrl": "/api/data",
            },
        )
        assert resp.status_code == 200
        assert "set-cookie" in resp.headers
        assert "__botgate=" in resp.headers["set-cookie"]


@pytest.mark.asyncio
async def test_middleware_allows_legitimate():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/api/data",
            headers={
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "accept": "text/html,application/json",
                "accept-language": "en-US,en;q=0.9",
                "accept-encoding": "gzip, deflate, br",
                "sec-ch-ua": '"Chromium";v="120"',
            },
        )
        assert resp.status_code == 200
        assert resp.headers.get("x-botgate-action") == "allow"
        assert resp.json() == {"data": "confidential data"}
