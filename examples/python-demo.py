"""Demonstration and traffic simulation script for Python bot-gate."""

import asyncio
from bot_gate import BotGate, botgate


async def main():
    gate = BotGate(
        policy="balanced",
        allow_good_bots=True,
        whitelisted_paths=["/healthz", "/favicon.ico"],
    )

    print("--- Simulating Incoming Traffic Scenarios (Python) ---\n")

    scenarios = [
        {
            "name": "Normal Human Visitor",
            "req": {
                "method": "GET",
                "url": "/pricing",
                "headers": {
                    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/122.0.0.0 Safari/537.36",
                    "accept": "text/html,application/xhtml+xml",
                    "accept-language": "en-US,en;q=0.9",
                    "accept-encoding": "gzip, deflate, br",
                    "sec-ch-ua": '"Chromium";v="122"',
                },
            },
        },
        {
            "name": "Googlebot Crawler",
            "req": {
                "method": "GET",
                "url": "/articles/ai-advances",
                "headers": {
                    "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                },
            },
        },
        {
            "name": "Automated CLI Scraper",
            "req": {
                "method": "GET",
                "url": "/api/v1/customers",
                "headers": {
                    "user-agent": "python-requests/2.31.0",
                },
            },
        },
        {
            "name": "SQL Injection Exploit Attack",
            "req": {
                "method": "POST",
                "url": "/login",
                "headers": {
                    "user-agent": "Mozilla/5.0",
                },
                "body": "username=admin' OR 1=1 --&password=test",
            },
        },
        {
            "name": "Sensitive File Probe Attack",
            "req": {
                "method": "GET",
                "url": "/.env",
                "headers": {
                    "user-agent": "curl/8.4.0",
                },
            },
        },
    ]

    for s in scenarios:
        decision = await gate.inspect(s["req"])
        badge = "[BLOCKED]" if decision.should_block else "[CHALLENGE]" if decision.should_challenge else "[ALLOWED]"
        print(f"{badge:<12} {s['name']}")
        print(f"  Action:     {decision.action}")
        print(f"  Category:   {decision.category}")
        print(f"  Risk Score: {decision.risk_score} / 3.0")
        print(f"  Reasons:    {'; '.join(decision.reasons)}\n")


if __name__ == "__main__":
    asyncio.run(main())
