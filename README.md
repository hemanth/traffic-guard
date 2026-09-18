# bot-gate

AI-powered bot and attack detection gate for incoming web traffic using TypeSafe System One.

Available as a Node.js module and a Python package.

## How it works

Traditional WAFs rely on brittle regexes that miss obfuscated payloads and generate false positives. `bot-gate` uses TypeSafe's System One model (`jev-latest`) to evaluate incoming HTTP traffic across five semantic dimensions in a single parallel request:

1. `is_bot` (Noul) — Probability of automated tool, crawler, headless browser, or scraper
2. `is_attack` (Noul) — Probability of SQLi, XSS, path traversal, exploit probe, or credential abuse
3. `is_spoofed` (Noul) — Probability of browser impersonation or discordant client headers
4. `traffic_type` (Choice) — Categorization into `human`, `good_bot`, `bad_bot`, or `attack`
5. `risk_level` (Score) — Calibrated risk severity on a 0–3 scale

Your application owns the decision policy (`allow`, `challenge`, `block`) while the model provides fast, calibrated judgments.

## Quick start (Node.js)

```bash
npm install bot-gate
```

```js
import botgate from 'bot-gate';

const gate = await botgate(req);

if (gate.shouldBlock) {
  return res.status(403).json({ error: 'Blocked', reasons: gate.reasons });
}
```

Or as Express middleware:

```js
import express from 'express';
import botgate from 'bot-gate';

const app = express();
app.use(botgate.middleware({ policy: 'balanced', allowGoodBots: true }));
```

## Quick start (Python)

```bash
pip install bot-gate
```

```python
from bot_gate import botgate

decision = await botgate(request)

if decision.should_block:
    return Response(status_code=403, content="Forbidden")
```

Or as FastAPI / Starlette middleware:

```python
from fastapi import FastAPI
from bot_gate import BotGateMiddleware

app = FastAPI()
app.add_middleware(BotGateMiddleware, policy="balanced", allow_good_bots=True)
```

## Detection scenarios

| Scenario | Incoming Traffic Profile | Action | Risk Score | Category |
|---|---|---|---|---|
| Human Visitor | Valid headers (`accept-language`, `sec-ch-ua`) | `allow` | `0.09` | `human` |
| Search Engine | Verified Googlebot / Bingbot crawler | `allow` | `0.10` | `good_bot` |
| Automated Scraper | `python-requests`, `curl`, headless tools | `block` / `challenge` | `0.70` | `bad_bot` |
| SQL Injection | Payload containing `' UNION SELECT ... --` | `block` | `3.00` | `attack` |
| Probe Attack | Endpoint probing `/.env` or `/wp-login.php` | `block` | `3.00` | `attack` |

## Run simulation demos

Node demo:

```bash
node examples/node-demo.mjs
```

Python demo:

```bash
python3 examples/python-demo.py
```

## Packages

- [Node.js Module (`node/`)](./node)
- [Python Package (`python/`)](./python)

## License

MIT © [Hemanth.HM](https://h3manth.com)
