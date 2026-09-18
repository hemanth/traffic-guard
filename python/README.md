# bot-gate

AI-powered bot and attack detection gate for web traffic with zero required dependencies, advanced server-side defense patterns, and TypeSafe System One acceleration.

```bash
pip install bot-gate
```

## Quick start

```python
from bot_gate import botgate

decision = await botgate(request)

if decision.should_block:
    return Response(status_code=403, content="Forbidden")
```

`botgate(request)` inspects headers, sequence order, payload entropy, and velocity signals. Returns `action`, `should_block`, `should_tarpit`, `risk_score`, and calibrated reasons.

## FastAPI / Starlette middleware

```python
from fastapi import FastAPI
from bot_gate import BotGateMiddleware

app = FastAPI()

app.add_middleware(
    BotGateMiddleware,
    policy="balanced",
    allow_good_bots=True,
    honeypot_paths=["/__bg_trap"],
    whitelisted_paths=["/healthz"],
)
```

## Advanced defense patterns implemented

1. **Header Order Sequence Analysis**: Real Chromium browsers send `Host` before `User-Agent` and Client Hints (`sec-ch-ua`) in a strict order. Bots forging user-agents in Python/cURL exhibit sequence disorder.
2. **Stateless HMAC Tokens & Velocity Tracking**: Signs a signed `__botgate` cookie via HMAC-SHA256 tracking request velocity in 10-second sliding windows with zero database dependency.
3. **Silent Proof-of-Work (PoW) Micro-Challenge**: Serves an inline 1.2 KB HashCash puzzle. Legitimate browsers solve it in 15–30 ms; automated CLI scrapers cannot execute JS.
4. **Tarpitting (Slowdown Defense)**: Configurable artificial latency delay for scrapers to exhaust their concurrency pools.
5. **Canary Honeypot Traps**: Immediate blocking of crawlers that scrape invisible honeypot URLs.

## Empirical benchmark

Evaluated on 25 canonical golden test cases (`bench/dataset.json`):

| Metric | In-Tree Zero-Dep Engine (Python) | TypeSafe Cloud Tier (Jev-latest) |
|---|---|---|
| Category Classification | 100.0% | 100.0% |
| Action Accuracy | 100.0% | 100.0% |
| Attack Block Rate (Recall) | 100.0% | 100.0% |
| Human False Positive Rate | 0.0% | 0.0% |
| Good Bot Passthrough Rate | 100.0% | 100.0% |
| Mean Latency | 22 µs (0.02 ms) | ~250 ms |
| p95 Latency | 41 µs | ~320 ms |
| External Dependencies | 0 required | Optional `typesafe-sdk` |

## Run benchmark

```bash
python3 bench/bench.py
```

## License

MIT © [Hemanth.HM](https://h3manth.com)
