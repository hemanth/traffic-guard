# bot-gate

AI-powered bot and attack detection gate for web traffic with zero required dependencies and TypeSafe System One acceleration.

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

`botgate(request)` inspects headers, paths, payloads, and client signals. Returns `action`, `should_block`, `risk_score`, and calibrated reasons.

## FastAPI / Starlette middleware

```python
from fastapi import FastAPI
from bot_gate import BotGateMiddleware

app = FastAPI()

app.add_middleware(
    BotGateMiddleware,
    policy="balanced",
    allow_good_bots=True,
    whitelisted_paths=["/healthz"],
)
```

## Empirical benchmark

Evaluated on 25 canonical golden test cases (`bench/dataset.json`) covering standard browsers, search crawlers, scrapers, and exploit injections (SQLi, XSS, JNDI, path traversal):

| Metric | In-Tree Zero-Dep Engine (Python) | TypeSafe Cloud Tier (Jev-latest) |
|---|---|---|
| Category Classification | 100.0% | 100.0% |
| Action Accuracy | 100.0% | 100.0% |
| Attack Block Rate (Recall) | 100.0% | 100.0% |
| Human False Positive Rate | 0.0% | 0.0% |
| Good Bot Passthrough Rate | 100.0% | 100.0% |
| Mean Latency | 13 µs (0.01 ms) | ~250 ms |
| p95 Latency | 19 µs | ~320 ms |
| External Dependencies | 0 required | Optional `typesafe-sdk` |

## Progressive tiering

- **In-Tree Algorithmic Engine**: Zero required external dependencies. Runs locally via Shannon entropy, header bitmask analysis, and token signatures in `< 20 µs`.
- **TypeSafe Cloud System One**: When `TYPESAFE_API_KEY` is provided, requests evaluate against `jev-latest` across 5 parallel typed questions for semantic understanding of novel obfuscated attacks.

## Run benchmark

```bash
python3 bench/bench.py
```

## License

MIT © [Hemanth.HM](https://h3manth.com)
