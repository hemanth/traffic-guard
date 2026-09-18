# bot-gate

AI-powered bot and attack detection gate for incoming web traffic with zero required dependencies, advanced server-side defense patterns, and TypeSafe System One acceleration.

Available as a Node.js module (`node/`) and a Python package (`python/`).

## Philosophy

1. **Never speculate, benchmark.** All accuracy and latency claims are verified against the canonical ground-truth dataset in `bench/dataset.json`.
2. **Zero required dependencies.** Base `npm install bot-gate` and `pip install bot-gate` operate out of the box with zero external dependencies.
3. **Advanced Server-Side Defense.** Integrates Header Order Sequence analysis, stateless HMAC sliding-window velocity tokens, canary honeypots, tarpit latency defense, and inline HashCash Proof-of-Work micro-challenges.
4. **Progressive TypeSafe System One Tiering.** When `TYPESAFE_API_KEY` is provided, the gate elevates to `jev-latest` for semantic evaluation across 5 parallel typed questions.

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

## Advanced defense patterns implemented

1. **Header Order Sequence Analysis**: Inspects wire order of incoming headers. Bots forging Chromium User-Agents in Python/cURL exhibit unnatural header ordering (e.g. `User-Agent` before `Host`).
2. **Stateless HMAC Tokens & Velocity Tracking**: Signs a tamper-proof `__botgate` cookie via HMAC-SHA256 tracking request velocity in 10s windows with zero database dependency.
3. **Silent Proof-of-Work (PoW) Micro-Challenge**: Serves an inline 1.2 KB HashCash puzzle. Legitimate browsers solve it in 15–30 ms; automated CLI scrapers cannot execute JS.
4. **Tarpitting (Slowdown Defense)**: Artificial latency delays to exhaust bot concurrency pools.
5. **Canary Honeypot Traps**: Immediate blocking of crawlers that scrape invisible honeypot URLs.

## Empirical benchmark

Evaluated across 25 canonical ground-truth scenarios (`bench/dataset.json`):

| Metric | In-Tree JS | In-Tree Python | TypeSafe Cloud Tier (Jev-latest) |
|---|---|---|---|
| Category Classification | 100.0% | 100.0% | 100.0% |
| Action Accuracy | 100.0% | 100.0% | 100.0% |
| Attack Block Rate (Recall) | 100.0% | 100.0% | 100.0% |
| Human False Positive Rate | 0.0% | 0.0% | 0.0% |
| Good Bot Passthrough Rate | 100.0% | 100.0% | 100.0% |
| Mean Latency | 128 µs | 22 µs | ~250 ms |
| p95 Latency | 140 µs | 41 µs | ~320 ms |
| Dependencies | 0 required | 0 required | Optional SDK |

## Run benchmarks

```bash
node bench/bench.mjs
python3 bench/bench.py
```

## Packages

- [Node.js Module (`node/`)](./node)
- [Python Package (`python/`)](./python)

## License

MIT © [Hemanth.HM](https://h3manth.com)
