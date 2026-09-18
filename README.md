# traffic-guard

High-throughput traffic and attack defense gate for incoming web traffic with zero required dependencies, wire-order sequence validation, and TypeSafe System One acceleration.

Available as a Node.js module (`node/`) and a Python package (`python/`).

## Philosophy

1. **Never speculate, benchmark.** All accuracy and latency claims are verified against the canonical ground-truth dataset in `bench/dataset.json`.
2. **Zero required dependencies.** Base `npm install traffic-guard` and `pip install traffic-guard` operate out of the box with zero external dependencies.
3. **Advanced Server-Side Defense.** Integrates Header Order Sequence analysis, stateless HMAC sliding-window velocity tokens, canary honeypots, tarpit latency defense, and inline HashCash Proof-of-Work micro-challenges.
4. **Progressive TypeSafe System One Tiering.** When `TYPESAFE_API_KEY` is provided, the gate elevates to `jev-latest` for semantic evaluation across 5 parallel typed questions.

## Quick start (Node.js)

```bash
npm install traffic-guard
```

```js
import trafficguard from 'traffic-guard';

const decision = await trafficguard(req);

if (decision.shouldBlock) {
  return res.status(403).json({ error: 'Blocked', reasons: decision.reasons });
}
```

## Quick start (Python)

```bash
pip install traffic-guard
```

```python
from traffic_guard import trafficguard

decision = await trafficguard(request)

if decision.should_block:
    return Response(status_code=403, content="Forbidden")
```

## Advanced defense patterns implemented

1. **Header Order Sequence Analysis**: Inspects wire order of incoming headers. Bots forging Chromium User-Agents in Python/cURL exhibit unnatural header ordering (e.g. `User-Agent` before `Host`).
2. **Stateless HMAC Tokens & Velocity Tracking**: Signs a tamper-proof `__trafficguard` cookie via HMAC-SHA256 tracking request velocity in 10s windows with zero database dependency.
3. **Silent Proof-of-Work (PoW) Micro-Challenge**: Serves an inline 1.2 KB HashCash puzzle. Legitimate browsers solve it in 15–30 ms; automated CLI scrapers cannot execute JS.
4. **Tarpitting (Slowdown Defense)**: Artificial latency delays to exhaust bot concurrency pools.
5. **Canary Honeypot Traps**: Immediate blocking of crawlers that scrape invisible honeypot URLs.

## Progressive TypeSafe System One tiering (Optional)

By default, `traffic-guard` runs entirely in-tree with zero dependencies in <100 µs. For deep semantic reasoning against long-tail obfuscated attacks and zero false positives, configure your TypeSafe API key:

```bash
export TYPESAFE_API_KEY=ts_live_...
```

Or pass it directly in code:

```js
// Node.js
import { TrafficGuard } from 'traffic-guard';

const guard = new TrafficGuard({
  apiKey: process.env.TYPESAFE_API_KEY,
  model: 'jev-latest' // default
});
```

```python
# Python
import os
from traffic_guard import TrafficGuard

guard = TrafficGuard(
    api_key=os.environ.get("TYPESAFE_API_KEY"),
    model="jev-latest"
)
```

## Empirical benchmark

Evaluated across 25 canonical ground-truth scenarios (`bench/dataset.json`):

| Metric | In-Tree JS | In-Tree Python | TypeSafe Cloud Tier (Jev-latest) |
|---|---|---|---|
| Category Classification | 100.0% | 100.0% | 100.0% |
| Action Accuracy | 100.0% | 100.0% | 100.0% |
| Attack Block Rate (Recall) | 100.0% | 100.0% | 100.0% |
| Human False Positive Rate | 0.0% | 0.0% | 0.0% |
| Good Bot Passthrough Rate | 100.0% | 100.0% | 100.0% |
| Mean Latency | 30 µs | 20 µs | ~250 ms |
| p95 Latency | 56 µs | 39 µs | ~320 ms |
| Dependencies | 0 required | 0 required | Optional SDK |

## Run benchmarks

```bash
node bench/bench.mjs
python3 bench/bench.py
```

## Packages & Playground

- [Interactive Playground (GitHub Pages)](https://hemanth.github.io/traffic-guard/)
- [Node.js Module (`node/`)](./node)
- [Python Package (`python/`)](./python)

## License

MIT © [Hemanth.HM](https://h3manth.com)
