# traffic-guard

High-throughput traffic and attack defense gate for incoming web traffic with zero required dependencies, wire-order analysis, and TypeSafe System One acceleration.

```bash
npm install traffic-guard
```

## Quick start

```js
import trafficguard from 'traffic-guard';

const decision = await trafficguard(req);

if (decision.shouldBlock) {
  return res.status(403).json({ error: 'Forbidden', reasons: decision.reasons });
}
```

`trafficguard(req)` inspects headers, wire sequence order, payload entropy, and velocity signals in under 30 µs. Returns `action`, `shouldBlock`, `shouldTarpit`, `riskScore`, and calibrated reasons.

## Express middleware

```js
import express from 'express';
import trafficguard from 'traffic-guard';

const app = express();

app.use(trafficguard.middleware({
  policy: 'balanced',
  allowGoodBots: true,
  honeypotPaths: ['/__tg_trap'], // instant ban for web spiders touching hidden links
  whitelistedPaths: ['/healthz', /^\/public\//]
}));

app.get('/api/data', (req, res) => res.json({ message: 'Hello Human!' }));
app.listen(3000);
```

## Advanced defense patterns implemented

1. **Header Order Sequence Analysis**: Real Chromium browsers send `Host` before `User-Agent` and Client Hints (`sec-ch-ua`) in a strict order. Bots forging user-agents in Python/cURL exhibit sequence disorder.
2. **Stateless HMAC Tokens & Velocity Tracking**: Signs a signed `__trafficguard` cookie via HMAC-SHA256 tracking request velocity in 10-second sliding windows with zero database dependency.
3. **Silent Proof-of-Work (PoW) Micro-Challenge**: Serves an inline 1.2 KB HashCash puzzle. Legitimate browsers solve it in 15–30 ms; automated CLI scrapers cannot execute JS.
4. **Tarpitting (Slowdown Defense)**: Configurable artificial latency delay for scrapers to exhaust their concurrency pools.
5. **Canary Honeypot Traps**: Immediate blocking of crawlers that scrape invisible honeypot URLs.

## Empirical benchmark

Evaluated on 25 canonical golden test cases (`bench/dataset.json`):

| Metric | In-Tree Zero-Dep Engine (JS) | TypeSafe Cloud Tier (Jev-latest) |
|---|---|---|
| Category Classification | 100.0% | 100.0% |
| Action Accuracy | 100.0% | 100.0% |
| Attack Block Rate (Recall) | 100.0% | 100.0% |
| Human False Positive Rate | 0.0% | 0.0% |
| Good Bot Passthrough Rate | 100.0% | 100.0% |
| Mean Latency | 30 µs (0.03 ms) | ~250 ms |
| p95 Latency | 56 µs | ~320 ms |
| External Dependencies | 0 required | Optional `@typesafe-ai/sdk` |

## License

MIT © [Hemanth.HM](https://h3manth.com)
