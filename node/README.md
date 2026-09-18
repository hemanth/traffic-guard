# bot-gate

AI-powered bot and attack detection gate for web traffic with zero required dependencies and TypeSafe System One acceleration.

```bash
npm install bot-gate
```

## Quick start

```js
import botgate from 'bot-gate';

const gate = await botgate(req);

if (gate.shouldBlock) {
  return res.status(403).json({ error: 'Forbidden', reasons: gate.reasons });
}
```

`botgate(req)` inspects headers, paths, payloads, and client signals. Returns `action`, `shouldBlock`, `riskScore`, and calibrated reasons.

## Express middleware

```js
import express from 'express';
import botgate from 'bot-gate';

const app = express();

app.use(botgate.middleware({
  policy: 'balanced',
  allowGoodBots: true,
  whitelistedPaths: ['/healthz', /^\/public\//]
}));

app.get('/api/data', (req, res) => res.json({ message: 'Hello Human!' }));
app.listen(3000);
```

## Empirical benchmark

Evaluated on 25 canonical golden test cases (`bench/dataset.json`) covering standard browsers, search crawlers, scrapers, and exploit injections (SQLi, XSS, JNDI, path traversal):

| Metric | In-Tree Zero-Dep Engine (JS) | TypeSafe Cloud Tier (Jev-latest) |
|---|---|---|
| Category Classification | 100.0% | 100.0% |
| Action Accuracy | 100.0% | 100.0% |
| Attack Block Rate (Recall) | 100.0% | 100.0% |
| Human False Positive Rate | 0.0% | 0.0% |
| Good Bot Passthrough Rate | 100.0% | 100.0% |
| Mean Latency | 27 µs (0.03 ms) | ~250 ms |
| p95 Latency | 67 µs | ~320 ms |
| External Dependencies | 0 required | Optional `@typesafe-ai/sdk` |

## Progressive tiering

- **In-Tree Algorithmic Engine**: Zero required external dependencies. Runs locally via Shannon entropy, header bitmask analysis, and token signatures in `< 30 µs`.
- **TypeSafe Cloud System One**: When `TYPESAFE_API_KEY` is provided, requests evaluate against `jev-latest` across 5 parallel typed questions for semantic understanding of novel obfuscated attacks.

## Run benchmark

```bash
node bench/bench.mjs
```

## License

MIT © [Hemanth.HM](https://h3manth.com)
