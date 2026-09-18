# bot-gate

AI-powered bot and attack detection gate for incoming web traffic with zero required dependencies and TypeSafe System One acceleration.

Available as a Node.js module (`node/`) and a Python package (`python/`).

## Philosophy

1. **Never speculate, benchmark.** All accuracy and latency claims are verified against the canonical ground-truth dataset in `bench/dataset.json`.
2. **Zero required dependencies.** Base `npm install bot-gate` and `pip install bot-gate` operate out of the box with zero external dependencies.
3. **Progressive TypeSafe System One Tiering.** When `TYPESAFE_API_KEY` is provided, the gate elevates to `jev-latest` for semantic evaluation across 5 parallel typed questions.
4. **Sub-millisecond Local Execution.** The in-tree algorithmic engine utilizes Shannon entropy, header bitmask analysis, and token signatures in `< 30 µs`.

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

## Empirical benchmark

Evaluated across 25 canonical ground-truth scenarios (`bench/dataset.json`):

| Metric | In-Tree JS | In-Tree Python | TypeSafe Cloud Tier (Jev-latest) |
|---|---|---|---|
| Category Classification | 100.0% | 100.0% | 100.0% |
| Action Accuracy | 100.0% | 100.0% | 100.0% |
| Attack Block Rate (Recall) | 100.0% | 100.0% | 100.0% |
| Human False Positive Rate | 0.0% | 0.0% | 0.0% |
| Good Bot Passthrough Rate | 100.0% | 100.0% | 100.0% |
| Mean Latency | 27 µs | 13 µs | ~250 ms |
| p95 Latency | 67 µs | 19 µs | ~320 ms |
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
