# bot-gate

AI-powered bot and attack detection gate for web traffic using TypeSafe System One.

```bash
npm install bot-gate
```

## Quick start

```js
import botgate from 'bot-gate';

const gate = await botgate(req);

if (gate.shouldBlock) {
  return res.status(403).json({ error: 'Blocked', reasons: gate.reasons });
}
```

`botgate(req)` inspects headers, paths, payloads, and client signals against TypeSafe System One. Returns `action`, `shouldBlock`, `riskScore`, and calibrated reasons.

## Express middleware

```js
import express from 'express';
import botgate from 'bot-gate';

const app = express();

app.use(botgate.middleware({
  policy: 'balanced', // 'strict' | 'balanced' | 'permissive'
  allowGoodBots: true, // passes Googlebot, Bingbot, uptime monitors
  whitelistedPaths: ['/healthz', /^\/public\//]
}));

app.get('/api/data', (req, res) => {
  res.json({ message: 'Hello Human!' });
});

app.listen(3000);
```

Attaches `req.botGate` decision to every request and automatically blocks malicious traffic with 403.

## Detect spoofing and attacks

```js
const decision = await botgate({
  method: 'GET',
  url: "/search?q=' UNION SELECT 1, password FROM users --",
  headers: {
    'user-agent': 'Mozilla/5.0'
  }
});

console.log(decision.action);      // 'block'
console.log(decision.isAttack);    // true
console.log(decision.riskScore);   // 2.8 (0-3 scale)
console.log(decision.reasons);     // ['Detected malicious attack payload or exploit attempt']
```

Runs 5 parallel TypeSafe questions (bot probability, attack probability, header spoofing, traffic classification, and risk severity) in a single request.

## Custom policies

```js
const gate = botgate.create({
  policy: {
    attackThreshold: 0.70,
    botThreshold: 0.80,
    challengeThreshold: 0.40,
    riskBlock: 2.0
  },
  onBlock: (decision, req, res) => {
    res.status(403).json({ error: 'Access Denied', details: decision.reasons });
  }
});
```

Control thresholds and actions in your code. The model supplies probabilities; your application owns the policy.

## License

MIT © [Hemanth.HM](https://h3manth.com)
