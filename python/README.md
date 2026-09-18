# bot-gate

AI-powered bot and attack detection gate for web traffic using TypeSafe System One.

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

`botgate(request)` inspects headers, paths, payloads, and client signals against TypeSafe System One. Returns `action`, `should_block`, `risk_score`, and calibrated reasons.

## FastAPI / Starlette middleware

```python
from fastapi import FastAPI
from bot_gate import BotGateMiddleware

app = FastAPI()

app.add_middleware(
    BotGateMiddleware,
    policy="balanced",  # "strict" | "balanced" | "permissive"
    allow_good_bots=True,
    whitelisted_paths=["/healthz", "/docs"],
)

@app.get("/")
def home():
    return {"message": "Hello Human!"}
```

Attaches `request.state.bot_gate` to incoming requests and automatically blocks malicious attacks.

## Sync usage

```python
from bot_gate import botgate

decision = botgate.inspect({
    "method": "GET",
    "url": "/search?q=' UNION SELECT 1, password FROM users --",
    "headers": {"user-agent": "Mozilla/5.0"}
})

print(decision.action)       # "block"
print(decision.is_attack)    # True
print(decision.risk_score)   # 2.8
print(decision.reasons)      # ["Detected malicious attack payload or exploit attempt"]
```

## Custom policies

```python
from bot_gate import BotGate

gate = BotGate(
    policy={
        "attack_threshold": 0.70,
        "bot_threshold": 0.80,
        "challenge_threshold": 0.40,
        "risk_block": 2.0,
    }
)
```

## License

MIT © [Hemanth.HM](https://h3manth.com)
