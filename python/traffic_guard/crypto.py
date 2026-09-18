"""Zero-dependency cryptographic helpers for stateless tokens and PoW challenges."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

DEFAULT_SECRET = "traffic-guard-default-secret-key-32b!"


@dataclass
class BotCookiePayload:
    h: str  # client signature hash
    c: int  # request count in window
    ws: float  # window start timestamp
    v: float | None = None  # verified until timestamp


def create_client_hash(ip: str = "", user_agent: str = "") -> str:
    raw = f"{ip}::{user_agent.lower()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def sign_bot_token(payload: dict[str, Any], secret: str = DEFAULT_SECRET) -> str:
    json_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")
    sig = hmac.new(secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256).hexdigest()[:32]
    return f"{b64_payload}.{sig}"


def verify_bot_token(token: str, secret: str = DEFAULT_SECRET) -> BotCookiePayload | None:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        b64_payload, sig = parts
        expected_sig = hmac.new(
            secret.encode("utf-8"), b64_payload.encode("ascii"), hashlib.sha256
        ).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected_sig):
            return None

        # Add padding back if necessary
        padding = 4 - (len(b64_payload) % 4)
        if padding != 4:
            b64_payload += "=" * padding

        json_bytes = base64.urlsafe_b64decode(b64_payload)
        data = json.loads(json_bytes.decode("utf-8"))
        return BotCookiePayload(
            h=data.get("h", ""),
            c=int(data.get("c", 1)),
            ws=float(data.get("ws", time.time())),
            v=data.get("v"),
        )
    except Exception:
        return None


def parse_cookies(cookie_header: str = "") -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def create_pow_challenge(secret: str = DEFAULT_SECRET, difficulty: int = 4) -> tuple[str, int]:
    ts = int(time.time() * 1000)
    rand = secrets.token_hex(4)
    payload = f"{ts}:{rand}:{difficulty}"
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    seed = f"{payload}:{sig}"
    return seed, difficulty


def verify_pow(
    seed: str,
    nonce: str,
    expected_difficulty: int | None = None,
    secret: str = DEFAULT_SECRET,
) -> bool:
    try:
        parts = seed.split(":")
        if len(parts) != 4:
            return False
        ts_str, rand, diff_str, sig = parts
        payload = f"{ts_str}:{rand}:{diff_str}"
        expected_sig = hmac.new(
            secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected_sig):
            return False

        # Reject puzzles older than 3 minutes
        ts = int(ts_str)
        if (time.time() * 1000) - ts > 180_000:
            return False

        difficulty = int(diff_str)
        if expected_difficulty is not None and difficulty < expected_difficulty:
            return False

        candidate = f"{seed}:{nonce}".encode("utf-8")
        h = hashlib.sha256(candidate).hexdigest()
        return h.startswith("0" * difficulty)
    except Exception:
        return False


def generate_challenge_html(seed: str, difficulty: int, return_url: str = "/") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verifying Connection...</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #fafafa; color: #222; }}
    .card {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 32px; max-width: 400px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
    .spinner {{ border: 3px solid #f3f3f3; border-top: 3px solid #111; border-radius: 50%; width: 32px; height: 32px; animation: spin 0.8s linear infinite; margin: 20px auto; }}
    @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
    h2 {{ font-size: 18px; margin-bottom: 8px; }}
    p {{ font-size: 14px; color: #666; margin: 0; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>Verifying Connection</h2>
    <p>Please wait a moment while your browser verifies your session...</p>
    <div class="spinner"></div>
  </div>
  <script>
    (async function() {{
      const seed = "{seed}";
      const difficulty = {difficulty};
      const returnUrl = "{return_url}";
      const targetPrefix = "0".repeat(difficulty);
      const isAutomated = !!(navigator.webdriver || window._phantom || window.__nightmare || !window.chrome);

      async function sha256(message) {{
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      }}

      let nonce = 0;
      while (true) {{
        const hash = await sha256(seed + ":" + nonce);
        if (hash.startsWith(targetPrefix)) break;
        nonce++;
        if (nonce > 500000) break;
      }}

      try {{
        const res = await fetch("/__trafficguard/verify", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ seed, nonce: String(nonce), isAutomated, returnUrl }})
        }});
        if (res.ok) {{
          window.location.href = returnUrl;
        }} else {{
          document.querySelector("p").innerText = "Verification challenge failed.";
        }}
      }} catch (e) {{
        window.location.reload();
      }}
    }})();
  </script>
</body>
</html>"""
