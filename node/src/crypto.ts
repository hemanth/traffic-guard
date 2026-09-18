import { createHash, createHmac, randomBytes } from 'node:crypto';

const DEFAULT_SECRET = 'traffic-guard-default-secret-key-32b!';

export interface BotCookiePayload {
  h: string; // client signature hash (ip + ua)
  c: number; // request count in window
  ws: number; // window start timestamp
  v?: number; // verified until timestamp
}

export function createClientHash(ip: string = '', userAgent: string = ''): string {
  return createHash('sha256')
    .update(`${ip}::${userAgent.toLowerCase()}`)
    .digest('hex')
    .slice(0, 16);
}

export function signBotToken(payload: BotCookiePayload, secret: string = DEFAULT_SECRET): string {
  const jsonStr = JSON.stringify(payload);
  const b64Payload = Buffer.from(jsonStr, 'utf8').toString('base64url');
  const signature = createHmac('sha256', secret).update(b64Payload).digest('base64url');
  return `${b64Payload}.${signature}`;
}

export function verifyBotToken(token: string, secret: string = DEFAULT_SECRET): BotCookiePayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [b64Payload, signature] = parts;
    const expectedSig = createHmac('sha256', secret).update(b64Payload).digest('base64url');
    if (signature !== expectedSig) return null;
    const jsonStr = Buffer.from(b64Payload, 'base64url').toString('utf8');
    return JSON.parse(jsonStr) as BotCookiePayload;
  } catch {
    return null;
  }
}

export function parseCookies(cookieHeader: string = ''): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      cookies[key] = val;
    }
  }
  return cookies;
}

export function createPoWChallenge(secret: string = DEFAULT_SECRET, difficulty: number = 4): { seed: string; difficulty: number } {
  const ts = Date.now();
  const rand = randomBytes(8).toString('hex');
  const payload = `${ts}:${rand}:${difficulty}`;
  const sig = createHmac('sha256', secret).update(payload).digest('hex').slice(0, 16);
  const seed = `${payload}:${sig}`;
  return { seed, difficulty };
}

export function verifyPoW(seed: string, nonce: string, minDifficulty: number = 1, secret: string = DEFAULT_SECRET): boolean {
  try {
    const parts = seed.split(':');
    if (parts.length !== 4) return false;
    const [tsStr, rand, diffStr, sig] = parts;
    const payload = `${tsStr}:${rand}:${diffStr}`;
    const expectedSig = createHmac('sha256', secret).update(payload).digest('hex').slice(0, 16);
    if (sig !== expectedSig) return false;

    // Reject puzzles older than 3 minutes
    const ts = parseInt(tsStr, 10);
    if (Date.now() - ts > 180_000) return false;

    const diff = parseInt(diffStr, 10);
    if (diff < minDifficulty) return false;

    // Check proof-of-work
    const hash = createHash('sha256').update(`${seed}:${nonce}`).digest('hex');
    return hash.startsWith('0'.repeat(diff));
  } catch {
    return false;
  }
}

export function generateChallengeHtml(seed: string, difficulty: number, returnUrl: string = '/'): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verifying Connection...</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #fafafa; color: #222; }
    .card { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 32px; max-width: 400px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
    .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #111; border-radius: 50%; width: 32px; height: 32px; animation: spin 0.8s linear infinite; margin: 20px auto; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    h2 { font-size: 18px; margin-bottom: 8px; }
    p { font-size: 14px; color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Verifying Connection</h2>
    <p>Please wait a moment while your browser verifies your session...</p>
    <div class="spinner"></div>
  </div>
  <script>
    (async function() {
      const seed = "${seed}";
      const difficulty = ${difficulty};
      const returnUrl = "${returnUrl}";
      const targetPrefix = "0".repeat(difficulty);

      // Automated browser checks
      const isAutomated = !!(navigator.webdriver || window._phantom || window.__nightmare || !window.chrome);

      async function sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      }

      let nonce = 0;
      while (true) {
        const hash = await sha256(seed + ":" + nonce);
        if (hash.startsWith(targetPrefix)) break;
        nonce++;
        if (nonce > 500000) break;
      }

      try {
        const res = await fetch("/__trafficguard/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ seed, nonce: String(nonce), isAutomated, returnUrl })
        });
        if (res.ok) {
          window.location.href = returnUrl;
        } else {
          document.querySelector("p").innerText = "Verification challenge failed.";
        }
      } catch (e) {
        window.location.reload();
      }
    })();
  </script>
</body>
</html>`;
}
