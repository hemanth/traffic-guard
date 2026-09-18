import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import trafficguard, {
  TrafficGuard,
  botgate,
  createPoWChallenge,
  verifyPoW,
  signBotToken,
  verifyBotToken,
  createClientHash
} from '../dist/index.mjs';

describe('traffic-guard Node module', () => {
  it('allows normal human browser traffic', async () => {
    const req = {
      method: 'GET',
      url: '/products/laptop-pro',
      headers: {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
      }
    };

    const decision = await botgate(req);
    assert.equal(decision.action, 'allow');
    assert.equal(decision.shouldBlock, false);
    assert.equal(decision.shouldChallenge, false);
    assert.equal(decision.isAttack, false);
    assert.equal(decision.category, 'human');
    assert.ok(decision.riskScore < 1.0);
  });

  it('blocks SQL injection attack payload', async () => {
    const req = {
      method: 'GET',
      url: "/search?q=' UNION SELECT username, password FROM users --",
      headers: {
        'user-agent': 'Mozilla/5.0'
      }
    };

    const decision = await botgate(req);
    assert.equal(decision.action, 'block');
    assert.equal(decision.shouldBlock, true);
    assert.equal(decision.isAttack, true);
    assert.ok(decision.riskScore >= 2.0);
    assert.ok(decision.reasons.some((r) => r.toLowerCase().includes('attack')));
  });

  it('blocks known penetration testing tools (sqlmap)', async () => {
    const req = {
      method: 'GET',
      url: '/api/v1/users',
      headers: {
        'user-agent': 'sqlmap/1.5#stable (http://sqlmap.org)'
      }
    };

    const decision = await botgate(req);
    assert.equal(decision.action, 'block');
    assert.equal(decision.shouldBlock, true);
    assert.equal(decision.isBot, true);
    assert.equal(decision.category, 'attack');
  });

  it('blocks sensitive path probe (/.env)', async () => {
    const req = {
      method: 'GET',
      url: '/.env',
      headers: {
        'user-agent': 'python-requests/2.31.0'
      }
    };

    const decision = await botgate(req);
    assert.equal(decision.action, 'block');
    assert.equal(decision.shouldBlock, true);
    assert.ok(decision.riskScore >= 2.0);
  });

  it('allows verified good bots (Googlebot) when allowGoodBots is true', async () => {
    const req = {
      method: 'GET',
      url: '/blog/ai-trends',
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
      }
    };

    const decision = await botgate(req, { allowGoodBots: true });
    assert.equal(decision.action, 'allow');
    assert.equal(decision.shouldBlock, false);
    assert.equal(decision.category, 'good_bot');
    assert.ok(decision.riskScore < 0.5);
  });

  it('detects header order anomalies (advanced defense pattern)', async () => {
    // A bot sending User-Agent before Host in rawHeaders
    const req = {
      method: 'GET',
      url: '/api/catalog',
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
        'host': 'example.com'
      },
      rawHeaders: [
        'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
        'Host', 'example.com',
        'Accept', '*/*'
      ]
    };

    const decision = await botgate(req);
    assert.equal(decision.action, 'challenge');
    assert.ok(decision.shouldChallenge);
    assert.ok(decision.reasons.some((r) => r.includes('header sequence')));
  });

  it('immediately blocks honeypot canary URL traps (advanced defense pattern)', async () => {
    const gate = botgate.create({
      honeypotPaths: ['/__bg_trap', '/.canary_spider']
    });

    const decision = await gate.inspect('/__bg_trap');
    assert.equal(decision.action, 'block');
    assert.equal(decision.shouldBlock, true);
    assert.ok(decision.reasons[0].includes('honeypot'));
  });

  it('tarpits high velocity burst requests (advanced defense pattern)', async () => {
    const secret = 'test-secret';
    const clientHash = createClientHash('1.2.3.4', 'Mozilla/5.0');
    // Simulate token with count = 45 (> limit of 40)
    const token = signBotToken({ h: clientHash, c: 45, ws: Date.now() }, secret);

    const gate = botgate.create({
      secretKey: secret,
      policy: 'balanced'
    });

    const req = {
      method: 'GET',
      url: '/feed',
      ip: '1.2.3.4',
      headers: {
        'user-agent': 'Mozilla/5.0',
        'cookie': `__trafficguard=${token}`
      }
    };

    const decision = await gate.inspect(req);
    assert.equal(decision.action, 'tarpit');
    assert.equal(decision.shouldTarpit, true);
    assert.ok(decision.reasons.some((r) => r.includes('velocity')));
  });

  it('generates and verifies cryptographic Proof-of-Work challenge (advanced defense pattern)', () => {
    const secret = 'test-secret';
    const pow = createPoWChallenge(secret, 2); // difficulty = 2 for fast test
    assert.ok(pow.seed);

    // Solve the 2-zero puzzle
    let nonce = 0;
    while (true) {
      const hash = createHash('sha256').update(`${pow.seed}:${nonce}`).digest('hex');
      if (hash.startsWith('00')) break;
      nonce++;
    }

    const isValid = verifyPoW(pow.seed, String(nonce), 2, secret);
    assert.equal(isValid, true);

    const isInvalid = verifyPoW(pow.seed, 'wrong-nonce', 2, secret);
    assert.equal(isInvalid, false);
  });

  it('respects whitelisted paths without overhead', async () => {
    const gate = botgate.create({
      whitelistedPaths: ['/healthz', /^\/public\//]
    });

    const decision1 = await gate.inspect('/healthz');
    assert.equal(decision1.action, 'allow');
    assert.equal(decision1.reasons[0], 'Path whitelisted');
  });

  it('supports Express middleware semantics with challenge endpoint', async () => {
    const middleware = botgate.middleware({ policy: 'strict', tarpitMs: 10 });

    let nextCalled = false;
    const req1: any = {
      method: 'GET',
      url: '/',
      headers: {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36',
        'accept-language': 'en',
        'accept-encoding': 'gzip',
        'sec-ch-ua': '"Chrome";v="120"'
      }
    };
    const res1: any = {
      setHeader: () => {}
    };

    await middleware(req1, res1, () => {
      nextCalled = true;
    });
    assert.equal(nextCalled, true);
    assert.ok(req1.botGate);
    assert.equal(req1.botGate.action, 'allow');
  });
});
