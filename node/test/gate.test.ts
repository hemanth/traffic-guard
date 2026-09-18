import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import botgate, { BotGate, normalizeRequest, evaluateDecision } from '../dist/index.mjs';

describe('bot-gate Node module', () => {
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

  it('challenges or blocks unapproved automated scrapers', async () => {
    const req = {
      method: 'GET',
      url: '/catalog/all-items',
      headers: {
        'user-agent': 'python-requests/2.28.1'
      }
    };

    const decision = await botgate(req);
    assert.ok(decision.action === 'challenge' || decision.action === 'block');
    assert.equal(decision.isBot, true);
  });

  it('detects header spoofing when browser claims chrome but omits standard headers', async () => {
    const req = {
      method: 'GET',
      url: '/dashboard',
      headers: {
        // Claims Chrome on Windows, but missing accept-language, accept-encoding, and sec-ch-ua
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
      }
    };

    const decision = await botgate(req);
    assert.ok(decision.assessment.isSpoofedProbability >= 0.5);
    assert.ok(decision.shouldChallenge || decision.shouldBlock);
  });

  it('respects whitelisted paths without overhead', async () => {
    const gate = botgate.create({
      whitelistedPaths: ['/healthz', /^\/public\//]
    });

    const decision1 = await gate.inspect('/healthz');
    assert.equal(decision1.action, 'allow');
    assert.equal(decision1.reasons[0], 'Path whitelisted');

    const decision2 = await gate.inspect('/public/logo.png');
    assert.equal(decision2.action, 'allow');
    assert.equal(decision2.reasons[0], 'Path matched whitelist pattern');
  });

  it('supports Express middleware semantics', async () => {
    const middleware = botgate.middleware({ policy: 'strict' });

    // Test legitimate request passes to next()
    let nextCalled = false;
    const req1: any = {
      method: 'GET',
      url: '/',
      headers: {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
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

    // Test attack request is blocked with 403
    let nextCalledAttack = false;
    let statusCode = 0;
    let jsonBody: any = null;

    const req2: any = {
      method: 'GET',
      url: '/.env',
      headers: { 'user-agent': 'curl/7.88.1' }
    };
    const res2: any = {
      status: (code: number) => {
        statusCode = code;
        return {
          json: (body: any) => {
            jsonBody = body;
          }
        };
      },
      setHeader: () => {}
    };

    await middleware(req2, res2, () => {
      nextCalledAttack = true;
    });

    assert.equal(nextCalledAttack, false);
    assert.equal(statusCode, 403);
    assert.equal(jsonBody?.error, 'Forbidden');
    assert.equal(jsonBody?.action, 'block');
  });
});
