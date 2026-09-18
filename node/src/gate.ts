import { createBotGateBattery, heuristicAssessment, loadTypeSafePrimitives } from './battery.js';
import {
  createClientHash,
  createPoWChallenge,
  generateChallengeHtml,
  signBotToken,
  verifyBotToken,
  verifyPoW,
  type BotCookiePayload
} from './crypto.js';
import { normalizeRequest } from './normalizer.js';
import { evaluateDecision, resolvePolicy } from './policy.js';
import type {
  AssessmentResult,
  BotGateDecision,
  BotGateOptions,
  RequestInput,
  TrafficCategory
} from './types.js';

let sdkLoaded = false;
let TypeSafeClientClass: any = null;

async function getTypeSafeClientClass() {
  if (!sdkLoaded) {
    try {
      const sdk = await import('@typesafe-ai/sdk');
      TypeSafeClientClass = sdk.TypeSafeClient;
      await loadTypeSafePrimitives();
    } catch {
      TypeSafeClientClass = null;
    }
    sdkLoaded = true;
  }
  return TypeSafeClientClass;
}

export class BotGate {
  private client: any = null;
  private clientInitAttempted = false;
  private options: BotGateOptions;
  private battery = createBotGateBattery();

  constructor(options: BotGateOptions = {}) {
    this.options = options;
  }

  private async getClient() {
    if (!this.clientInitAttempted) {
      this.clientInitAttempted = true;
      const apiKey = this.options.apiKey || process.env.TYPESAFE_API_KEY;
      if (apiKey) {
        const ClientClass = await getTypeSafeClientClass();
        if (ClientClass) {
          this.client = new ClientClass({
            apiKey,
            baseURL: this.options.endpoint || process.env.TYPESAFE_ENDPOINT,
            timeout: this.options.timeout || 15000
          });
          this.battery = createBotGateBattery();
        }
      }
    }
    return this.client;
  }

  async inspect(input: RequestInput, runtimeOptions: BotGateOptions = {}): Promise<BotGateDecision> {
    const startTime = performance.now();
    const opts = { ...this.options, ...runtimeOptions };
    const policy = resolvePolicy(opts.policy);
    const { request, context } = normalizeRequest(input);

    // Fast-path 1: Path whitelist
    if (opts.whitelistedPaths) {
      for (const pattern of opts.whitelistedPaths) {
        if (typeof pattern === 'string' && request.path === pattern) {
          return this.createAllowedDecision('Path whitelisted', startTime);
        }
        if (pattern instanceof RegExp && pattern.test(request.path)) {
          return this.createAllowedDecision('Path matched whitelist pattern', startTime);
        }
      }
    }

    // Fast-path 2: IP whitelist
    if (opts.whitelistedIps && request.ip && opts.whitelistedIps.includes(request.ip)) {
      return this.createAllowedDecision('Client IP whitelisted', startTime);
    }

    // Fast-path 3: Canary honeypot traps (advanced defense pattern)
    if (opts.honeypotPaths && opts.honeypotPaths.includes(request.path)) {
      context.isHoneypot = true;
    }

    // Fast-path 4: Stateless HMAC Cookie & Velocity Tracking (advanced defense pattern)
    const secret = opts.secretKey || process.env.BOTGATE_SECRET || 'bot-gate-default-secret-key-32b!';
    const userAgent = request.headers['user-agent'] || '';
    const clientHash = createClientHash(request.ip, userAgent);
    const rawCookie = request.cookies?.['__botgate'];
    const now = Date.now();

    let cookiePayload: BotCookiePayload | null = null;
    if (rawCookie) {
      cookiePayload = verifyBotToken(rawCookie, secret);
    }

    // Check if client previously verified a challenge and token is valid
    if (cookiePayload && cookiePayload.h === clientHash && cookiePayload.v && cookiePayload.v > now) {
      // Verified human pass
      return this.createAllowedDecision('Client passed cryptographic verification', startTime);
    }

    // Track request velocity in 10-second sliding window
    let currentCount = 1;
    let windowStart = now;
    if (cookiePayload && cookiePayload.h === clientHash) {
      if (now - cookiePayload.ws < 10_000) {
        currentCount = cookiePayload.c + 1;
        windowStart = cookiePayload.ws;
      }
    }
    context.rateCount = currentCount;

    let assessment: AssessmentResult;
    const client = await this.getClient();

    if (client && !context.isHoneypot) {
      try {
        const state = {
          request: {
            method: request.method,
            path: request.path,
            headers: request.headers,
            query: request.query,
            body: (request.body ?? null) as any,
            ip: (request.ip ?? null) as any
          },
          context: {
            missing_browser_headers: context.missingBrowserHeaders,
            suspicious_signatures: context.suspiciousSignatures,
            claims_browser: context.claimsBrowser,
            is_known_search_bot: context.isKnownSearchBot,
            header_order_anomaly: context.headerOrderAnomaly,
            shannon_entropy: context.shannonEntropy,
            rate_count: context.rateCount
          }
        };

        const response = await client.systemOne({
          model: opts.model || 'jev-latest',
          state: state as any,
          questions: this.battery as any
        });

        const answers = response.answers as any;

        const isBotProb = answers.is_bot?.noul ?? 0.1;
        const isAttackProb = answers.is_attack?.noul ?? 0.05;
        const isSpoofedProb = answers.is_spoofed?.noul ?? 0.05;

        const trafficTypeAnswer = answers.traffic_type;
        const trafficType = (trafficTypeAnswer?.choice as TrafficCategory) || 'human';
        const trafficTypeConfidence = trafficTypeAnswer?.confidence ?? 0.8;
        const trafficTypeDist = trafficTypeAnswer?.probabilities ?? {};

        const riskAnswer = answers.risk_level;
        const riskScore = riskAnswer?.score ?? 0;
        const riskConfidence = riskAnswer?.confidence ?? 0.8;
        const riskDist = riskAnswer?.probabilities ?? {};

        assessment = {
          isBotProbability: isBotProb,
          isAttackProbability: isAttackProb,
          isSpoofedProbability: isSpoofedProb,
          trafficType,
          trafficTypeConfidence,
          trafficTypeDistribution: trafficTypeDist,
          riskScore,
          riskConfidence,
          riskLevelDistribution: riskDist
        };
      } catch (err) {
        if (opts.fallback === 'block') {
          return this.createBlockedDecision('TypeSafe API unavailable (fallback: block)', startTime);
        }
        if (opts.fallback === 'allow') {
          return this.createAllowedDecision('TypeSafe API unavailable (fallback: allow)', startTime);
        }
        assessment = heuristicAssessment(request, context);
      }
    } else {
      assessment = heuristicAssessment(request, context);
    }

    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
    const decision = evaluateDecision(assessment, policy, opts, durationMs, context);

    // Prepare updated stateless cookie
    const updatedPayload: BotCookiePayload = {
      h: clientHash,
      c: currentCount,
      ws: windowStart
    };
    const newToken = signBotToken(updatedPayload, secret);
    decision.setCookieHeader = `__botgate=${newToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`;

    // If challenged, attach PoW challenge payload
    if (decision.shouldChallenge) {
      const pow = createPoWChallenge(secret, 4);
      decision.challengeHtml = generateChallengeHtml(pow.seed, pow.difficulty, request.url || '/');
    }

    return decision;
  }

  middleware(middlewareOptions: BotGateOptions = {}) {
    const opts = { ...this.options, ...middlewareOptions };
    const secret = opts.secretKey || process.env.BOTGATE_SECRET || 'bot-gate-default-secret-key-32b!';

    return async (req: any, res: any, next: (err?: any) => void) => {
      try {
        // Handle PoW Challenge verification endpoint
        if (req.method === 'POST' && (req.url === '/__botgate/verify' || req.path === '/__botgate/verify')) {
          let body = req.body;
          if (typeof body === 'string') {
            try { body = JSON.parse(body); } catch {}
          }
          const { seed, nonce, isAutomated, returnUrl } = body || {};
          const isValid = !isAutomated && verifyPoW(seed, nonce, 1, secret);

          if (isValid) {
            const userAgent = req.headers['user-agent'] || '';
            const ip = req.ip || req.socket?.remoteAddress || '';
            const clientHash = createClientHash(ip, userAgent);
            // Grant 30 minutes verification
            const token = signBotToken({ h: clientHash, c: 1, ws: Date.now(), v: Date.now() + 1800_000 }, secret);
            res.setHeader('Set-Cookie', `__botgate=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800`);
            return res.status(200).json({ status: 'ok', redirect: returnUrl || '/' });
          } else {
            return res.status(403).json({ error: 'Verification failed' });
          }
        }

        const decision = await this.inspect(req, opts);
        req.botGate = decision;

        if (decision.setCookieHeader) {
          res.setHeader('Set-Cookie', decision.setCookieHeader);
        }

        if (decision.shouldTarpit) {
          if (opts.onTarpit) {
            return opts.onTarpit(decision, req, res);
          }
          const delay = opts.tarpitMs || 3000;
          await new Promise((r) => setTimeout(r, delay));
          return res.status(429).json({
            error: 'Too Many Requests',
            message: 'Velocity exceeded threshold',
            action: decision.action,
            reasons: decision.reasons
          });
        }

        if (decision.shouldBlock) {
          if (opts.onBlock) {
            return opts.onBlock(decision, req, res);
          }
          return res.status(403).json({
            error: 'Forbidden',
            message: 'Access blocked by BotGate security policy',
            action: decision.action,
            reasons: decision.reasons,
            category: decision.category,
            riskScore: decision.riskScore
          });
        }

        if (decision.shouldChallenge) {
          if (opts.onChallenge) {
            return opts.onChallenge(decision, req, res);
          }
          if (opts.enablePoWChallenge !== false && decision.challengeHtml) {
            res.status(428);
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            return res.end(decision.challengeHtml);
          }
          res.setHeader('X-BotGate-Action', 'challenge');
          res.setHeader('X-BotGate-Risk', decision.riskScore.toString());
        } else {
          res.setHeader('X-BotGate-Action', 'allow');
        }

        next();
      } catch (err) {
        next(err);
      }
    };
  }

  private createAllowedDecision(reason: string, startTime: number): BotGateDecision {
    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
    return {
      action: 'allow',
      shouldBlock: false,
      shouldChallenge: false,
      shouldTarpit: false,
      isBot: false,
      isAttack: false,
      category: 'human',
      riskScore: 0,
      confidence: 1.0,
      reasons: [reason],
      assessment: {
        isBotProbability: 0,
        isAttackProbability: 0,
        isSpoofedProbability: 0,
        trafficType: 'human',
        trafficTypeConfidence: 1.0,
        trafficTypeDistribution: { human: 1.0 },
        riskScore: 0,
        riskConfidence: 1.0,
        riskLevelDistribution: { '0': 1.0 }
      },
      durationMs,
      respond: () => false
    };
  }

  private createBlockedDecision(reason: string, startTime: number): BotGateDecision {
    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
    return {
      action: 'block',
      shouldBlock: true,
      shouldChallenge: false,
      shouldTarpit: false,
      isBot: true,
      isAttack: true,
      category: 'attack',
      riskScore: 3.0,
      confidence: 1.0,
      reasons: [reason],
      assessment: {
        isBotProbability: 1.0,
        isAttackProbability: 1.0,
        isSpoofedProbability: 1.0,
        trafficType: 'attack',
        trafficTypeConfidence: 1.0,
        trafficTypeDistribution: { attack: 1.0 },
        riskScore: 3.0,
        riskConfidence: 1.0,
        riskLevelDistribution: { '3': 1.0 }
      },
      durationMs,
      respond: (res: any) => {
        if (res && typeof res.status === 'function') {
          res.status(403).json({ error: 'Forbidden', message: reason });
          return true;
        }
        return false;
      }
    };
  }
}
