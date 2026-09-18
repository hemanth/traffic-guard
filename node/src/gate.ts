import { TypeSafeClient } from '@typesafe-ai/sdk';
import { createBotGateBattery, heuristicAssessment } from './battery.js';
import { normalizeRequest } from './normalizer.js';
import { evaluateDecision, resolvePolicy } from './policy.js';
import type {
  AssessmentResult,
  BotGateDecision,
  BotGateOptions,
  RequestInput,
  TrafficCategory
} from './types.js';

export class BotGate {
  private client: TypeSafeClient | null = null;
  private options: BotGateOptions;
  private battery = createBotGateBattery();

  constructor(options: BotGateOptions = {}) {
    this.options = options;
    const apiKey = options.apiKey || process.env.TYPESAFE_API_KEY;
    if (apiKey) {
      this.client = new TypeSafeClient({
        apiKey,
        baseURL: options.endpoint || process.env.TYPESAFE_ENDPOINT,
        timeout: options.timeout || 15000
      });
    }
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

    // Fast-path 3: Localhost pass-through if specifically requested
    if (request.ip === '127.0.0.1' || request.ip === '::1') {
      // unless there's an obvious injection, we let localhost pass if configured
    }

    let assessment: AssessmentResult;

    if (this.client) {
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
            is_known_search_bot: context.isKnownSearchBot
          }
        };

        const response = await this.client.systemOne({
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
        // Fallback to intelligent heuristic assessment
        assessment = heuristicAssessment(request, context);
      }
    } else {
      // Offline / heuristic assessment
      assessment = heuristicAssessment(request, context);
    }

    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
    return evaluateDecision(assessment, policy, opts, durationMs);
  }

  middleware(middlewareOptions: BotGateOptions = {}) {
    const opts = { ...this.options, ...middlewareOptions };

    return async (req: any, res: any, next: (err?: any) => void) => {
      try {
        const decision = await this.inspect(req, opts);
        req.botGate = decision;

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
