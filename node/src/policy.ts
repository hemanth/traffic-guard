import type {
  ActionType,
  AssessmentResult,
  BotGateDecision,
  GatePolicy,
  PolicyName,
  BotGateOptions
} from './types.js';

export const DEFAULT_POLICIES: Record<PolicyName, GatePolicy> = {
  balanced: {
    attackThreshold: 0.75,
    botThreshold: 0.85,
    challengeThreshold: 0.50,
    riskBlock: 2.2,
    riskChallenge: 1.4,
    spoofThreshold: 0.60
  },
  strict: {
    attackThreshold: 0.60,
    botThreshold: 0.70,
    challengeThreshold: 0.35,
    riskBlock: 1.8,
    riskChallenge: 1.0,
    spoofThreshold: 0.40
  },
  permissive: {
    attackThreshold: 0.88,
    botThreshold: 0.92,
    challengeThreshold: 0.70,
    riskBlock: 2.6,
    riskChallenge: 2.0,
    spoofThreshold: 0.75
  }
};

export function resolvePolicy(policy?: PolicyName | Partial<GatePolicy>): GatePolicy {
  if (typeof policy === 'string') {
    return DEFAULT_POLICIES[policy] || DEFAULT_POLICIES.balanced;
  }
  if (typeof policy === 'object' && policy !== null) {
    return {
      ...DEFAULT_POLICIES.balanced,
      ...policy
    };
  }
  return DEFAULT_POLICIES.balanced;
}

export function evaluateDecision(
  assessment: AssessmentResult,
  policy: GatePolicy,
  options: BotGateOptions,
  durationMs: number
): BotGateDecision {
  const allowGoodBots = options.allowGoodBots !== false;
  const reasons: string[] = [];

  // Check good bot exception
  if (allowGoodBots && assessment.trafficType === 'good_bot' && assessment.isAttackProbability < 0.4) {
    return {
      action: 'allow',
      shouldBlock: false,
      shouldChallenge: false,
      isBot: true,
      isAttack: false,
      category: 'good_bot',
      riskScore: assessment.riskScore,
      confidence: assessment.trafficTypeConfidence,
      reasons: ['Verified legitimate crawler allowed by policy'],
      assessment,
      durationMs
    };
  }

  let action: ActionType = 'allow';

  // 1. Attack evaluation (highest priority)
  if (assessment.isAttackProbability >= policy.attackThreshold) {
    action = 'block';
    reasons.push(
      `Detected malicious attack payload or exploit attempt (probability: ${Math.round(assessment.isAttackProbability * 100)}%)`
    );
  }

  // 2. Risk level evaluation
  if (assessment.riskScore >= policy.riskBlock) {
    action = 'block';
    reasons.push(`High risk severity score (${assessment.riskScore.toFixed(2)} >= ${policy.riskBlock})`);
  } else if (assessment.riskScore >= policy.riskChallenge && action !== 'block') {
    action = 'challenge';
    reasons.push(`Elevated risk severity score (${assessment.riskScore.toFixed(2)} >= ${policy.riskChallenge})`);
  }

  // 3. Bad bot evaluation
  if (assessment.isBotProbability >= policy.botThreshold && assessment.trafficType === 'bad_bot') {
    action = 'block';
    reasons.push(
      `Unapproved automated bot/scraper detected (probability: ${Math.round(assessment.isBotProbability * 100)}%)`
    );
  } else if (assessment.isBotProbability >= policy.challengeThreshold && action === 'allow') {
    action = 'challenge';
    reasons.push(
      `Possible automated traffic requiring verification (probability: ${Math.round(assessment.isBotProbability * 100)}%)`
    );
  }

  // 4. Header spoofing evaluation
  if (assessment.isSpoofedProbability >= policy.spoofThreshold && action === 'allow') {
    action = 'challenge';
    reasons.push(
      `Suspicious header inconsistency or impersonation detected (probability: ${Math.round(assessment.isSpoofedProbability * 100)}%)`
    );
  }

  if (action === 'allow' && reasons.length === 0) {
    reasons.push('Traffic matches expected legitimate profile');
  }

  const shouldBlock = action === 'block';
  const shouldChallenge = action === 'challenge';
  const isBot = assessment.isBotProbability >= 0.5;
  const isAttack = assessment.isAttackProbability >= 0.5;

  const decision: BotGateDecision = {
    action,
    shouldBlock,
    shouldChallenge,
    isBot,
    isAttack,
    category: assessment.trafficType,
    riskScore: assessment.riskScore,
    confidence: assessment.trafficTypeConfidence,
    reasons,
    assessment,
    durationMs,
    respond(res: any): boolean {
      if (!res || typeof res.status !== 'function') return false;
      if (shouldBlock) {
        if (options.onBlock) {
          options.onBlock(decision, null, res);
        } else {
          res.status(403).json({
            error: 'Forbidden',
            message: 'Access blocked by BotGate security policy',
            reasons: decision.reasons
          });
        }
        return true;
      }
      if (shouldChallenge) {
        if (options.onChallenge) {
          options.onChallenge(decision, null, res);
        } else {
          res.status(428).json({
            error: 'Precondition Required',
            message: 'Traffic verification or challenge required',
            reasons: decision.reasons
          });
        }
        return true;
      }
      return false;
    }
  };

  return decision;
}
