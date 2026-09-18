import { BotGate, TrafficGuard } from './gate.js';
import type { BotGateDecision, BotGateOptions, RequestInput, TrafficDecision, TrafficGuardOptions } from './types.js';

let defaultGuard: TrafficGuard | null = null;

function getDefaultGuard(): TrafficGuard {
  if (!defaultGuard) {
    defaultGuard = new TrafficGuard();
  }
  return defaultGuard;
}

/**
 * Inspects an incoming request and returns a bot/attack defense decision in under 30 µs.
 *
 * @example
 * ```ts
 * import trafficguard from 'traffic-guard';
 *
 * const decision = await trafficguard(req);
 * if (decision.shouldBlock) {
 *   return res.status(403).json({ error: 'Forbidden', reasons: decision.reasons });
 * }
 * ```
 */
async function trafficguard(input: RequestInput, options?: TrafficGuardOptions): Promise<TrafficDecision> {
  if (options) {
    const guard = new TrafficGuard(options);
    return guard.inspect(input);
  }
  return getDefaultGuard().inspect(input);
}

trafficguard.create = (options?: TrafficGuardOptions) => new TrafficGuard(options);

trafficguard.inspect = (input: RequestInput, options?: TrafficGuardOptions) => {
  return trafficguard(input, options);
};

trafficguard.middleware = (options?: TrafficGuardOptions) => {
  const guard = options ? new TrafficGuard(options) : getDefaultGuard();
  return guard.middleware(options);
};

trafficguard.TrafficGuard = TrafficGuard;
trafficguard.BotGate = BotGate;

const botgate = trafficguard;
const trafficGuard = trafficguard;

export { TrafficGuard, BotGate, trafficguard, trafficGuard, botgate };
export { normalizeRequest, checkHeaderOrderAnomaly } from './normalizer.js';
export { DEFAULT_POLICIES, evaluateDecision, resolvePolicy } from './policy.js';
export { createBotGateBattery, heuristicAssessment, calculateShannonEntropy } from './battery.js';
export {
  signBotToken,
  verifyBotToken,
  createPoWChallenge,
  verifyPoW,
  generateChallengeHtml,
  createClientHash
} from './crypto.js';
export type * from './types.js';

export default trafficguard;
