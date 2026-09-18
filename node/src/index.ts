import { BotGate } from './gate.js';
import type { BotGateDecision, BotGateOptions, RequestInput } from './types.js';

let defaultGate: BotGate | null = null;

function getDefaultGate(): BotGate {
  if (!defaultGate) {
    defaultGate = new BotGate();
  }
  return defaultGate;
}

/**
 * Inspects an incoming request and returns a bot/attack detection decision.
 *
 * @example
 * ```ts
 * const gate = await botgate(req);
 * if (gate.shouldBlock) {
 *   return res.status(403).send('Forbidden');
 * }
 * ```
 */
async function botgate(input: RequestInput, options?: BotGateOptions): Promise<BotGateDecision> {
  if (options) {
    const gate = new BotGate(options);
    return gate.inspect(input);
  }
  return getDefaultGate().inspect(input);
}

botgate.create = (options?: BotGateOptions) => new BotGate(options);

botgate.inspect = (input: RequestInput, options?: BotGateOptions) => {
  return botgate(input, options);
};

botgate.middleware = (options?: BotGateOptions) => {
  const gate = options ? new BotGate(options) : getDefaultGate();
  return gate.middleware(options);
};

botgate.BotGate = BotGate;

export { BotGate };
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

export default botgate;
