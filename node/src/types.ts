export type PolicyName = 'balanced' | 'strict' | 'permissive';

export type ActionType = 'allow' | 'challenge' | 'block' | 'monitor';

export type TrafficCategory = 'human' | 'good_bot' | 'bad_bot' | 'attack';

export interface NormalizedRequest {
  method: string;
  path: string;
  query: Record<string, string | string[]>;
  headers: Record<string, string>;
  body?: string | Record<string, unknown> | null;
  ip?: string;
  url?: string;
}

export interface RequestContext {
  missingBrowserHeaders: string[];
  suspiciousSignatures: string[];
  claimsBrowser: boolean;
  isKnownSearchBot: boolean;
  rateCount?: number;
}

export interface GatePolicy {
  attackThreshold: number;
  botThreshold: number;
  challengeThreshold: number;
  riskBlock: number;
  riskChallenge: number;
  spoofThreshold: number;
}

export interface BotGateOptions {
  policy?: PolicyName | Partial<GatePolicy>;
  apiKey?: string;
  endpoint?: string;
  model?: string;
  timeout?: number;
  allowGoodBots?: boolean;
  whitelistedPaths?: (string | RegExp)[];
  whitelistedIps?: string[];
  fallback?: 'heuristic' | 'allow' | 'block';
  onBlock?: (decision: BotGateDecision, req: unknown, res: unknown) => void;
  onChallenge?: (decision: BotGateDecision, req: unknown, res: unknown) => void;
}

export interface AssessmentResult {
  isBotProbability: number;
  isAttackProbability: number;
  isSpoofedProbability: number;
  trafficType: TrafficCategory;
  trafficTypeConfidence: number;
  trafficTypeDistribution: Record<string, number>;
  riskScore: number;
  riskConfidence: number;
  riskLevelDistribution: Record<string, number>;
}

export interface BotGateDecision {
  action: ActionType;
  shouldBlock: boolean;
  shouldChallenge: boolean;
  isBot: boolean;
  isAttack: boolean;
  category: TrafficCategory;
  riskScore: number;
  confidence: number;
  reasons: string[];
  assessment: AssessmentResult;
  durationMs: number;
  respond?: (res: any) => boolean;
}

export type RequestInput =
  | string
  | NormalizedRequest
  | {
      method?: string;
      url?: string;
      path?: string;
      originalUrl?: string;
      headers?: Record<string, string | string[] | undefined>;
      query?: Record<string, unknown>;
      body?: unknown;
      ip?: string;
      socket?: { remoteAddress?: string };
    };
