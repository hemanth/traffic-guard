export type PolicyName = 'balanced' | 'strict' | 'permissive';

export type ActionType = 'allow' | 'challenge' | 'block' | 'tarpit' | 'monitor';

export type TrafficCategory = 'human' | 'good_bot' | 'bad_bot' | 'attack';

export interface NormalizedRequest {
  method: string;
  path: string;
  query: Record<string, string | string[]>;
  headers: Record<string, string>;
  rawHeaders?: string[];
  body?: string | Record<string, unknown> | null;
  ip?: string;
  url?: string;
  cookies?: Record<string, string>;
}

export interface RequestContext {
  missingBrowserHeaders: string[];
  suspiciousSignatures: string[];
  claimsBrowser: boolean;
  isKnownSearchBot: boolean;
  headerOrderAnomaly: boolean;
  shannonEntropy: number;
  rateCount?: number;
  isHoneypot?: boolean;
}

export interface GatePolicy {
  attackThreshold: number;
  botThreshold: number;
  challengeThreshold: number;
  riskBlock: number;
  riskChallenge: number;
  spoofThreshold: number;
  velocityBurstLimit: number; // max requests per 10s window before challenge/tarpit
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
  honeypotPaths?: string[];
  secretKey?: string; // HMAC secret for signed stateless session cookies
  tarpitMs?: number; // Delay in ms for tarpit action (default: 3000)
  enablePoWChallenge?: boolean; // Serve self-contained HashCash challenge (default: true)
  fallback?: 'heuristic' | 'allow' | 'block';
  onBlock?: (decision: BotGateDecision, req: unknown, res: unknown) => void;
  onChallenge?: (decision: BotGateDecision, req: unknown, res: unknown) => void;
  onTarpit?: (decision: BotGateDecision, req: unknown, res: unknown) => void;
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
  shouldTarpit: boolean;
  isBot: boolean;
  isAttack: boolean;
  category: TrafficCategory;
  riskScore: number;
  confidence: number;
  reasons: string[];
  assessment: AssessmentResult;
  durationMs: number;
  setCookieHeader?: string;
  challengeHtml?: string;
  respond?: (res: any) => Promise<boolean> | boolean;
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
      rawHeaders?: string[];
      query?: Record<string, unknown>;
      body?: unknown;
      ip?: string;
      socket?: { remoteAddress?: string };
      cookies?: Record<string, string>;
    };
