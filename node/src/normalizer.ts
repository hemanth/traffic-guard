import { calculateShannonEntropy } from './battery.js';
import { parseCookies } from './crypto.js';
import type { NormalizedRequest, RequestContext, RequestInput } from './types.js';

const KNOWN_GOOD_BOTS = [
  'googlebot',
  'bingbot',
  'yandexbot',
  'duckduckbot',
  'slurp',
  'baiduspider',
  'facebookexternalhit',
  'twitterbot',
  'linkedinbot',
  'embedly',
  'quora link preview',
  'showyoubot',
  'outbrain',
  'pinterest',
  'slackbot',
  'vkshare',
  'w3c_validator',
  'uptime'
];

const KNOWN_ATTACK_TOOLS = [
  'sqlmap',
  'nikto',
  'nmap',
  'masscan',
  'acunetix',
  'dirbuster',
  'gobuster',
  'wfuzz',
  'burpcollaborator',
  'hydra',
  'havij'
];

export function checkHeaderOrderAnomaly(rawHeaders: string[] | undefined, userAgent: string): boolean {
  if (!rawHeaders || rawHeaders.length < 6) return false;

  const order: string[] = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    order.push(rawHeaders[i].toLowerCase());
  }

  const ua = userAgent.toLowerCase();
  const claimsChromium = ua.includes('chrome/') || ua.includes('edg/');
  const hostIdx = order.indexOf('host');
  const uaIdx = order.indexOf('user-agent');
  const secChUaIdx = order.indexOf('sec-ch-ua');

  // Anomaly 1: User-Agent sent BEFORE Host (common in scripts like python-requests or manual curl)
  if (uaIdx !== -1 && hostIdx !== -1 && uaIdx < hostIdx) {
    return true;
  }

  // Anomaly 2: Claims Chromium, but sec-ch-ua is placed at the end after accept-encoding/language
  if (claimsChromium && secChUaIdx !== -1 && uaIdx !== -1) {
    // In real Chromium, sec-ch-ua precedes or immediately neighbors User-Agent
    const acceptEncIdx = order.indexOf('accept-encoding');
    if (acceptEncIdx !== -1 && secChUaIdx > acceptEncIdx + 2) {
      return true;
    }
  }

  return false;
}

export function normalizeRequest(input: RequestInput): {
  request: NormalizedRequest;
  context: RequestContext;
} {
  let method = 'GET';
  let path = '/';
  let query: Record<string, string | string[]> = {};
  const headers: Record<string, string> = {};
  let rawHeaders: string[] | undefined;
  let body: string | Record<string, unknown> | null = null;
  let ip: string | undefined;
  let cookies: Record<string, string> = {};

  if (typeof input === 'string') {
    try {
      const parsed = new URL(input, 'http://localhost');
      path = parsed.pathname;
      parsed.searchParams.forEach((v, k) => {
        query[k] = v;
      });
    } catch {
      path = input;
    }
  } else if (typeof input === 'object' && input !== null) {
    const raw = input as any;
    method = (raw.method || 'GET').toUpperCase();

    const rawUrl = raw.url || raw.originalUrl || raw.path || '/';
    try {
      const parsed = new URL(rawUrl, 'http://localhost');
      path = parsed.pathname;
      parsed.searchParams.forEach((v, k) => {
        query[k] = v;
      });
    } catch {
      path = typeof rawUrl === 'string' ? rawUrl : '/';
    }

    if (raw.query && typeof raw.query === 'object') {
      query = { ...query, ...raw.query };
    }

    if (raw.headers && typeof raw.headers === 'object') {
      for (const [k, v] of Object.entries(raw.headers)) {
        if (typeof v === 'string') {
          headers[k.toLowerCase()] = v;
        } else if (Array.isArray(v)) {
          headers[k.toLowerCase()] = v.join(', ');
        }
      }
    }

    rawHeaders = raw.rawHeaders;
    body = raw.body ?? null;
    ip = raw.ip || raw.socket?.remoteAddress || headers['x-forwarded-for']?.split(',')[0]?.trim();
    cookies = raw.cookies || parseCookies(headers['cookie']);
  }

  const userAgent = (headers['user-agent'] || '').toLowerCase();
  const claimsBrowser =
    userAgent.includes('mozilla/') &&
    (userAgent.includes('chrome/') ||
      userAgent.includes('safari/') ||
      userAgent.includes('firefox/') ||
      userAgent.includes('edg/'));

  const isKnownSearchBot = KNOWN_GOOD_BOTS.some((bot) => userAgent.includes(bot));

  const missingBrowserHeaders: string[] = [];
  if (claimsBrowser && !isKnownSearchBot) {
    if (!headers['accept-language']) missingBrowserHeaders.push('accept-language');
    if (!headers['accept-encoding']) missingBrowserHeaders.push('accept-encoding');
    const isChromium = userAgent.includes('chrome/') || userAgent.includes('edg/');
    if (isChromium && !headers['sec-ch-ua']) {
      missingBrowserHeaders.push('sec-ch-ua');
    }
  }

  const suspiciousSignatures: string[] = [];
  for (const tool of KNOWN_ATTACK_TOOLS) {
    if (userAgent.includes(tool)) {
      suspiciousSignatures.push(`known_attack_tool:${tool}`);
    }
  }

  const headerOrderAnomaly = checkHeaderOrderAnomaly(rawHeaders, userAgent);
  const targetForEntropy = path + ' ' + JSON.stringify(query);
  const shannonEntropy = calculateShannonEntropy(targetForEntropy);

  const normalized: NormalizedRequest = {
    method,
    path,
    query,
    headers,
    rawHeaders,
    body,
    ip,
    url: path,
    cookies
  };

  const context: RequestContext = {
    missingBrowserHeaders,
    suspiciousSignatures,
    claimsBrowser,
    isKnownSearchBot,
    headerOrderAnomaly,
    shannonEntropy
  };

  return { request: normalized, context };
}
