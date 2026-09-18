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

export function normalizeRequest(input: RequestInput): {
  request: NormalizedRequest;
  context: RequestContext;
} {
  let method = 'GET';
  let path = '/';
  let query: Record<string, string | string[]> = {};
  const headers: Record<string, string> = {};
  let body: string | Record<string, unknown> | null = null;
  let ip: string | undefined;

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

    body = raw.body ?? null;
    ip = raw.ip || raw.socket?.remoteAddress || headers['x-forwarded-for']?.split(',')[0]?.trim();
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
    if (!headers['sec-ch-ua'] && !userAgent.includes('firefox/')) {
      missingBrowserHeaders.push('sec-ch-ua');
    }
  }

  const suspiciousSignatures: string[] = [];
  for (const tool of KNOWN_ATTACK_TOOLS) {
    if (userAgent.includes(tool)) {
      suspiciousSignatures.push(`known_attack_tool:${tool}`);
    }
  }

  const normalized: NormalizedRequest = {
    method,
    path,
    query,
    headers,
    body,
    ip,
    url: path
  };

  const context: RequestContext = {
    missingBrowserHeaders,
    suspiciousSignatures,
    claimsBrowser,
    isKnownSearchBot
  };

  return { request: normalized, context };
}
