import http from 'node:http';
import botgate from '../node/dist/index.mjs';

const gate = botgate.create({
  policy: 'balanced',
  allowGoodBots: true,
  whitelistedPaths: ['/healthz', '/favicon.ico']
});

const server = http.createServer(async (req, res) => {
  const decision = await gate.inspect(req);

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-BotGate-Action', decision.action);
  res.setHeader('X-BotGate-Risk', decision.riskScore.toString());

  if (decision.shouldBlock) {
    res.statusCode = 403;
    res.end(
      JSON.stringify(
        {
          status: 'BLOCKED',
          action: decision.action,
          reasons: decision.reasons,
          category: decision.category,
          riskScore: decision.riskScore,
          assessment: decision.assessment
        },
        null,
        2
      )
    );
    return;
  }

  if (decision.shouldChallenge) {
    res.statusCode = 428;
    res.end(
      JSON.stringify(
        {
          status: 'CHALLENGE_REQUIRED',
          action: decision.action,
          reasons: decision.reasons,
          riskScore: decision.riskScore
        },
        null,
        2
      )
    );
    return;
  }

  res.statusCode = 200;
  res.end(
    JSON.stringify(
      {
        status: 'ALLOWED',
        message: 'Welcome, legitimate traffic!',
        category: decision.category,
        riskScore: decision.riskScore,
        latencyMs: decision.durationMs
      },
      null,
      2
    )
  );
});

const PORT = 3000;
if (process.env.RUN_SERVER) {
  server.listen(PORT, () => {
    console.log(`BotGate server running on http://localhost:${PORT}`);
  });
} else {
  // Direct simulation run
  console.log('--- Simulating Incoming Traffic Scenarios ---\n');

  const scenarios = [
    {
      name: 'Normal Human Visitor',
      req: {
        method: 'GET',
        url: '/pricing',
        headers: {
          'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/122.0.0.0 Safari/537.36',
          'accept': 'text/html,application/xhtml+xml',
          'accept-language': 'en-US,en;q=0.9',
          'accept-encoding': 'gzip, deflate, br',
          'sec-ch-ua': '"Chromium";v="122"'
        }
      }
    },
    {
      name: 'Googlebot Crawler',
      req: {
        method: 'GET',
        url: '/articles/ai-advances',
        headers: {
          'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        }
      }
    },
    {
      name: 'Automated CLI Scraper',
      req: {
        method: 'GET',
        url: '/api/v1/customers',
        headers: {
          'user-agent': 'python-requests/2.31.0'
        }
      }
    },
    {
      name: 'SQL Injection Exploit Attack',
      req: {
        method: 'POST',
        url: '/login',
        headers: {
          'user-agent': 'Mozilla/5.0'
        },
        body: "username=admin' OR 1=1 --&password=test"
      }
    },
    {
      name: 'Sensitive File Probe Attack',
      req: {
        method: 'GET',
        url: '/.env',
        headers: {
          'user-agent': 'curl/8.4.0'
        }
      }
    }
  ];

  for (const s of scenarios) {
    const decision = await gate.inspect(s.req);
    const badge = decision.shouldBlock ? '[BLOCKED]' : decision.shouldChallenge ? '[CHALLENGE]' : '[ALLOWED]';
    console.log(`${badge.padEnd(12)} ${s.name}`);
    console.log(`  Action:     ${decision.action}`);
    console.log(`  Category:   ${decision.category}`);
    console.log(`  Risk Score: ${decision.riskScore} / 3.0`);
    console.log(`  Reasons:    ${decision.reasons.join('; ')}\n`);
  }
}
