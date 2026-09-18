"""Zero-dependency standard library unittest suite."""

import unittest
from bot_gate import BotGate, botgate


class TestBotGate(unittest.TestCase):
    def setUp(self):
        self.gate = BotGate(allow_good_bots=True, whitelisted_paths=["/healthz"])

    def test_human_traffic_allowed(self):
        req = {
            "method": "GET",
            "url": "/products",
            "headers": {
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0.0.0 Safari/537.36",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept-language": "en-US,en;q=0.9",
                "accept-encoding": "gzip, deflate, br",
                "sec-ch-ua": '"Chromium";v="124"',
            },
        }
        decision = self.gate.inspect_sync(req)
        self.assertEqual(decision.action, "allow")
        self.assertFalse(decision.should_block)
        self.assertEqual(decision.category, "human")

    def test_sqli_attack_blocked(self):
        req = {
            "method": "GET",
            "url": "/search?q=1' UNION SELECT username,password FROM users--",
            "headers": {"user-agent": "Mozilla/5.0"},
        }
        decision = self.gate.inspect_sync(req)
        self.assertEqual(decision.action, "block")
        self.assertTrue(decision.should_block)
        self.assertTrue(decision.is_attack)
        self.assertGreaterEqual(decision.risk_score, 2.0)

    def test_sqlmap_scanner_blocked(self):
        req = {
            "method": "GET",
            "url": "/users",
            "headers": {"user-agent": "sqlmap/1.7#stable"},
        }
        decision = self.gate.inspect_sync(req)
        self.assertEqual(decision.action, "block")
        self.assertTrue(decision.should_block)
        self.assertEqual(decision.category, "attack")

    def test_sensitive_env_probe_blocked(self):
        req = {
            "method": "GET",
            "url": "/.env",
            "headers": {"user-agent": "curl/8.0.0"},
        }
        decision = self.gate.inspect_sync(req)
        self.assertEqual(decision.action, "block")
        self.assertTrue(decision.should_block)

    def test_good_bot_allowed(self):
        req = {
            "method": "GET",
            "url": "/sitemap.xml",
            "headers": {
                "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            },
        }
        decision = self.gate.inspect_sync(req)
        self.assertEqual(decision.action, "allow")
        self.assertFalse(decision.should_block)
        self.assertEqual(decision.category, "good_bot")

    def test_whitelisted_path(self):
        decision = self.gate.inspect_sync("/healthz")
        self.assertEqual(decision.action, "allow")
        self.assertFalse(decision.should_block)
        self.assertEqual(decision.reasons[0], "Path whitelisted")


if __name__ == "__main__":
    unittest.main()
