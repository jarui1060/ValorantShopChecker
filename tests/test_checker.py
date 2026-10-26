"""Offline regression checks: fake credentials, no network calls."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci_check_store as checker
import valorant_auth as auth
import requests


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state" / "riot-session.enc"
        self.seed = {"ssid": "fake-original-credential"}

    def test_rotated_session_survives_without_plaintext(self):
        rotated = {"ssid": "fake-rotated-credential", "tdid": "fake-device"}
        checker.save_session(self.seed, rotated, self.path)
        ciphertext = self.path.read_bytes()
        self.assertNotIn(b"fake-original-credential", ciphertext)
        self.assertNotIn(b"fake-rotated-credential", ciphertext)
        self.assertEqual(checker.load_session(self.seed, self.path), rotated)

    def test_new_secret_starts_a_new_session(self):
        checker.save_session(self.seed, {"ssid": "old-session"}, self.path)
        new_seed = {"ssid": "replacement-credential"}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(checker.load_session(new_seed, self.path), new_seed)

    def test_tampered_cache_is_not_trusted(self):
        checker.save_session(self.seed, self.seed, self.path)
        self.path.write_bytes(self.path.read_bytes()[:-8] + b"tampered")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(checker.load_session(self.seed, self.path), self.seed)

    def test_invalid_secret_forms_are_rejected(self):
        for value in ["", "not json", "[]", '"cookie"', '{"sid":"x"}', '{"ssid":1}']:
            with self.subTest(value=value), self.assertRaises(checker.CheckerError):
                checker.parse_cookies(value)


class DeliveryTests(unittest.TestCase):
    def test_delivery_waits_for_confirmation_and_disables_mentions(self):
        response = Mock(ok=True, status_code=200)
        response.json.return_value = {"id": "fake-message-id"}
        with patch.object(checker.requests, "post", return_value=response) as post:
            checker.post_to_discord("https://discord.com/api/webhooks/1/fake-token", "@everyone boutique")
        self.assertEqual(post.call_args.kwargs["params"], {"wait": "true"})
        self.assertEqual(post.call_args.kwargs["json"]["allowed_mentions"], {"parse": []})

    def test_rejected_discord_delivery_is_a_failure(self):
        with patch.object(checker.requests, "post", return_value=Mock(ok=False, status_code=404)):
            with self.assertRaisesRegex(checker.CheckerError, "HTTP 404"):
                checker.post_to_discord("https://discord.com/api/webhooks/1/fake-token", "shop")

    def test_delivery_without_message_id_is_not_reported_as_success(self):
        response = Mock(ok=True, status_code=200)
        response.json.return_value = {}
        with patch.object(checker.requests, "post", return_value=response):
            with self.assertRaises(checker.CheckerError):
                checker.post_to_discord("https://discord.com/api/webhooks/1/fake-token", "shop")

    def test_network_errors_do_not_disclose_webhook(self):
        with patch.object(checker.requests, "post", side_effect=requests.ConnectionError("fake-token")):
            with self.assertRaises(checker.CheckerError) as error:
                checker.post_to_discord("https://discord.com/api/webhooks/1/fake-token", "shop")
        self.assertNotIn("fake-token", str(error.exception))

    def test_only_discord_https_webhooks_are_accepted(self):
        self.assertTrue(checker.validate_webhook("https://discord.com/api/webhooks/1/fake"))
        for url in ["http://discord.com/api/webhooks/1/fake", "https://discord.com.evil.test/api/webhooks/1/fake"]:
            self.assertFalse(checker.validate_webhook(url))


class AuthTests(unittest.TestCase):
    def test_failed_json_response_does_not_disclose_body(self):
        response = Mock(ok=False, status_code=401, text="private-response-body")
        with self.assertRaises(auth.AuthError) as error:
            auth.checked_json(response, "store")
        self.assertIn("401", str(error.exception))
        self.assertNotIn("private-response-body", str(error.exception))

    def test_blocked_auth_is_not_treated_as_expired_cookie(self):
        session = Mock()
        session.get.return_value = Mock(status_code=403)
        with self.assertRaisesRegex(auth.AuthError, "HTTP 403"):
            auth.reauth_with_cookies(session)
        session.get.assert_called_once()

    def test_unexpected_auth_redirect_is_rejected(self):
        session = Mock()
        session.get.return_value = Mock(status_code=302, headers={"Location": "https://evil.test/#access_token=fake"})
        with self.assertRaises(auth.AuthError):
            auth.reauth_with_cookies(session)


class RunnerTests(unittest.TestCase):
    def test_rotation_is_retained_even_when_the_store_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "session.enc"
            seed = {"ssid": "fake-original-credential"}
            env = {"RIOT_COOKIES": json.dumps(seed), "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1/fake-token",
                   "RIOT_SESSION_FILE": str(path), "REGION": "eu"}
            def authenticate(session):
                session.cookies.set("ssid", "fake-rotated-credential", domain="auth.riotgames.com")
                return "fake-access-token"
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(checker, "reauth_with_cookies", side_effect=authenticate), \
                 patch.object(checker, "fetch_store", side_effect=auth.AuthError("Store indisponible")), \
                 patch.object(checker, "post_to_discord") as post, \
                 contextlib.redirect_stderr(io.StringIO()) as output:
                self.assertEqual(checker.main(), 1)
            self.assertEqual(checker.load_session(seed, path)["ssid"], "fake-rotated-credential")
            self.assertNotIn("fake-access-token", output.getvalue())
            self.assertNotIn("fake-rotated-credential", output.getvalue())
            self.assertTrue(post.call_args.args[1].startswith("⚠️"))

    def test_success_uses_eu_and_reports_confirmed_delivery(self):
        with tempfile.TemporaryDirectory() as folder:
            env = {"RIOT_COOKIES": '{"ssid":"fake-seed"}', "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1/fake-token",
                   "RIOT_SESSION_FILE": str(Path(folder) / "session.enc")}
            store = {"SkinsPanelLayout": {"SingleItemOffers": ["a", "b", "c", "d"]}}
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(checker, "reauth_with_cookies", return_value="fake-token"), \
                 patch.object(checker, "fetch_store", return_value=store) as fetch, \
                 patch.object(checker, "format_store_lines", return_value=["Boutique de test"]), \
                 patch.object(checker, "post_to_discord") as post, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(checker.main(), 0)
            self.assertEqual(fetch.call_args.args[2], "eu")
            self.assertEqual(post.call_args.args[1], "Boutique de test")
            self.assertIn("enregistré par Discord", output.getvalue())


if __name__ == "__main__":
    unittest.main()
