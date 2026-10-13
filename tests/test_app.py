"""Tests for the JWT Decoder API.

Run with::

    python -m unittest discover -s tests -v

Only the standard library plus the runtime requirements (Flask, PyJWT) are
needed, no extra test dependency.
"""

import base64
import json
import os
import sys
import time
import unittest

import jwt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import MAX_TOKEN_LENGTH, app  # noqa: E402  (path set up above)


SECRET = "a-test-secret-that-is-long-enough-for-hs256"


def b64(part):
    """base64url encode a JSON serialisable object without padding."""
    raw = json.dumps(part).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_token(payload, header=None):
    """Build a signed HS256 token for the given payload."""
    return jwt.encode(payload, SECRET, algorithm="HS256", headers=header)


def raw_token(payload, header=None, signature=None):
    """Build a token straight from raw JSON parts (signature is not checked)."""
    if signature is None:
        signature = base64.urlsafe_b64encode(b"fake-signature").rstrip(b"=").decode("ascii")
    return ".".join(
        [b64(header or {"alg": "HS256", "typ": "JWT"}), b64(payload), signature]
    )


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()
        self.now = int(time.time())

    def decode(self, token):
        return self.client.get("/decode_jwt", query_string={"token": token})

    def assertJsonError(self, response, status, message):
        self.assertEqual(response.status_code, status, response.get_data(as_text=True))
        self.assertEqual(response.headers["Content-Type"].split(";")[0], "application/json")
        body = response.get_json()
        self.assertEqual(body["error"], message)
        return body


class DecodeSuccessTests(ApiTestCase):
    def test_valid_token_is_decoded(self):
        token = make_token({"sub": "1234567890", "name": "John Doe", "exp": self.now + 3600})
        response = self.decode(token)

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["sub"], "1234567890")
        self.assertEqual(body["name"], "John Doe")
        self.assertFalse(body["expired"])
        # exp is rewritten to a readable UTC string, the numeric one is kept as ISO.
        self.assertRegex(body["exp"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        self.assertTrue(body["expires_at"].endswith("Z"))

    def test_expired_token_is_reported_not_rejected(self):
        token = make_token({"sub": "1", "exp": self.now - 60})
        body = self.decode(token).get_json()
        self.assertTrue(body["expired"])

    def test_claim_order_is_preserved(self):
        token = make_token({"z": 1, "a": 2, "m": 3})
        keys = list(self.decode(token).get_json().keys())
        self.assertEqual(keys, ["z", "a", "m"])

    def test_token_without_exp_has_no_expired_flag(self):
        token = make_token({"sub": "1"})
        body = self.decode(token).get_json()
        self.assertNotIn("expired", body)
        self.assertNotIn("exp", body)

    def test_iat_and_nbf_get_readable_fields(self):
        token = make_token({"iat": self.now, "nbf": self.now, "exp": self.now + 10})
        body = self.decode(token).get_json()
        self.assertEqual(body["iat"], self.now)  # numeric value untouched
        self.assertIn("issued_at", body)
        self.assertIn("not_before", body)

    def test_lock_region_time_is_converted(self):
        token = make_token({"lock_region_time": 1750000000})
        body = self.decode(token).get_json()
        self.assertEqual(body["lock_region_time"], "2025-06-15 15:06:40")

    def test_unicode_claims_survive(self):
        token = make_token({"name": "سعید 🚀 ünïcode"})
        self.assertEqual(self.decode(token).get_json()["name"], "سعید 🚀 ünïcode")

    def test_mangled_signature_still_shows_payload(self):
        """A token with a broken signature segment is decoded with a warning."""
        token = raw_token({"sub": "1"}, signature="not-base64url-padding")
        response = self.decode(token)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        body = response.get_json()
        self.assertEqual(body["sub"], "1")
        self.assertIn("signature_warning", body)

    def test_alg_none_token_is_decodable(self):
        token = raw_token({"sub": "1"}, header={"alg": "none"}, signature="")
        body = self.decode(token).get_json()
        self.assertEqual(body["sub"], "1")

    def test_token_with_whitespace_and_bearer_prefix(self):
        token = make_token({"sub": "1"})
        messy = "Bearer  " + token[:20] + "\n" + token[20:]
        response = self.decode(messy)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json()["sub"], "1")


class MalformedTokenTests(ApiTestCase):
    """Every malformed token must answer with JSON, never an HTML 500 page."""

    def test_two_parts(self):
        self.assertJsonError(self.decode("abc.def"), 400, "Invalid token")

    def test_not_a_token(self):
        self.assertJsonError(self.decode("not-a-token"), 400, "Invalid token")

    def test_bad_json_payload(self):
        token = b64({"alg": "HS256"}) + ".not-json.signature"
        self.assertJsonError(self.decode(token), 400, "Invalid token")

    def test_empty_header_segment(self):
        self.assertJsonError(self.decode(".payload.signature"), 400, "Invalid token")

    def test_jwe_token_is_explained(self):
        token = ".".join([b64({"alg": "dir", "enc": "A256GCM"})] * 5)
        body = self.assertJsonError(self.decode(token), 400, "Invalid token")
        self.assertIn("JWE", body["details"])

    def test_non_object_payload(self):
        token = b64({"alg": "HS256"}) + "." + b64([1, 2, 3]) + ".sig"
        self.assertJsonError(self.decode(token), 400, "Invalid token")


class BadClaimTypesTests(ApiTestCase):
    """Regression tests: malformed timestamps used to crash with a 500."""

    def test_string_exp_does_not_crash(self):
        body = self.decode(raw_token({"exp": "tomorrow"})).get_json()
        self.assertEqual(body["exp"], "tomorrow")
        self.assertIsNone(body["expired"])
        self.assertIn("expiry_warning", body)

    def test_numeric_string_exp_is_converted(self):
        body = self.decode(raw_token({"exp": "1750000000"})).get_json()
        self.assertEqual(body["exp"], "2025-06-15 15:06:40")

    def test_huge_exp_does_not_crash(self):
        response = self.decode(raw_token({"exp": 10 ** 30}))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get_json()["expired"])

    def test_boolean_exp_does_not_crash(self):
        self.assertIsNone(self.decode(raw_token({"exp": True})).get_json()["expired"])

    def test_string_lock_region_time_does_not_crash(self):
        response = self.decode(raw_token({"lock_region_time": "yesterday"}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["lock_region_time"], "yesterday")


class RequestHandlingTests(ApiTestCase):
    def test_missing_token(self):
        self.assertJsonError(self.client.get("/decode_jwt"), 400, "Token is required")

    def test_blank_token(self):
        self.assertJsonError(self.client.get("/decode_jwt?token="), 400, "Token is required")

    def test_token_from_authorization_header(self):
        token = make_token({"sub": "1"})
        response = self.client.get(
            "/decode_jwt", headers={"Authorization": "Bearer " + token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["sub"], "1")

    def test_token_from_json_body(self):
        token = make_token({"sub": "body"})
        response = self.client.post("/decode_jwt", json={"token": token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["sub"], "body")

    def test_token_from_form_body(self):
        token = make_token({"sub": "form"})
        response = self.client.post("/decode_jwt", data={"token": token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["sub"], "form")

    def test_post_without_token(self):
        self.assertJsonError(self.client.post("/decode_jwt", json={}), 400, "Token is required")

    def test_oversized_token(self):
        token = "a" * (MAX_TOKEN_LENGTH + 1)
        self.assertJsonError(self.decode(token), 413, "Token is too long")

    def test_cors_headers_are_present(self):
        response = self.decode(make_token({"sub": "1"}))
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "*")

    def test_options_preflight(self):
        response = self.client.options("/decode_jwt")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "*")

    def test_unknown_api_route_returns_json(self):
        response = self.client.get("/decode_jwt/extra")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["Content-Type"].split(";")[0], "application/json")

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_index_page_is_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["Content-Type"])
        self.assertIn("JWT Decoder", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class FaviconTests(ApiTestCase):
    """The favicon set must be linked, served and readable."""

    def test_favicon_ico_is_served_at_the_site_root(self):
        response = self.client.get("/favicon.ico")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "image/vnd.microsoft.icon")
        # ICONDIR: reserved=0, type=1 (icon), image count
        self.assertEqual(response.data[:4], b"\x00\x00\x01\x00")
        self.assertIn("max-age=604800", response.headers.get("Cache-Control", ""))

    def test_favicon_svg_uses_the_brand_colour(self):
        response = self.client.get("/static/favicon.svg")
        self.assertEqual(response.status_code, 200)
        self.assertIn("image/svg+xml", response.headers["Content-Type"])
        body = response.get_data(as_text=True)
        self.assertIn("#6366f1", body)  # var(--color-primary)
        self.assertIn("M12 2L2 7L12 12L22 7L12 2Z", body)  # header logo mark

    def test_png_icons_and_manifest_are_served(self):
        expected = {
            "/static/favicon-16x16.png": "image/png",
            "/static/favicon-32x32.png": "image/png",
            "/static/apple-touch-icon.png": "image/png",
            "/static/android-chrome-192x192.png": "image/png",
            "/static/site.webmanifest": "application/manifest+json",
        }
        for path, content_type in expected.items():
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(content_type, response.headers["Content-Type"])

    def test_index_links_the_icon_set(self):
        html = self.client.get("/").get_data(as_text=True)
        for needle in (
            'rel="icon" type="image/svg+xml"',
            'rel="icon" href="/favicon.ico" sizes="any"',
            'rel="apple-touch-icon" sizes="180x180"',
            'rel="manifest"',
            'name="theme-color" content="#6366f1"',
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, html)
