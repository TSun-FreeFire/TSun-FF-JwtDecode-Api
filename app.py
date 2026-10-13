"""JWT Decoder API.

A small Flask service that decodes JSON Web Tokens (header + payload) without
verifying the signature, so that expired / untrusted tokens can still be
inspected.

Endpoints
---------
GET  /               Web UI (decodes tokens in the browser).
GET  /decode_jwt     Decode a token passed as ?token=<jwt>.
POST /decode_jwt     Decode a token passed as JSON/form {"token": "<jwt>"}
                     (useful for tokens that are too long for a URL).
GET  /health         Liveness probe used by Docker / Nginx.

Success response (HTTP 200)::

    {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022,
      "issued_at": "2018-01-18 01:30:22",
      "exp": "2018-01-18 02:30:22",
      "expires_at": "2018-01-18T02:30:22Z",
      "expired": true
    }

Error response (HTTP 400 / 413 / 500)::

    {"error": "Invalid token", "details": "Not enough segments"}
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import jwt
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

# Keep the original claim order of the token in the API response instead of
# having Flask alphabetically re-sort every key.
try:  # Flask >= 2.2
    app.json.sort_keys = False
except AttributeError:  # pragma: no cover - very old Flask
    app.config["JSON_SORT_KEYS"] = False


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# We only *decode*: signature and claim validity checks are intentionally
# disabled so that expired or not-yet-valid tokens can still be inspected.
# Without this PyJWT refuses an expired token before we can report it.
DECODE_OPTIONS = {
    "verify_signature": False,
    "verify_exp": False,
    "verify_nbf": False,
    "verify_iat": False,
    "verify_aud": False,
    "verify_iss": False,
    "verify_sub": False,
    "verify_jti": False,
}

# Claims that carry a unix timestamp and are converted to a readable UTC value.
LOCK_TIME_CLAIMS = ("lock_region_time",)

# Maximum accepted token length (protects the server from oversized payloads).
MAX_TOKEN_LENGTH = 16384

# Human readable format used for the converted timestamp claims.
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class TokenError(Exception):
    """Raised when a token cannot be decoded.

    ``status`` is the HTTP status code that should be returned to the client.
    """

    def __init__(self, message: str, status: int = 400, details: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.details = details


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _as_utc_datetime(value: Any) -> Optional[datetime]:
    """Return a timezone aware UTC ``datetime`` for a unix timestamp.

    Accepts int/float timestamps and numeric strings (tokens in the wild
    sometimes store timestamps as strings). Returns ``None`` for anything that
    is not a sane timestamp instead of raising TypeError/OverflowError.
    """
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        timestamp = float(value)
    elif isinstance(value, str):
        try:
            timestamp = float(value.strip())
        except (TypeError, ValueError):
            return None
    else:
        return None

    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _format_utc(moment: datetime) -> str:
    """Format a UTC datetime the way this API has always reported times."""
    return moment.strftime(TIME_FORMAT)


def _iso_utc(moment: datetime) -> str:
    """RFC 3339 / ISO 8601 representation (2025-11-03T14:23:00Z)."""
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _decode_segment(segment: str) -> Any:
    """Decode one base64url + JSON JWT segment, tolerant about padding.

    Used as a fallback so that a token whose *signature* segment is mangled
    (truncated, wrong padding, ...) still yields a readable header/payload.
    """
    if not segment:
        raise ValueError("empty segment")

    candidates = (
        segment + "=" * (-len(segment) % 4),
        segment.replace("-", "+").replace("_", "/"),
    )
    for candidate in candidates:
        try:
            return json.loads(base64.urlsafe_b64decode(candidate).decode("utf-8"))
        except Exception:  # try the next candidate
            continue

    raise ValueError("segment is not valid base64url encoded JSON")


def annotate_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``claims`` with readable timestamps and an expiry flag.

    Original values are kept so existing consumers keep working; only ``exp``
    and ``lock_region_time`` are rewritten (as this API always did) and extra
    descriptive fields are added.
    """
    result: Dict[str, Any] = dict(claims)

    # --- exp: readable date, ISO date and expired flag --------------------- #
    if "exp" in claims:
        exp_dt = _as_utc_datetime(claims["exp"])
        if exp_dt is None:
            # Never crash on a malformed exp claim, just report it.
            result["expired"] = None
            result["expiry_warning"] = (
                "The 'exp' claim is not a valid unix timestamp, "
                "expiration cannot be determined."
            )
        else:
            result["exp"] = _format_utc(exp_dt)
            result["expires_at"] = _iso_utc(exp_dt)
            result["expired"] = exp_dt <= datetime.now(timezone.utc)

    # --- iat / nbf: keep the numeric claim, add a readable field ----------- #
    if "iat" in claims:
        iat_dt = _as_utc_datetime(claims["iat"])
        if iat_dt is not None:
            result["issued_at"] = _format_utc(iat_dt)

    if "nbf" in claims:
        nbf_dt = _as_utc_datetime(claims["nbf"])
        if nbf_dt is not None:
            result["not_before"] = _format_utc(nbf_dt)

    # --- FreeFire specific lock time (converted in place, as before) ------- #
    for claim in LOCK_TIME_CLAIMS:
        if claim in claims:
            claim_dt = _as_utc_datetime(claims[claim])
            if claim_dt is not None:
                result[claim] = _format_utc(claim_dt)

    return result


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode a JWT and annotate its time based claims.

    Raises :class:`TokenError` when the token is malformed. Never raises for
    unexpected claim types (a bad ``exp`` claim is reported, not a crash).
    """
    segments = token.split(".")

    if len(segments) == 5:
        raise TokenError(
            "Invalid token",
            details=(
                "This looks like an encrypted JWT (JWE, 5 parts). "
                "Only signed JWTs (header.payload.signature) can be decoded."
            ),
        )

    if len(segments) != 3:
        raise TokenError(
            "Invalid token",
            details=(
                "A JWT must have exactly 3 dot-separated parts "
                f"(header.payload.signature), got {len(segments)}."
            ),
        )

    if not segments[0] or not segments[1]:
        raise TokenError(
            "Invalid token", details="The header or the payload segment is empty."
        )

    reason = ""
    try:
        claims = jwt.decode(token, options=DECODE_OPTIONS)
    except jwt.InvalidTokenError as exc:
        reason = str(exc)
    except Exception as exc:  # pragma: no cover - defensive
        reason = str(exc)
    else:
        if not isinstance(claims, dict):
            raise TokenError("Invalid token", details="The payload must be a JSON object.")
        return annotate_claims(claims)

    # Lenient fallback: the header and the payload are frequently readable even
    # when PyJWT refuses the token (usually a truncated / mangled signature).
    try:
        header = _decode_segment(segments[0])
        payload = _decode_segment(segments[1])
    except ValueError as exc:
        raise TokenError("Invalid token", details=reason) from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenError("Invalid token", details=reason)

    result = annotate_claims(payload)
    result["signature_warning"] = (
        "The signature segment is not a valid base64url value, the header and "
        f"payload were decoded without it ({reason})."
    )
    return result


def extract_token() -> Optional[str]:
    """Pull the token out of the request (query, body or Authorization header).

    Whitespace is stripped and a leading ``Bearer `` prefix is removed so that
    tokens copied from documentation, logs or HTTP headers just work.
    """
    token: Optional[str] = request.args.get("token")

    if not token and request.method == "POST":
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            token = payload.get("token")
        if not token:
            token = request.form.get("token")

    if not token:
        header = request.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            token = header[len("bearer ") :]

    if isinstance(token, str):
        # Tokens are often pasted with a "Bearer " prefix and/or line breaks.
        token = token.strip()
        if token.lower().startswith("bearer"):
            token = token[len("bearer") :].strip()
        token = "".join(token.split())

    return token or None


def _is_api_request() -> bool:
    """True when the client expects JSON (API routes, fetch/XHR calls)."""
    if request.path.startswith(("/decode_jwt", "/health")):
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


def _error(message: str, status: int, details: Optional[str] = None):
    body: Dict[str, Any] = {"error": message}
    if details:
        body["details"] = details
    return jsonify(body), status


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    """Serve the main JWT decoder frontend."""
    return render_template("index.html")


@app.route("/health")
def health():
    """Liveness probe (used by the Docker healthcheck and Nginx)."""
    return jsonify({"status": "ok", "service": "tsun-ff-jwtdecode-api"})


@app.route("/decode_jwt", methods=["GET", "POST", "OPTIONS"])
def api_decode_jwt():
    """Decode the JWT supplied in the request.

    The documented way to call this API is ``GET /decode_jwt?token=<jwt>``.
    """
    if request.method == "OPTIONS":
        # CORS pre-flight.
        return "", 204

    token = extract_token()

    if not token:
        return _error(
            "Token is required",
            400,
            details=(
                "Pass the token as a query parameter (?token=<jwt>), as a JSON "
                'body {"token": "<jwt>"} or as an "Authorization: Bearer <jwt>" header.'
            ),
        )

    if len(token) > MAX_TOKEN_LENGTH:
        return _error(
            "Token is too long",
            413,
            details=f"Maximum accepted length is {MAX_TOKEN_LENGTH} characters.",
        )

    try:
        return jsonify(decode_jwt(token))
    except TokenError as exc:
        return _error(exc.message, exc.status, details=exc.details)
    except Exception as exc:  # pragma: no cover - defensive, keeps JSON output
        app.logger.exception("Unexpected error while decoding token")
        return _error("Internal server error", 500, details=str(exc))


@app.after_request
def add_cors_headers(response):
    """Allow the API to be consumed from any origin (browser / JS clients)."""
    if request.path.startswith(("/decode_jwt", "/health")):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.errorhandler(HTTPException)
def handle_http_exception(exc: HTTPException):
    """Return JSON instead of an HTML error page for API requests."""
    if _is_api_request():
        return _error(exc.name, exc.code or 500, details=exc.description)
    return exc


@app.errorhandler(Exception)
def handle_unexpected_exception(exc: Exception):
    """Last resort: never leak an HTML stack page to API clients."""
    app.logger.exception("Unhandled exception on %s", request.path)
    if _is_api_request():
        return _error("Internal server error", 500)
    return "<h1>Internal Server Error</h1>", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
