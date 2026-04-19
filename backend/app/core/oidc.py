"""OIDC discovery, JWT validation, and session-token helpers.

This module implements the server-side of the Authorization Code flow
for a generic OIDC provider (e.g. Authentik).  It:

1. Discovers provider endpoints via ``/.well-known/openid-configuration``.
2. Fetches and caches the JWKS for token signature verification.
3. Validates ID tokens returned by the provider after code exchange.
4. Issues short-lived *session JWTs* consumed by the MC frontend,
   keeping the same ``Authorization: Bearer <token>`` pattern used
   by the ``local`` and ``clerk`` auth modes.

The OIDC client secret never leaves the backend.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any

import httpx
import jwt as pyjwt
from jwt import PyJWKClient

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Provider discovery (cached)
# ---------------------------------------------------------------------------

_discovery_cache: dict[str, Any] | None = None
_discovery_ts: float = 0.0
_DISCOVERY_TTL = 3600  # re-fetch once per hour


async def _fetch_discovery() -> dict[str, Any]:
    """Fetch and cache the OpenID Connect discovery document."""
    global _discovery_cache, _discovery_ts  # noqa: PLW0603

    now = time.monotonic()
    if _discovery_cache is not None and (now - _discovery_ts) < _DISCOVERY_TTL:
        return _discovery_cache

    issuer = settings.oidc_issuer_url.rstrip("/")
    url = f"{issuer}/application/o/{settings.oidc_application_slug}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        doc = resp.json()

    _discovery_cache = doc
    _discovery_ts = now
    logger.info("oidc.discovery.refreshed issuer=%s", issuer)
    return doc


async def get_authorization_endpoint() -> str:
    doc = await _fetch_discovery()
    return str(doc["authorization_endpoint"])


async def get_token_endpoint() -> str:
    doc = await _fetch_discovery()
    return str(doc["token_endpoint"])


async def get_jwks_uri() -> str:
    doc = await _fetch_discovery()
    return str(doc["jwks_uri"])


async def get_userinfo_endpoint() -> str:
    doc = await _fetch_discovery()
    return str(doc["userinfo_endpoint"])


# ---------------------------------------------------------------------------
# JWKS client (cached by PyJWKClient internally)
# ---------------------------------------------------------------------------

_jwk_client: PyJWKClient | None = None


async def _get_jwk_client() -> PyJWKClient:
    """Return a PyJWKClient pointed at the provider's JWKS URI."""
    global _jwk_client  # noqa: PLW0603
    if _jwk_client is not None:
        return _jwk_client
    jwks_uri = await get_jwks_uri()
    _jwk_client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600)
    return _jwk_client


# ---------------------------------------------------------------------------
# Authorization code exchange
# ---------------------------------------------------------------------------


async def exchange_code(code: str, redirect_uri: str) -> dict[str, Any]:
    """Exchange an authorization code for tokens at the provider's token endpoint."""
    token_url = await get_token_endpoint()

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
            },
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# ID-token validation
# ---------------------------------------------------------------------------


async def validate_id_token(raw_token: str) -> dict[str, Any]:
    """Validate and decode an OIDC ID token.

    Returns the full set of claims on success.
    Raises ``jwt.PyJWTError`` subclasses on failure.
    """
    client = await _get_jwk_client()
    signing_key = client.get_signing_key_from_jwt(raw_token)

    claims: dict[str, Any] = pyjwt.decode(
        raw_token,
        signing_key.key,
        algorithms=["RS256", "ES256"],
        audience=settings.oidc_client_id,
        issuer=settings.oidc_issuer_url.rstrip("/"),
        options={
            "verify_exp": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
        },
        leeway=30,
    )
    return claims


# ---------------------------------------------------------------------------
# Userinfo fetch (fallback when ID token lacks email/name)
# ---------------------------------------------------------------------------


async def fetch_userinfo(access_token: str) -> dict[str, Any]:
    """Fetch claims from the provider's userinfo endpoint."""
    userinfo_url = await get_userinfo_endpoint()
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Session JWT helpers (issued by MC backend, not the OIDC provider)
# ---------------------------------------------------------------------------

_SESSION_ALGORITHM = "HS256"
SESSION_TOKEN_LIFETIME = 86400  # 24 hours


def create_session_token(
    *,
    sub: str,
    email: str | None = None,
    name: str | None = None,
) -> str:
    """Mint a backend-signed session JWT for the frontend."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": sub,
        "iat": now,
        "exp": now + SESSION_TOKEN_LIFETIME,
        "iss": "mission-control",
        "aud": "mission-control-frontend",
    }
    if email:
        payload["email"] = email
    if name:
        payload["name"] = name
    return pyjwt.encode(payload, settings.oidc_session_secret, algorithm=_SESSION_ALGORITHM)


def validate_session_token(raw_token: str) -> dict[str, Any]:
    """Validate a backend-issued session JWT. Returns claims or raises."""
    return pyjwt.decode(
        raw_token,
        settings.oidc_session_secret,
        algorithms=[_SESSION_ALGORITHM],
        audience="mission-control-frontend",
        issuer="mission-control",
        options={"verify_exp": True, "verify_iat": True},
        leeway=10,
    )


# ---------------------------------------------------------------------------
# One-time exchange tokens (stored in Redis)
# ---------------------------------------------------------------------------


def generate_exchange_token() -> str:
    """Generate a cryptographically random one-time exchange token."""
    return secrets.token_urlsafe(48)


def hash_exchange_token(token: str) -> str:
    """Hash an exchange token for safe Redis storage."""
    return hashlib.sha256(token.encode()).hexdigest()
