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
from jwt import PyJWK

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
# JWKS fetching (via httpx, cached)
# ---------------------------------------------------------------------------

_jwks_cache: dict[str, Any] | None = None
_jwks_ts: float = 0.0
_JWKS_TTL = 3600  # re-fetch once per hour


async def _fetch_jwks() -> dict[str, Any]:
    """Fetch and cache the JWKS from the provider using httpx.

    We fetch manually instead of using PyJWKClient because the latter
    uses urllib internally, whose default User-Agent gets blocked by
    some reverse proxies (NPM) and identity providers.
    """
    global _jwks_cache, _jwks_ts  # noqa: PLW0603

    now = time.monotonic()
    if _jwks_cache is not None and (now - _jwks_ts) < _JWKS_TTL:
        return _jwks_cache

    jwks_uri = await get_jwks_uri()
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            jwks_uri,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        jwks_data = resp.json()

    _jwks_cache = jwks_data
    _jwks_ts = now
    logger.info("oidc.jwks.refreshed uri=%s keys=%d", jwks_uri, len(jwks_data.get("keys", [])))
    return jwks_data


async def _get_signing_key_for_token(raw_token: str) -> Any:
    """Find the signing key that matches the token's kid header."""
    jwks_data = await _fetch_jwks()

    # Decode the token header to get the kid
    unverified_header = pyjwt.get_unverified_header(raw_token)
    kid = unverified_header.get("kid")
    alg = unverified_header.get("alg", "RS256")

    for key_data in jwks_data.get("keys", []):
        if kid and key_data.get("kid") != kid:
            continue
        if key_data.get("alg") and key_data["alg"] != alg:
            continue
        jwk = PyJWK(key_data, algorithm=alg)
        return jwk.key

    # If no kid match, try refreshing JWKS (key rotation)
    global _jwks_cache, _jwks_ts  # noqa: PLW0603
    _jwks_cache = None
    _jwks_ts = 0.0
    jwks_data = await _fetch_jwks()

    for key_data in jwks_data.get("keys", []):
        if kid and key_data.get("kid") != kid:
            continue
        jwk = PyJWK(key_data, algorithm=alg)
        return jwk.key

    raise pyjwt.PyJWKClientError(f"No matching key found for kid={kid}")


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
    signing_key = await _get_signing_key_for_token(raw_token)

    # Authentik sets the issuer to the base URL (not the application-specific URL)
    # so we accept both forms.
    issuer = settings.oidc_issuer_url.rstrip("/")
    app_issuer = f"{issuer}/application/o/{settings.oidc_application_slug}"

    # Try with the application-specific issuer first, then base issuer
    for iss in (app_issuer, issuer):
        try:
            claims: dict[str, Any] = pyjwt.decode(
                raw_token,
                signing_key,
                algorithms=["RS256", "ES256"],
                audience=settings.oidc_client_id,
                issuer=iss,
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
                leeway=30,
            )
            return claims
        except pyjwt.InvalidIssuerError:
            continue

    # If neither issuer matched, raise with the last error
    raise pyjwt.InvalidIssuerError("Token issuer does not match expected values")


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
