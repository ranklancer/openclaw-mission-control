"""OIDC authentication endpoints for the Authorization Code flow.

Provides three endpoints:

- ``GET /api/auth/oidc/login``    — Redirect to the OIDC provider (Authentik).
- ``GET /api/auth/oidc/callback`` — Handle the provider callback, exchange
  the authorization code, create/sync the user, and redirect the browser
  to the frontend with a one-time exchange token.
- ``POST /api/auth/oidc/exchange`` — Swap the one-time token for a
  backend-signed session JWT the frontend stores and sends as a Bearer
  token on subsequent API calls.

The client secret never reaches the frontend.
"""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode

import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.core.auth_mode import AuthMode
from app.core.config import settings
from app.core.logging import get_logger
from app.core.oidc import (
    create_session_token,
    exchange_code,
    fetch_userinfo,
    generate_exchange_token,
    get_authorization_endpoint,
    hash_exchange_token,
    validate_id_token,
)
from app.db import crud
from app.db.session import async_session_maker
from app.models.users import User

logger = get_logger(__name__)
router = APIRouter(prefix="/auth/oidc", tags=["auth"])

# Redis key prefixes & TTLs
_STATE_PREFIX = "oidc:state:"
_STATE_TTL = 300  # 5 minutes
_EXCHANGE_PREFIX = "oidc:xchg:"
_EXCHANGE_TTL = 60  # 1 minute — one-time use


def _get_redis() -> aioredis.Redis:
    """Return an async Redis client from the RQ connection string."""
    return aioredis.from_url(settings.rq_redis_url, decode_responses=True)


def _oidc_redirect_uri() -> str:
    """Build the absolute redirect URI the provider will call back to."""
    return f"{settings.base_url}/api/v1/auth/oidc/callback"


# -----------------------------------------------------------------------
# GET /api/auth/oidc/login — start the OIDC flow
# -----------------------------------------------------------------------


@router.get("/login", include_in_schema=False)
async def oidc_login() -> RedirectResponse:
    """Redirect the browser to the OIDC provider's authorize endpoint."""
    if settings.auth_mode != AuthMode.OIDC:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OIDC auth is not enabled.",
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Persist state+nonce in Redis so we can verify them on callback.
    r = _get_redis()
    await r.setex(f"{_STATE_PREFIX}{state}", _STATE_TTL, nonce)
    await r.aclose()

    authorize_url = await get_authorization_endpoint()
    params = urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": _oidc_redirect_uri(),
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
        }
    )
    return RedirectResponse(f"{authorize_url}?{params}", status_code=302)


# -----------------------------------------------------------------------
# GET /api/auth/oidc/callback — provider redirects here with ?code=&state=
# -----------------------------------------------------------------------


def _extract_claim(claims: dict[str, Any], *keys: str) -> str | None:
    """Best-effort extraction of a string value from multiple claim keys."""
    for k in keys:
        v = claims.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


@router.get("/callback", include_in_schema=False)
async def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> RedirectResponse:
    """Handle the OIDC provider callback."""
    if settings.auth_mode != AuthMode.OIDC:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    # Provider-side errors (e.g. user denied consent).
    if error:
        logger.warning(
            "oidc.callback.provider_error error=%s description=%s",
            error,
            error_description or "",
        )
        return RedirectResponse(
            f"{settings.base_url}/sign-in?error=oidc_denied",
            status_code=302,
        )

    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing code or state parameter.",
        )

    # Validate state against Redis.
    r = _get_redis()
    nonce = await r.getdel(f"{_STATE_PREFIX}{state}")
    if nonce is None:
        await r.aclose()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired state.",
        )

    # Exchange the authorization code for tokens.
    try:
        token_data = await exchange_code(code, _oidc_redirect_uri())
    except Exception as exc:
        await r.aclose()
        logger.error("oidc.callback.code_exchange_failed error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Token exchange with identity provider failed.",
        ) from exc

    id_token_raw = token_data.get("id_token")
    access_token = token_data.get("access_token", "")

    # Validate the ID token signature and claims.
    email: str | None = None
    name: str | None = None
    oidc_sub: str | None = None

    if id_token_raw:
        try:
            id_claims = await validate_id_token(id_token_raw)
        except Exception as exc:
            await r.aclose()
            logger.error("oidc.callback.id_token_invalid error=%s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="ID token validation failed.",
            ) from exc

        # Verify nonce matches to prevent replay.
        if id_claims.get("nonce") != nonce:
            await r.aclose()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Nonce mismatch.",
            )

        oidc_sub = _extract_claim(id_claims, "sub")
        email = _extract_claim(
            id_claims, "email", "preferred_username", "email_address"
        )
        name = _extract_claim(
            id_claims, "name", "given_name", "preferred_username"
        )

    # Fallback: fetch userinfo if ID token lacked email/name.
    if access_token and (not email or not name):
        try:
            userinfo = await fetch_userinfo(access_token)
            if not email:
                email = _extract_claim(
                    userinfo, "email", "preferred_username"
                )
            if not name:
                name = _extract_claim(
                    userinfo, "name", "given_name", "preferred_username"
                )
            if not oidc_sub:
                oidc_sub = _extract_claim(userinfo, "sub")
        except Exception as exc:
            logger.warning("oidc.callback.userinfo_failed error=%s", exc)

    if not oidc_sub:
        await r.aclose()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not determine user identity from provider.",
        )

    # Create or sync user in the MC database.
    # We store the OIDC subject in the ``clerk_user_id`` column to avoid
    # a schema migration — the column is just a unique external-provider ID.
    async with async_session_maker() as session:
        defaults: dict[str, object] = {}
        if email:
            defaults["email"] = email.lower()
        if name:
            defaults["name"] = name

        user, created = await crud.get_or_create(
            session,
            User,
            clerk_user_id=f"oidc|{oidc_sub}",
            defaults=defaults,
        )

        changed = False
        if email and user.email != email.lower():
            user.email = email.lower()
            changed = True
        if name and not user.name:
            user.name = name
            changed = True
        if changed:
            session.add(user)
            await session.commit()
            await session.refresh(user)

        from app.services.organizations import ensure_member_for_user

        await ensure_member_for_user(session, user)

    logger.info(
        "oidc.callback.user_synced sub=%s email=%s created=%s",
        oidc_sub[-6:] if oidc_sub else "",
        email or "",
        created,
    )

    # Mint a session JWT and store a one-time exchange token in Redis.
    session_jwt = create_session_token(
        sub=f"oidc|{oidc_sub}",
        email=email,
        name=name,
    )

    exchange_token = generate_exchange_token()
    exchange_hash = hash_exchange_token(exchange_token)
    await r.setex(f"{_EXCHANGE_PREFIX}{exchange_hash}", _EXCHANGE_TTL, session_jwt)
    await r.aclose()

    # Redirect to frontend callback page with the one-time token.
    redirect_url = f"{settings.base_url}/auth/callback?session_id={exchange_token}"
    return RedirectResponse(redirect_url, status_code=302)


# -----------------------------------------------------------------------
# POST /api/auth/oidc/exchange — swap one-time token for session JWT
# -----------------------------------------------------------------------


class ExchangeRequest(BaseModel):
    session_id: str


class ExchangeResponse(BaseModel):
    token: str


@router.post(
    "/exchange",
    response_model=ExchangeResponse,
    summary="Exchange OIDC session token",
    description="Swap a one-time exchange token for a backend-signed session JWT.",
)
async def oidc_exchange(body: ExchangeRequest) -> ExchangeResponse:
    """Swap a one-time exchange token for a session JWT."""
    if settings.auth_mode != AuthMode.OIDC:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    exchange_hash = hash_exchange_token(body.session_id)
    r = _get_redis()
    session_jwt = await r.getdel(f"{_EXCHANGE_PREFIX}{exchange_hash}")
    await r.aclose()

    if not session_jwt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired exchange token.",
        )

    return ExchangeResponse(token=session_jwt)
