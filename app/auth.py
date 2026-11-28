"""Protects the endpoints that change settings or data.

The dashboard sends the signed-in user's Clerk session token as
`Authorization: Bearer <token>`; it is verified against Clerk's public keys.

If Clerk isn't configured on the backend (no NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY or CLERK_JWKS_URL
in .env), those endpoints only accept requests from this machine, so someone else on
the network can't change your keys.
"""
import base64
import logging
from functools import lru_cache

import jwt
from fastapi import HTTPException, Request

from app.config import CLERK_JWKS_URL, CLERK_PUBLISHABLE_KEY

log = logging.getLogger("auth")
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def jwks_url() -> str:
    if CLERK_JWKS_URL:
        return CLERK_JWKS_URL
    if CLERK_PUBLISHABLE_KEY.startswith(("pk_test_", "pk_live_")):
        # The publishable key is base64 of "<frontend-api-host>$".
        encoded = CLERK_PUBLISHABLE_KEY.split("_", 2)[2]
        host = base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode().rstrip("$")
        return f"https://{host}/.well-known/jwks.json"
    return ""


@lru_cache(maxsize=1)
def _jwk_client() -> jwt.PyJWKClient | None:
    url = jwks_url()
    return jwt.PyJWKClient(url) if url else None


def require_user(request: Request) -> dict:
    client = _jwk_client()
    if client is None:
        host = request.client.host if request.client else ""
        if host in LOCAL_HOSTS:
            return {"sub": "local"}
        raise HTTPException(403, "Clerk is not configured on the backend; settings can only be "
                                 "changed from this machine. Add NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY to the root .env.")
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "Sign in to change settings.")
    token = header.split(" ", 1)[1]
    try:
        key = client.get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"Invalid session token: {e}")
