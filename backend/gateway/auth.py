"""
gateway/auth.py — JWT + API Key Authentication

Supports:
- JWT Bearer token authentication
- API key validation (X-API-Key header)
- Permission-based access control
"""
import hashlib
import secrets
import time
from typing import Optional, Dict
from datetime import datetime, timedelta

from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
import jwt
from loguru import logger

from backend.config import settings
from backend.models.schemas import TokenData, APIKey

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_scheme = APIKeyHeader(name=settings.API_KEY_HEADER, auto_error=False)

# In-memory API key store (production: use Redis/PostgreSQL)
_api_keys: Dict[str, APIKey] = {}

# Demo key for development
_DEMO_KEY = settings.DEMO_API_KEY
_api_keys[_DEMO_KEY] = APIKey(
    key_id="demo",
    name="Demo API Key",
    key_hash=hashlib.sha256(_DEMO_KEY.encode()).hexdigest(),
    permissions=["read", "write", "admin"],
    rate_limit=1000,
)


def create_jwt_token(subject: str, permissions: list[str] = None) -> str:
    """Create a signed JWT token."""
    payload = {
        "sub": subject,
        "permissions": permissions or ["read"],
        "iat": int(time.time()),
        "exp": int(time.time()) + (settings.JWT_EXPIRE_MINUTES * 60),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Optional[TokenData]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return TokenData(
            sub=payload["sub"],
            permissions=payload.get("permissions", []),
            exp=payload.get("exp"),
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


def validate_api_key(key: str) -> Optional[APIKey]:
    """Validate an API key."""
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    for stored_key in _api_keys.values():
        if stored_key.key_hash == key_hash and stored_key.is_active:
            return stored_key
    return None


def generate_api_key(name: str, permissions: list[str] = None) -> tuple[str, APIKey]:
    """Generate a new API key."""
    raw_key = f"sat-{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    api_key = APIKey(
        name=name,
        key_hash=key_hash,
        permissions=permissions or ["read", "write"],
    )
    _api_keys[raw_key] = api_key
    return raw_key, api_key


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_scheme),
) -> TokenData:
    """
    FastAPI dependency: authenticate via JWT or API key.
    Returns token data or raises 401.
    """
    # Try API key first
    if api_key:
        stored_key = validate_api_key(api_key)
        if stored_key:
            return TokenData(
                sub=f"apikey:{stored_key.key_id}",
                permissions=stored_key.permissions,
            )
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Try JWT Bearer
    if credentials:
        return decode_jwt_token(credentials.credentials)

    # Development mode: allow unauthenticated if DEBUG
    if settings.DEBUG:
        return TokenData(sub="anonymous", permissions=["read", "write"])

    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide Bearer token or X-API-Key header.",
    )


def require_permission(permission: str):
    """Dependency factory: require a specific permission."""
    async def _check(token: TokenData = Depends(get_current_user)):
        if permission not in token.permissions and "admin" not in token.permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{permission}' required",
            )
        return token
    return _check
