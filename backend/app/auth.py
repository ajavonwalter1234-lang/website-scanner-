"""Bearer-token authentication mapped to per-user scan ownership."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings


bearer_scheme = HTTPBearer(auto_error=False, scheme_name="BearerToken")


@dataclass(frozen=True)
class CurrentUser:
    user_id: str


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> CurrentUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    owner_id = None
    # Compare all configured values without returning token-specific diagnostics.
    for configured_token, configured_owner in settings.api_tokens.items():
        if hmac.compare_digest(token.encode("utf-8"), configured_token.encode("utf-8")):
            owner_id = configured_owner
    if owner_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(user_id=owner_id)


AuthenticatedUser = Annotated[CurrentUser, Depends(get_current_user)]
