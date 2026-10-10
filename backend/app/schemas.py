"""Request and response models for the HTTP API."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)
    authorized: StrictBool
    path_scope: str = Field(default="/", min_length=1, max_length=2048)
    mode: Literal["basic", "deep"] = "basic"
    max_pages: StrictInt = Field(default=10, ge=1, le=30)


class OwnershipChallengeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=253)


class OwnershipVerify(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=253)


class ScanOut(BaseModel):
    id: str
    target_url: str
    hostname: str
    path_scope: str
    mode: str
    max_pages: int
    status: str
    progress: int
    progress_message: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    warnings: list[str]
    tested_areas: list[str]
    summary: dict


class FindingOut(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    status: str
    confidence: int
    affected_url: str
    evidence: str
    impact: str
    remediation: str
    observed_at: datetime


class OwnershipChallengeOut(BaseModel):
    hostname: str
    txt_name: str
    txt_value: str
    expires_at: datetime
    instructions: str


class OwnershipStatusOut(BaseModel):
    hostname: str
    verified: bool
    valid_until: datetime | None = None
