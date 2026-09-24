from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AuditCreateRequest(BaseModel):
    domain: str = Field(..., examples=["exemple.com"])
    client_name: str = Field(..., description="Nom du client pour lequel l'audit est réalisé")
    verification_method: Literal["dns_txt", "well_known"] = "dns_txt"


class VerificationInfoResponse(BaseModel):
    method: Literal["dns_txt", "well_known"]
    instructions: str
    status: Literal["pending", "verified", "expired"]


class AuditResponse(BaseModel):
    id: str
    domain: str
    status: str
    recon_results: dict[str, Any] | None = None
    verification: VerificationInfoResponse | None = None
    started_at: datetime
    completed_at: datetime | None = None

    class Config:
        from_attributes = True