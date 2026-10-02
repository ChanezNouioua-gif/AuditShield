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


class FindingResponse(BaseModel):
    id: str
    category: str
    title: str
    description: str | None = None
    severity: float | None = None
    business_priority: int | None = None
    confidence: Literal["confirmed", "needs_manual_review"]
    cve_id: str | None = None
    evidence: dict[str, Any] | None = None
    remediation: str | None = None

    class Config:
        from_attributes = True


class AuditResponse(BaseModel):
    id: str
    domain: str
    status: str
    recon_results: dict[str, Any] | None = None
    scan_results: dict[str, Any] | None = None
    findings: list[FindingResponse] | None = None
    verification: VerificationInfoResponse | None = None
    started_at: datetime
    completed_at: datetime | None = None

    class Config:
        from_attributes = True


class VerificationCheckResponse(BaseModel):
    audit_id: str
    domain: str
    method: Literal["dns_txt", "well_known"]
    status: Literal["pending", "verified", "expired"]
    verified: bool
    message: str