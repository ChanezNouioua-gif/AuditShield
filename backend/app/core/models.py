import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, JSON, Enum as SAEnum
from sqlalchemy.orm import relationship
import enum
from app.core.db import Base


def _uuid():
    return str(uuid.uuid4())

def _now():
    return datetime.now(timezone.utc)


class AuditStatus(str, enum.Enum):
    pending = "pending"
    recon_only = "recon_only"
    scanning = "scanning"
    triaging = "triaging"
    completed = "completed"
    failed = "failed"


class VerificationStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    expired = "expired"


class VerificationMethod(str, enum.Enum):
    dns_txt = "dns_txt"
    well_known = "well_known"


class Confidence(str, enum.Enum):
    confirmed = "confirmed"
    needs_manual_review = "needs_manual_review"


class Client(Base):
    __tablename__ = "clients"
    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    contact_email = Column(String)
    created_at = Column(DateTime(timezone=True), default=_now)

    audits = relationship("Audit", back_populates="client", cascade="all, delete-orphan")


class VerificationToken(Base):
    __tablename__ = "verification_tokens"
    id = Column(String, primary_key=True, default=_uuid)
    domain = Column(String, nullable=False, index=True)
    token = Column(String, nullable=False, unique=True)
    method = Column(SAEnum(VerificationMethod))
    status = Column(SAEnum(VerificationStatus), default=VerificationStatus.pending)
    created_at = Column(DateTime(timezone=True), default=_now)
    expires_at = Column(DateTime(timezone=True))
    verified_at = Column(DateTime(timezone=True))


class Audit(Base):
    __tablename__ = "audits"
    id = Column(String, primary_key=True, default=_uuid)
    client_id = Column(String, ForeignKey("clients.id"))
    domain = Column(String, nullable=False, index=True)
    status = Column(SAEnum(AuditStatus), default=AuditStatus.pending)
    verification_token_id = Column(String, ForeignKey("verification_tokens.id"))
    global_score = Column(Float)
    recon_results = Column(JSON)          # sortie brute du ReconAgent
    started_at = Column(DateTime(timezone=True), default=_now)
    completed_at = Column(DateTime(timezone=True))

    client = relationship("Client", back_populates="audits")
    findings = relationship("Finding", back_populates="audit", cascade="all, delete-orphan")
    scores = relationship("ScoreHistory", back_populates="audit", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=_uuid)
    audit_id = Column(String, ForeignKey("audits.id"), index=True)
    category = Column(String, index=True)       # tls | headers | email | exposed_services | known_vulns
    title = Column(String, nullable=False)
    description = Column(String)                # explication LLM en langage clair
    severity = Column(Float)                    # CVSS brut si disponible
    business_priority = Column(Integer)         # 1 = critique ... 5 = informatif
    confidence = Column(SAEnum(Confidence), default=Confidence.needs_manual_review)
    cve_id = Column(String, nullable=True, index=True)
    evidence = Column(JSON)                     # {"port": 443, "endpoint": "/.env", "response": "..."}
    remediation = Column(String)
    created_at = Column(DateTime(timezone=True), default=_now)

    audit = relationship("Audit", back_populates="findings")


class ScoreHistory(Base):
    __tablename__ = "score_history"
    id = Column(String, primary_key=True, default=_uuid)
    audit_id = Column(String, ForeignKey("audits.id"))
    domain = Column(String, index=True)
    category = Column(String)
    score = Column(Float)
    recorded_at = Column(DateTime(timezone=True), default=_now)

    audit = relationship("Audit", back_populates="scores")