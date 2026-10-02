"""
Routes de gestion des audits.

POST /audits
    -> crée l'audit et lance ReconAgent via l'Orchestrator.
    -> l'audit s'arrête en `recon_only` jusqu'à vérification.

POST /audits/{audit_id}/scan
    -> reprend l'audit au stage `scan`.
    -> Orchestrator exécute :
        ScanAgent -> TriageAgent -> ReportAgent

POST /audits/{audit_id}/triage
    -> endpoint de reprise/compatibilité.
    -> reprend directement au stage `triage`.
    -> Orchestrator exécute :
        TriageAgent -> ReportAgent

GET /audits/{audit_id}
    -> relit l'état courant de l'audit.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.agents.orchestrator import build_orchestrator
from app.api.deps import get_db
from app.core import models
from app.core.schemas import (
    AuditCreateRequest,
    AuditResponse,
    FindingResponse,
    VerificationInfoResponse,
)

router = APIRouter()

TOKEN_TTL_HOURS = 72

# L'orchestrateur est compilé une seule fois au chargement du module.
_orchestrator = build_orchestrator()


# ============================================================
# HELPERS
# ============================================================

def _finding_to_dict(finding: models.Finding) -> dict:
    """
    Convertit un Finding SQLAlchemy en dictionnaire compatible
    avec AuditState.
    """
    return {
        "category": finding.category,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "business_priority": finding.business_priority,
        "confidence": finding.confidence.value,
        "cve_id": finding.cve_id,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
    }


def _persist_findings(
    db: Session,
    audit: models.Audit,
    triaged_findings: list[dict],
) -> list[models.Finding]:
    """
    Remplace les findings existants par ceux produits par TriageAgent.

    Cette opération rend une relance du triage idempotente :
    on ne crée pas de doublons.
    """

    db.query(models.Finding).filter_by(
        audit_id=audit.id
    ).delete()

    findings_rows: list[models.Finding] = []

    for item in triaged_findings:
        finding = models.Finding(
            audit_id=audit.id,
            category=item["category"],
            title=item["title"],
            description=item.get("description"),
            severity=item.get("severity"),
            business_priority=item.get("business_priority"),
            confidence=models.Confidence(
                item["confidence"]
            ),
            cve_id=item.get("cve_id"),
            evidence=item.get("evidence"),
            remediation=item.get("remediation"),
        )

        db.add(finding)
        findings_rows.append(finding)

    return findings_rows


def _persist_orchestrator_result(
    db: Session,
    audit: models.Audit,
    result: dict,
) -> list[models.Finding]:
    """
    Persiste dans la DB les données produites par l'Orchestrator.

    Le State est la source de vérité pendant l'exécution du pipeline.
    La DB devient la source de vérité entre deux appels HTTP.
    """

    # --------------------------------------------------------
    # Recon
    # --------------------------------------------------------

    if "recon_results" in result:
        audit.recon_results = (
            result.get("recon_results") or {}
        )

    # --------------------------------------------------------
    # Scan
    # --------------------------------------------------------

    if "scan_results" in result:
        audit.scan_results = (
            result.get("scan_results") or {}
        )

    # --------------------------------------------------------
    # Findings / Triage
    # --------------------------------------------------------

    findings_rows: list[models.Finding] = []

    if "triaged_findings" in result:
        findings_rows = _persist_findings(
            db,
            audit,
            result.get("triaged_findings") or [],
        )

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    if "report" in result:
        audit.report = (
            result.get("report") or {}
        )

        report = result.get("report") or {}

        if "global_score" in report:
            audit.global_score = report["global_score"]

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    result_status = result.get("status")

    if result_status:
        audit.status = models.AuditStatus(
            result_status
        )

    # --------------------------------------------------------
    # Completion
    # --------------------------------------------------------

    if result_status == "completed":
        completed_at = result.get("completed_at")

        if completed_at:
            audit.completed_at = datetime.fromisoformat(
                completed_at
            )
        elif audit.completed_at is None:
            audit.completed_at = datetime.now(
                timezone.utc
            )

    return findings_rows


def _build_scan_state(
    audit: models.Audit,
    verification_method: str,
) -> dict:
    """
    Reconstruit un AuditState à partir de la DB pour reprendre
    le pipeline au stage `scan`.

    La DB permet ici de franchir la frontière entre deux requêtes HTTP.
    """

    findings = [
        _finding_to_dict(finding)
        for finding in audit.findings
    ]

    return {
        "audit_id": audit.id,
        "domain": audit.domain,
        "client_id": audit.client_id,
        "verification_method": verification_method,
        "stage": "scan",
        "status": "verified",
        "verified": True,
        "error": None,
        "recon_results": audit.recon_results or {},
        "scan_results": audit.scan_results or {},
        "triaged_findings": findings,
        "report": audit.report or {},
    }


def _build_triage_state(
    audit: models.Audit,
    verification_method: str,
) -> dict:
    """
    Reconstruit un AuditState pour une reprise directe au stage `triage`.

    Cet endpoint est conservé pour permettre une reprise manuelle/debug,
    même si le workflow normal Scan -> Triage -> Report est désormais
    entièrement géré par l'Orchestrator.
    """

    findings = [
        _finding_to_dict(finding)
        for finding in audit.findings
    ]

    return {
        "audit_id": audit.id,
        "domain": audit.domain,
        "client_id": audit.client_id,
        "verification_method": verification_method,
        "stage": "triage",
        "status": "triaging",
        "verified": True,
        "error": None,
        "recon_results": audit.recon_results or {},
        "scan_results": audit.scan_results or {},
        "triaged_findings": findings,
        "report": audit.report or {},
    }


# ============================================================
# CREATE AUDIT
# ============================================================

@router.post(
    "/",
    response_model=AuditResponse,
    status_code=201,
)
def create_audit(
    payload: AuditCreateRequest,
    db: Session = Depends(get_db),
) -> AuditResponse:

    domain = (
        payload.domain
        .strip()
        .lower()
        .removeprefix("www.")
    )

    # --------------------------------------------------------
    # Client
    # --------------------------------------------------------

    client = (
        db.query(models.Client)
        .filter_by(name=payload.client_name)
        .first()
    )

    if client is None:
        client = models.Client(
            name=payload.client_name
        )

        db.add(client)
        db.flush()

    # --------------------------------------------------------
    # Audit
    # --------------------------------------------------------

    audit = models.Audit(
        client_id=client.id,
        domain=domain,
        status=models.AuditStatus.pending,
    )

    db.add(audit)
    db.flush()

    # --------------------------------------------------------
    # Orchestrator
    # --------------------------------------------------------

    result = _orchestrator.invoke(
        {
            "audit_id": audit.id,
            "domain": domain,
            "client_id": client.id,
            "verification_method": (
                payload.verification_method
            ),
            "stage": "recon",
            "status": "pending",
            "verified": False,
            "error": None,
            "recon_results": {},
            "scan_results": {},
            "triaged_findings": [],
            "report": {},
        }
    )

    # --------------------------------------------------------
    # Recon failed
    # --------------------------------------------------------

    if (
        result.get("status") == "failed"
        or "verification" not in result
    ):
        audit.status = models.AuditStatus.failed

        db.commit()

        detail = (
            result.get("error")
            or "Erreur inconnue pendant la collecte recon"
        )

        raise HTTPException(
            status_code=502,
            detail=f"Échec de la collecte : {detail}",
        )

    # --------------------------------------------------------
    # Verification token
    # --------------------------------------------------------

    verification_data = result["verification"]

    token_row = models.VerificationToken(
        domain=domain,
        token=verification_data["token"],
        method=models.VerificationMethod(
            verification_data["method"]
        ),
        status=models.VerificationStatus.pending,
        expires_at=(
            datetime.now(timezone.utc)
            + timedelta(hours=TOKEN_TTL_HOURS)
        ),
    )

    db.add(token_row)
    db.flush()

    # --------------------------------------------------------
    # Persist Recon result
    # --------------------------------------------------------

    audit.recon_results = (
        result.get("recon_results") or {}
    )

    audit.status = models.AuditStatus.recon_only

    audit.verification_token_id = token_row.id

    db.commit()
    db.refresh(audit)

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return AuditResponse(
        id=audit.id,
        domain=audit.domain,
        status=audit.status.value,
        recon_results=audit.recon_results,
        verification=VerificationInfoResponse(
            method=token_row.method.value,
            instructions=verification_data["instructions"],
            status=token_row.status.value,
        ),
        started_at=audit.started_at,
        completed_at=audit.completed_at,
    )


# ============================================================
# SCAN
# ============================================================

@router.post(
    "/{audit_id}/scan",
    response_model=AuditResponse,
)
def launch_scan(
    audit_id: str,
    db: Session = Depends(get_db),
) -> AuditResponse:

    audit = db.get(
        models.Audit,
        audit_id,
    )

    if audit is None:
        raise HTTPException(
            status_code=404,
            detail="Audit introuvable",
        )

    # --------------------------------------------------------
    # Verification obligatoire
    # --------------------------------------------------------

    if audit.status != models.AuditStatus.verified:
        raise HTTPException(
            status_code=409,
            detail=(
                "L'audit doit être au statut 'verified' "
                "pour lancer le scan "
                f"(statut actuel : {audit.status.value})."
            ),
        )

    # --------------------------------------------------------
    # Verification token
    # --------------------------------------------------------

    token_row = None

    if audit.verification_token_id:
        token_row = db.get(
            models.VerificationToken,
            audit.verification_token_id,
        )

    verification_method = (
        token_row.method.value
        if token_row is not None
        else "dns_txt"
    )

    # --------------------------------------------------------
    # Marque l'audit comme scanning avant le travail actif
    # --------------------------------------------------------

    audit.status = models.AuditStatus.scanning

    db.commit()

    # --------------------------------------------------------
    # Reconstruit l'état et reprend au stage scan
    # --------------------------------------------------------

    state = _build_scan_state(
        audit,
        verification_method,
    )

    result = _orchestrator.invoke(
        state
    )

    # --------------------------------------------------------
    # Pipeline failed
    # --------------------------------------------------------

    if result.get("status") == "failed":

        audit.status = models.AuditStatus.failed

        db.commit()

        detail = (
            result.get("error")
            or "Erreur inconnue pendant le pipeline"
        )

        raise HTTPException(
            status_code=502,
            detail=f"Échec du pipeline : {detail}",
        )

    # --------------------------------------------------------
    # Persist Scan + Triage + Report
    # --------------------------------------------------------

    findings_rows = _persist_orchestrator_result(
        db,
        audit,
        result,
    )

    db.commit()
    db.refresh(audit)

    for finding in findings_rows:
        db.refresh(finding)

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return AuditResponse(
        id=audit.id,
        domain=audit.domain,
        status=audit.status.value,
        recon_results=audit.recon_results,
        scan_results=audit.scan_results,
        findings=[
            FindingResponse.model_validate(finding)
            for finding in findings_rows
        ]
        if findings_rows
        else None,
        verification=None,
        started_at=audit.started_at,
        completed_at=audit.completed_at,
    )


# ============================================================
# TRIAGE
# ============================================================

@router.post(
    "/{audit_id}/triage",
    response_model=AuditResponse,
)
def launch_triage(
    audit_id: str,
    db: Session = Depends(get_db),
) -> AuditResponse:

    audit = db.get(
        models.Audit,
        audit_id,
    )

    if audit is None:
        raise HTTPException(
            status_code=404,
            detail="Audit introuvable",
        )

    if audit.status != models.AuditStatus.triaging:
        raise HTTPException(
            status_code=409,
            detail=(
                "L'audit doit être au statut 'triaging' "
                "pour lancer le triage "
                f"(statut actuel : {audit.status.value})."
            ),
        )

    if not audit.scan_results:
        raise HTTPException(
            status_code=409,
            detail=(
                "Aucun résultat de scan disponible "
                "pour cet audit."
            ),
        )

    # --------------------------------------------------------
    # Verification token
    # --------------------------------------------------------

    token_row = None

    if audit.verification_token_id:
        token_row = db.get(
            models.VerificationToken,
            audit.verification_token_id,
        )

    verification_method = (
        token_row.method.value
        if token_row is not None
        else "dns_txt"
    )

    # --------------------------------------------------------
    # Reprise du pipeline au stage triage
    # --------------------------------------------------------

    state = _build_triage_state(
        audit,
        verification_method,
    )

    result = _orchestrator.invoke(
        state
    )

    # --------------------------------------------------------
    # Pipeline failed
    # --------------------------------------------------------

    if result.get("status") == "failed":

        audit.status = models.AuditStatus.failed

        db.commit()

        detail = (
            result.get("error")
            or "Erreur inconnue pendant le triage"
        )

        raise HTTPException(
            status_code=502,
            detail=f"Échec du pipeline : {detail}",
        )

    # --------------------------------------------------------
    # Persist Triage + Report
    # --------------------------------------------------------

    findings_rows = _persist_orchestrator_result(
        db,
        audit,
        result,
    )

    db.commit()
    db.refresh(audit)

    for finding in findings_rows:
        db.refresh(finding)

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return AuditResponse(
        id=audit.id,
        domain=audit.domain,
        status=audit.status.value,
        recon_results=audit.recon_results,
        scan_results=audit.scan_results,
        findings=[
            FindingResponse.model_validate(finding)
            for finding in findings_rows
        ]
        if findings_rows
        else None,
        verification=None,
        started_at=audit.started_at,
        completed_at=audit.completed_at,
    )


# ============================================================
# GET AUDIT
# ============================================================

@router.get(
    "/{audit_id}",
    response_model=AuditResponse,
)
def get_audit(
    audit_id: str,
    db: Session = Depends(get_db),
) -> AuditResponse:

    audit = db.get(
        models.Audit,
        audit_id,
    )

    if audit is None:
        raise HTTPException(
            status_code=404,
            detail="Audit introuvable",
        )

    # --------------------------------------------------------
    # Verification
    # --------------------------------------------------------

    verification = None

    if audit.verification_token_id:

        token_row = db.get(
            models.VerificationToken,
            audit.verification_token_id,
        )

        if token_row is not None:
            verification = VerificationInfoResponse(
                method=token_row.method.value,

                # Les instructions ne sont pas régénérées
                # après création de l'audit.
                instructions="",

                status=token_row.status.value,
            )

    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    findings = (
        db.query(models.Finding)
        .filter_by(audit_id=audit.id)
        .all()
    )

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return AuditResponse(
        id=audit.id,
        domain=audit.domain,
        status=audit.status.value,
        recon_results=audit.recon_results,
        scan_results=audit.scan_results,
        findings=[
            FindingResponse.model_validate(finding)
            for finding in findings
        ]
        if findings
        else None,
        verification=verification,
        started_at=audit.started_at,
        completed_at=audit.completed_at,
    )