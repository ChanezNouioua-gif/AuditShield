"""
Routes de gestion des audits.

POST /audits    -> crée l'audit et exécute immédiatement la collecte passive
                   (ReconAgent). L'audit reste en `recon_only` tant que la
                   vérification de propriété n'a pas abouti (voir verification.py).
GET  /audits/{id} -> relit l'état courant d'un audit.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from fastapi.responses import Response

from app.agents.recon.graph import build_recon_graph
from app.agents.report.graph import build_report_graph
from app.agents.report.tools import export_findings_excel
from app.agents.scan.graph import build_scan_graph
from app.agents.triage.graph import build_triage_graph
from app.api.deps import get_db
from app.core import models
from app.core.schemas import AuditCreateRequest, AuditResponse, FindingResponse, VerificationInfoResponse

router = APIRouter()


def _finding_to_dict(finding: models.Finding) -> dict:
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


# Compilés une seule fois au chargement du module — pas à chaque requête.
_recon_graph = build_recon_graph()
_scan_graph = build_scan_graph()
_triage_graph = build_triage_graph()
_report_graph = build_report_graph()

TOKEN_TTL_HOURS = 72


@router.post("/", response_model=AuditResponse, status_code=201)
def create_audit(payload: AuditCreateRequest, db: Session = Depends(get_db)) -> AuditResponse:
    domain = payload.domain.strip().lower().removeprefix("www.")

    # Réutilise le client s'il existe déjà, pour que ses audits s'accumulent
    # dans le temps plutôt que de créer un nouveau client à chaque appel.
    client = db.query(models.Client).filter_by(name=payload.client_name).first()
    if client is None:
        client = models.Client(name=payload.client_name)
        db.add(client)
        db.flush()  # obtient client.id sans committer la transaction

    audit = models.Audit(client_id=client.id, domain=domain, status=models.AuditStatus.pending)
    db.add(audit)
    db.flush()

    result = _recon_graph.invoke({
        "audit_id": audit.id,
        "domain": domain,
        "verification_method": payload.verification_method,
    })

    if result.get("status") == "failed" or "verification" not in result:
        audit.status = models.AuditStatus.failed
        db.commit()
        detail = result.get("error") or "Erreur inconnue pendant la collecte recon"
        raise HTTPException(status_code=502, detail=f"Échec de la collecte : {detail}")

    verification_data = result["verification"]
    token_row = models.VerificationToken(
        domain=domain,
        token=verification_data["token"],
        method=models.VerificationMethod(verification_data["method"]),
        status=models.VerificationStatus.pending,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS),
    )
    db.add(token_row)
    db.flush()

    audit.recon_results = result["recon_results"]
    audit.status = models.AuditStatus.recon_only
    audit.verification_token_id = token_row.id
    db.commit()
    db.refresh(audit)

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


@router.post("/{audit_id}/scan", response_model=AuditResponse)
def launch_scan(audit_id: str, db: Session = Depends(get_db)) -> AuditResponse:
    audit = db.get(models.Audit, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit introuvable")

    # La vérité vient de la base, jamais d'un booléen porté d'un appel HTTP à
    # l'autre : c'est le statut `verified`, écrit par verification.py après un
    # contrôle DNS/well-known réussi, qui autorise le scan actif.
    if audit.status != models.AuditStatus.verified:
        raise HTTPException(
            status_code=409,
            detail=f"L'audit doit être au statut 'verified' pour lancer le scan (statut actuel : {audit.status.value}).",
        )

    result = _scan_graph.invoke({"domain": audit.domain, "verified": True})

    if result.get("status") == "failed" or "scan_results" not in result:
        audit.status = models.AuditStatus.failed
        db.commit()
        detail = result.get("error") or "Erreur inconnue pendant le scan actif"
        raise HTTPException(status_code=502, detail=f"Échec du scan : {detail}")

    audit.scan_results = result["scan_results"]
    audit.status = models.AuditStatus.triaging
    db.commit()
    db.refresh(audit)

    return AuditResponse(
        id=audit.id,
        domain=audit.domain,
        status=audit.status.value,
        recon_results=audit.recon_results,
        scan_results=audit.scan_results,
        verification=None,
        started_at=audit.started_at,
        completed_at=audit.completed_at,
    )


@router.post("/{audit_id}/triage", response_model=AuditResponse)
def launch_triage(audit_id: str, db: Session = Depends(get_db)) -> AuditResponse:
    audit = db.get(models.Audit, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit introuvable")

    if audit.status != models.AuditStatus.triaging:
        raise HTTPException(
            status_code=409,
            detail=f"L'audit doit être au statut 'triaging' pour lancer le triage (statut actuel : {audit.status.value}).",
        )

    if not audit.scan_results:
        raise HTTPException(status_code=409, detail="Aucun résultat de scan disponible pour cet audit.")

    result = _triage_graph.invoke({"domain": audit.domain, "scan_results": audit.scan_results})

    if result.get("status") == "failed" or "triaged_findings" not in result:
        audit.status = models.AuditStatus.failed
        db.commit()
        detail = result.get("error") or "Erreur inconnue pendant le triage"
        raise HTTPException(status_code=502, detail=f"Échec du triage : {detail}")

    # Supprime d'éventuels findings d'un triage précédent sur ce même audit,
    # pour que relancer l'endpoint soit idempotent plutôt que d'accumuler des doublons.
    db.query(models.Finding).filter_by(audit_id=audit.id).delete()

    findings_rows: list[models.Finding] = []
    for item in result["triaged_findings"]:
        finding = models.Finding(
            audit_id=audit.id,
            category=item["category"],
            title=item["title"],
            description=item.get("description"),
            severity=item.get("severity"),
            business_priority=item.get("business_priority"),
            confidence=models.Confidence(item["confidence"]),
            cve_id=item.get("cve_id"),
            evidence=item.get("evidence"),
            remediation=item.get("remediation"),
        )
        db.add(finding)
        findings_rows.append(finding)

    # Statut inchangé (`triaging`) : il n'y a pas encore de palier dédié entre
    # triage et rapport — c'est ReportAgent qui fera passer l'audit à `completed`.
    db.commit()
    db.refresh(audit)
    for f in findings_rows:
        db.refresh(f)

    return AuditResponse(
        id=audit.id,
        domain=audit.domain,
        status=audit.status.value,
        recon_results=audit.recon_results,
        scan_results=audit.scan_results,
        findings=[FindingResponse.model_validate(f) for f in findings_rows],
        verification=None,
        started_at=audit.started_at,
        completed_at=audit.completed_at,
    )


@router.get("/{audit_id}", response_model=AuditResponse)
def get_audit(audit_id: str, db: Session = Depends(get_db)) -> AuditResponse:
    audit = db.get(models.Audit, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit introuvable")

    verification = None
    if audit.verification_token_id:
        token_row = db.get(models.VerificationToken, audit.verification_token_id)
        if token_row is not None:
            verification = VerificationInfoResponse(
                method=token_row.method.value,
                # Les instructions ne sont pas ré-générées après coup : le
                # client les a déjà reçues à la création de l'audit.
                instructions="",
                status=token_row.status.value,
            )

    findings = db.query(models.Finding).filter_by(audit_id=audit.id).all()

    return AuditResponse(
        id=audit.id,
        domain=audit.domain,
        status=audit.status.value,
        recon_results=audit.recon_results,
        scan_results=audit.scan_results,
        findings=[FindingResponse.model_validate(f) for f in findings] if findings else None,
        verification=verification,
        started_at=audit.started_at,
        completed_at=audit.completed_at,
    )