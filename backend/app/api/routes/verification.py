"""
Route de vérification de propriété du domaine.

GET /verify/{audit_id}/check -> contrôle une fois si le token est bien déposé
(DNS TXT ou .well-known, selon la méthode choisie à la création de l'audit),
et fait passer l'audit de `recon_only` à `scanning` si c'est le cas.

Le client peut appeler cette route autant de fois qu'il le souhaite, le temps
de configurer son DNS ou son serveur — aucune limite de tentatives ici.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core import models
from app.core.schemas import VerificationCheckResponse
from app.services.verification_service import check_domain_ownership, is_expired

router = APIRouter()


@router.get("/{audit_id}/check", response_model=VerificationCheckResponse)
def check_verification(audit_id: str, db: Session = Depends(get_db)) -> VerificationCheckResponse:
    audit = db.get(models.Audit, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit introuvable")

    if audit.verification_token_id is None:
        raise HTTPException(status_code=409, detail="Aucune vérification en attente pour cet audit")

    token_row = db.get(models.VerificationToken, audit.verification_token_id)
    if token_row is None:
        raise HTTPException(status_code=404, detail="Token de vérification introuvable")

    # Déjà vérifié : pas besoin de recontrôler le DNS à chaque appel.
    if token_row.status == models.VerificationStatus.verified:
        return VerificationCheckResponse(
            audit_id=audit.id,
            domain=audit.domain,
            method=token_row.method.value,
            status=token_row.status.value,
            verified=True,
            message="Domaine déjà vérifié.",
        )

    if is_expired(token_row.expires_at):
        token_row.status = models.VerificationStatus.expired
        db.commit()
        return VerificationCheckResponse(
            audit_id=audit.id,
            domain=audit.domain,
            method=token_row.method.value,
            status=token_row.status.value,
            verified=False,
            message="Le token a expiré. Relancez un audit pour en obtenir un nouveau.",
        )

    ok = check_domain_ownership(audit.domain, token_row.token, token_row.method.value)

    if not ok:
        # On ne touche pas au statut : le client peut réessayer une fois son
        # DNS ou son fichier correctement configuré.
        method_label = "l'enregistrement TXT" if token_row.method == models.VerificationMethod.dns_txt else "le fichier .well-known"
        return VerificationCheckResponse(
            audit_id=audit.id,
            domain=audit.domain,
            method=token_row.method.value,
            status=token_row.status.value,
            verified=False,
            message=f"Vérification échouée : {method_label} n'est pas (encore) détecté. Réessayez une fois configuré.",
        )

    token_row.status = models.VerificationStatus.verified
    token_row.verified_at = datetime.now(timezone.utc)

    # L'audit est prêt pour le scan actif, mais celui-ci n'a pas encore démarré :
    # c'est orchestrator.py (ou un endpoint dédié) qui déclenchera ScanAgent et
    # fera passer le statut à `scanning` à ce moment-là, pas ici.
    audit.status = models.AuditStatus.verified
    db.commit()

    return VerificationCheckResponse(
        audit_id=audit.id,
        domain=audit.domain,
        method=token_row.method.value,
        status=token_row.status.value,
        verified=True,
        message="Domaine vérifié avec succès. L'audit est prêt pour le scan actif.",
    )