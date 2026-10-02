"""
Route de vérification de propriété du domaine.

GET /verify/{audit_id}/check
    -> vérifie une fois si le token est correctement déposé
       (DNS TXT ou .well-known).

    -> si la vérification réussit :
         VerificationToken -> verified
         Audit             -> verified

    -> le scan actif n'est PAS lancé ici.

Le client peut appeler cette route autant de fois qu'il le souhaite
tant que le token n'est pas expiré.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core import models
from app.core.schemas import VerificationCheckResponse
from app.services.verification_service import (
    check_domain_ownership,
    is_expired,
)

router = APIRouter()


@router.get(
    "/{audit_id}/check",
    response_model=VerificationCheckResponse,
)
def check_verification(
    audit_id: str,
    db: Session = Depends(get_db),
) -> VerificationCheckResponse:

    # ========================================================
    # Récupération de l'audit
    # ========================================================

    audit = db.get(
        models.Audit,
        audit_id,
    )

    if audit is None:
        raise HTTPException(
            status_code=404,
            detail="Audit introuvable",
        )

    # ========================================================
    # Récupération du token
    # ========================================================

    if audit.verification_token_id is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "Aucune vérification en attente "
                "pour cet audit"
            ),
        )

    token_row = db.get(
        models.VerificationToken,
        audit.verification_token_id,
    )

    if token_row is None:
        raise HTTPException(
            status_code=404,
            detail="Token de vérification introuvable",
        )

    # ========================================================
    # Déjà vérifié
    # ========================================================

    if (
        token_row.status
        == models.VerificationStatus.verified
    ):
        return VerificationCheckResponse(
            audit_id=audit.id,
            domain=audit.domain,
            method=token_row.method.value,
            status=token_row.status.value,
            verified=True,
            message="Domaine déjà vérifié.",
        )

    # ========================================================
    # Token expiré
    # ========================================================

    if is_expired(token_row.expires_at):

        token_row.status = (
            models.VerificationStatus.expired
        )

        db.commit()

        return VerificationCheckResponse(
            audit_id=audit.id,
            domain=audit.domain,
            method=token_row.method.value,
            status=token_row.status.value,
            verified=False,
            message=(
                "Le token a expiré. "
                "Relancez un audit pour en obtenir un nouveau."
            ),
        )

    # ========================================================
    # Vérification de propriété
    # ========================================================

    verified = check_domain_ownership(
        audit.domain,
        token_row.token,
        token_row.method.value,
    )

    # ========================================================
    # Vérification échouée
    # ========================================================

    if not verified:

        if (
            token_row.method
            == models.VerificationMethod.dns_txt
        ):
            method_label = "l'enregistrement TXT"
        else:
            method_label = "le fichier .well-known"

        return VerificationCheckResponse(
            audit_id=audit.id,
            domain=audit.domain,
            method=token_row.method.value,
            status=token_row.status.value,
            verified=False,
            message=(
                "Vérification échouée : "
                f"{method_label} n'est pas encore détecté. "
                "Réessayez une fois configuré."
            ),
        )

    # ========================================================
    # Vérification réussie
    # ========================================================

    token_row.status = (
        models.VerificationStatus.verified
    )

    token_row.verified_at = datetime.now(
        timezone.utc
    )

    # IMPORTANT :
    # on ne lance PAS le scan ici.
    #
    # On indique seulement que l'audit est maintenant
    # autorisé à effectuer le scan actif.
    audit.status = models.AuditStatus.verified

    db.commit()

    # ========================================================
    # Réponse
    # ========================================================

    return VerificationCheckResponse(
        audit_id=audit.id,
        domain=audit.domain,
        method=token_row.method.value,
        status=token_row.status.value,
        verified=True,
        message=(
            "Domaine vérifié avec succès. "
            "L'audit est prêt pour le scan actif."
        ),
    )