"""
État partagé et total du pipeline d'audit.

AuditState est le contrat unique entre l'orchestrateur et les sous-graphes.
Chaque étape écrit son résultat dans sa propre section et met à jour
le stage/status du pipeline.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict


AuditStatus = Literal[
    "pending",
    "recon_only",
    "verified",
    "scanning",
    "triaging",
    "completed",
    "failed",
]


AuditStage = Literal[
    "recon",
    "verification_pending",
    "scan",
    "triage",
    "report",
    "completed",
    "failed",
]


class VerificationInfo(TypedDict, total=False):
    token: str
    method: Literal["dns_txt", "well_known"]
    instructions: str
    status: Literal["pending", "verified", "expired"]
    verified_at: str


class AuditState(TypedDict, total=False):
    # ============================================================
    # IDENTITÉ / ENTRÉE
    # ============================================================

    audit_id: str
    domain: str
    client_id: str

    verification_method: Literal[
        "dns_txt",
        "well_known",
    ]

    # ============================================================
    # CONTRÔLE DU WORKFLOW
    # ============================================================

    stage: AuditStage
    status: AuditStatus

    # True uniquement après vérification effective de propriété.
    verified: bool

    # Dernière erreur rencontrée dans le pipeline.
    error: str | None

    # ============================================================
    # VÉRIFICATION DE PROPRIÉTÉ
    # ============================================================

    verification: VerificationInfo

    # ============================================================
    # RÉSULTATS DES AGENTS
    # ============================================================

    # ReconAgent
    recon_results: dict[str, Any]

    # ScanAgent
    scan_results: dict[str, Any]

    # TriageAgent
    triaged_findings: list[dict[str, Any]]

    # ReportAgent
    report: dict[str, Any]

    # ============================================================
    # MÉTADONNÉES D'EXÉCUTION
    # ============================================================

    started_at: str | None
    completed_at: str | None