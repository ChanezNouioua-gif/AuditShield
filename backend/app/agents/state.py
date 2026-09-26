"""
État partagé du pipeline d'audit.

Cet objet est le seul canal de communication entre les sous-graphes
(ReconAgent, ScanAgent, TriageAgent, ReportAgent). Chaque node lit ce dont
il a besoin et écrit ses résultats dans sa propre clé — jamais dans celle
d'un autre agent, pour garder une frontière claire entre les étapes.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

AuditStatus = Literal[
    "pending", "recon_only", "scanning", "triaging", "completed", "failed",
]


class VerificationInfo(TypedDict, total=False):
    token: str
    method: Literal["dns_txt", "well_known"]
    instructions: str
    status: Literal["pending", "verified", "expired"]


class AuditState(TypedDict, total=False):
    # Entrée
    audit_id: str
    domain: str
    # Choix du client, transmis par l'API lors de la création de l'audit.
    # Si absent, le node de vérification retombe sur "dns_txt" par défaut.
    verification_method: Literal["dns_txt", "well_known"]

    # Sortie ReconAgent
    recon_results: dict[str, Any]

    # Vérification de propriété (garde-fou avant ScanAgent)
    verification: VerificationInfo
    verified: bool

    # Sortie ScanAgent
    scan_results: dict[str, Any]

    # Sortie TriageAgent
    triaged_findings: list[dict[str, Any]]

    # Sortie ReportAgent
    report: dict[str, Any]

    # Statut global et traçabilité des erreurs
    status: AuditStatus
    error: str | None