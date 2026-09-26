"""
Sous-graphe LangGraph du ReconAgent.

Deux nodes séquentiels :
  1. run_recon        -> exécute la collecte passive (crt.sh, DNS, email, WHOIS)
  2. request_verification -> génère le token que le client doit poser en DNS TXT
                              ou dans un fichier .well-known avant tout accès actif

Ce sous-graphe ne touche jamais l'infrastructure du client au-delà de lectures
DNS/HTTP publiques. Le scan actif n'est débloqué qu'après vérification,
gérée par l'edge conditionnelle de l'orchestrateur (voir agents/orchestrator.py).
"""

from __future__ import annotations

import logging
import secrets
from typing import Literal

from langgraph.graph import END, StateGraph

from app.agents.recon.tools import run_passive_recon
from app.agents.state import AuditState

logger = logging.getLogger(__name__)

TOKEN_PREFIX = "auditshield-verify"
VerificationMethod = Literal["dns_txt", "well_known"]
DEFAULT_METHOD: VerificationMethod = "dns_txt"


def _generate_token() -> str:
    """Génère un token unique et suffisamment long pour ne pas être devinable."""
    return f"{TOKEN_PREFIX}={secrets.token_hex(16)}"


def _build_instructions(domain: str, token: str, method: VerificationMethod) -> str:
    """Construit l'instruction de dépôt correspondant à la méthode choisie."""
    if method == "well_known":
        return (
            f"Créez un fichier accessible à l'URL "
            f"https://{domain}/.well-known/auditshield-verify.txt "
            f"contenant uniquement : {token}"
        )
    return (
        f"Ajoutez un enregistrement TXT sur _auditshield-verify.{domain} "
        f"avec la valeur : {token}"
    )


def run_recon_node(state: AuditState) -> AuditState:
    """Exécute la collecte passive et écrit le résultat dans l'état."""
    domain = state["domain"]
    logger.info("ReconAgent : démarrage collecte passive pour %s", domain)

    try:
        results = run_passive_recon(domain)
    except Exception as exc:  # une source externe indisponible ne doit pas planter le pipeline
        logger.error("ReconAgent : échec collecte pour %s : %s", domain, exc)
        return {**state, "recon_results": {}, "status": "failed", "error": str(exc)}

    logger.info(
        "ReconAgent : %d sous-domaine(s) trouvé(s), %d anomalie(s) DNS en suspens",
        results["subdomain_count"], len(results["dangling_dns"]),
    )
    return {**state, "recon_results": results, "status": "recon_only", "error": None}


def request_verification_node(state: AuditState) -> AuditState:
    """Génère le token de vérification selon la méthode choisie par le client.

    Le choix (`verification_method`) vient de l'API, elle-même remplie par le
    client au moment de lancer l'audit. Sans choix explicite, on retombe sur
    dns_txt — c'est la méthode qui ne dépend pas d'un déploiement web actif.
    """
    if state.get("status") == "failed":
        # Recon a échoué : inutile de proposer une vérification pour rien
        return state

    domain = state["domain"]
    token = _generate_token()
    method = state.get("verification_method", DEFAULT_METHOD)

    if method not in ("dns_txt", "well_known"):
        logger.warning("Méthode de vérification inconnue (%s), retour à %s", method, DEFAULT_METHOD)
        method = DEFAULT_METHOD

    verification: dict = {
        "token": token,
        "method": method,
        "instructions": _build_instructions(domain, token, method),
        "status": "pending",
    }

    logger.info("ReconAgent : token de vérification (%s) généré pour %s", method, domain)
    return {**state, "verification": verification, "verified": False}


def build_recon_graph():
    """Compile le sous-graphe ReconAgent."""
    graph = StateGraph(AuditState)

    graph.add_node("run_recon", run_recon_node)
    graph.add_node("request_verification", request_verification_node)

    graph.set_entry_point("run_recon")
    graph.add_edge("run_recon", "request_verification")
    graph.add_edge("request_verification", END)

    return graph.compile()