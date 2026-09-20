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

from langgraph.graph import END, StateGraph

from app.agents.recon.tools import run_passive_recon
from app.agents.state import AuditState

logger = logging.getLogger(__name__)

TOKEN_PREFIX = "auditshield-verify"


def _generate_token() -> str:
    """Génère un token unique et suffisamment long pour ne pas être devinable."""
    return f"{TOKEN_PREFIX}={secrets.token_hex(16)}"


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
    """Génère le token de vérification et les instructions de dépôt.

    Une seule méthode est proposée ici par défaut (DNS TXT) ; l'API peut
    exposer l'alternative .well-known en présentant les deux formats de
    preuve au client à partir du même token.
    """
    if state.get("status") == "failed":
        # Recon a échoué : inutile de proposer une vérification pour rien
        return state

    domain = state["domain"]
    token = _generate_token()

    verification: dict = {
        "token": token,
        "method": "dns_txt",
        "instructions": (
            f"Ajoutez un enregistrement TXT sur _auditshield-verify.{domain} "
            f"avec la valeur : {token}\n"
            f"Alternative : déposez un fichier à l'URL "
            f"https://{domain}/.well-known/auditshield-verify.txt "
            f"contenant uniquement : {token}"
        ),
        "status": "pending",
    }

    logger.info("ReconAgent : token de vérification généré pour %s", domain)
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