"""
Sous-graphe LangGraph du ScanAgent.

Un seul node, mais avec une garde explicite : il refuse de lancer le scan actif
si `state["verified"]` n'est pas `True`. C'est une troisième barrière, après :
  1. le paramètre `authorized=True` exigé par `run_active_scan` (tools.py)
  2. l'edge conditionnelle de l'orchestrateur, qui ne devrait router vers ce
     sous-graphe que si l'audit est au statut `verified` en base

Trois barrières pour un seul geste (le scan actif) n'est pas de la
sur-ingénierie ici : c'est le point du pipeline où une erreur signifie
toucher l'infrastructure d'un tiers sans son accord.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph

from app.agents.scan.tools import UnauthorizedScanError, run_active_scan
from app.agents.state import AuditState

logger = logging.getLogger(__name__)


def run_scan_node(state: AuditState) -> AuditState:
    domain = state["domain"]

    if not state.get("verified"):
        logger.error(
            "ScanAgent : tentative de scan sans vérification confirmée pour %s — refusé", domain,
        )
        return {
            **state,
            "scan_results": {},
            "status": "failed",
            "error": "Scan refusé : vérification de propriété non confirmée.",
        }

    logger.info("ScanAgent : démarrage scan actif pour %s", domain)

    try:
        results = run_active_scan(domain, authorized=True)
    except UnauthorizedScanError as exc:
        # Ne devrait jamais arriver si le check ci-dessus est passé, mais on
        # ne fait confiance qu'aux exceptions, pas aux suppositions.
        logger.error("ScanAgent : refus interne pour %s : %s", domain, exc)
        return {**state, "scan_results": {}, "status": "failed", "error": str(exc)}
    except Exception as exc:  # une cible injoignable ne doit pas planter le pipeline
        logger.error("ScanAgent : échec scan pour %s : %s", domain, exc)
        return {**state, "scan_results": {}, "status": "failed", "error": str(exc)}

    open_count = len(results["ports"]["open_ports"])
    logger.info("ScanAgent : %d port(s) ouvert(s) trouvé(s) pour %s", open_count, domain)

    return {**state, "scan_results": results, "status": "triaging", "error": None}


def build_scan_graph():
    """Compile le sous-graphe ScanAgent."""
    graph = StateGraph(AuditState)
    graph.add_node("run_scan", run_scan_node)
    graph.set_entry_point("run_scan")
    graph.add_edge("run_scan", END)
    return graph.compile()