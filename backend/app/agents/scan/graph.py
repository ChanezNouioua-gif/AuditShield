"""
Sous-graphe LangGraph du ScanAgent.

Le scan actif est protégé par trois barrières :

1. l'orchestrateur ne route vers ScanAgent qu'après vérification ;
2. ce sous-graphe vérifie lui-même state["verified"] ;
3. run_active_scan exige explicitement authorized=True.

Le ScanAgent ne peut donc pas être lancé simplement parce qu'un domaine
existe dans l'état.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph

from app.agents.scan.tools import UnauthorizedScanError, run_active_scan
from app.agents.state import AuditState

logger = logging.getLogger(__name__)


def run_scan_node(state: AuditState) -> AuditState:
    domain = state["domain"]

    # Barrière n°2 : vérification présente dans l'état
    if not state.get("verified"):
        logger.error(
            "ScanAgent : tentative de scan sans vérification confirmée "
            "pour %s — refusé",
            domain,
        )

        return {
            **state,
            "scan_results": {},
            "status": "failed",
            "stage": "failed",
            "error": (
                "Scan refusé : vérification de propriété "
                "non confirmée."
            ),
        }

    logger.info(
        "ScanAgent : démarrage du scan actif pour %s",
        domain,
    )

    try:
        # Barrière n°3 : autorisation explicite exigée par tools.py
        results = run_active_scan(
            domain,
            authorized=True,
        )

    except UnauthorizedScanError as exc:
        logger.error(
            "ScanAgent : refus interne pour %s : %s",
            domain,
            exc,
        )

        return {
            **state,
            "scan_results": {},
            "status": "failed",
            "stage": "failed",
            "error": str(exc),
        }

    except Exception as exc:
        logger.error(
            "ScanAgent : échec scan pour %s : %s",
            domain,
            exc,
        )

        return {
            **state,
            "scan_results": {},
            "status": "failed",
            "stage": "failed",
            "error": str(exc),
        }

    open_count = len(
        results.get("ports", {}).get("open_ports", [])
    )

    logger.info(
        "ScanAgent : %d port(s) ouvert(s) trouvé(s) pour %s",
        open_count,
        domain,
    )

    return {
        **state,
        "scan_results": results,
        "status": "triaging",
        "stage": "triage",
        "error": None,
    }


def build_scan_graph():
    """Compile le sous-graphe ScanAgent."""

    graph = StateGraph(AuditState)

    graph.add_node(
        "run_scan",
        run_scan_node,
    )

    graph.set_entry_point("run_scan")

    graph.add_edge(
        "run_scan",
        END,
    )

    return graph.compile()