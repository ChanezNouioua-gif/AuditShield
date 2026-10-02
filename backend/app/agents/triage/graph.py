"""
Sous-graphe LangGraph du TriageAgent.

Un seul node pour l'instant : il applique le retrieval CVE (agents/triage/tools.py)
sur les résultats du ScanAgent. L'étape d'explication LLM en langage clair
n'est pas encore branchée — elle viendra se greffer ici une fois qu'une vraie
clé API sera configurée, sans modifier la structure du graphe : il suffira
d'ajouter un second node entre triage et END.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph

from app.agents.state import AuditState
from app.agents.triage.tools import triage_scan_results

logger = logging.getLogger(__name__)


def run_triage_node(state: AuditState) -> AuditState:
    scan_results = state.get("scan_results")

    if not scan_results:
        logger.error("TriageAgent : aucun résultat de scan disponible, triage impossible")
        return {
            **state,
            "triaged_findings": [],
            "status": "failed",
            "error": "Triage impossible : aucun résultat de scan en entrée.",
        }

    try:
        findings = triage_scan_results(scan_results)
    except Exception as exc:  # une erreur de matching ne doit pas perdre les résultats du scan
        logger.error("TriageAgent : échec du triage : %s", exc)
        return {**state, "triaged_findings": [], "status": "failed", "error": str(exc)}

    confirmed_count = sum(1 for f in findings if f["confidence"] == "confirmed")
    logger.info(
        "TriageAgent : %d finding(s) généré(s), dont %d confirmé(s)",
        len(findings), confirmed_count,
    )

    # Pas "completed" ici : ReportAgent n'a pas encore tourné. On reste sur
    # "triaging" — c'est l'endpoint qui orchestrera l'appel à ReportAgent et
    # qui fera passer le statut à "completed" une fois le rapport généré.
    return {**state, "triaged_findings": findings, "status": "triaging", "error": None}


def build_triage_graph():
    """Compile le sous-graphe TriageAgent."""
    graph = StateGraph(AuditState)
    graph.add_node("run_triage", run_triage_node)
    graph.set_entry_point("run_triage")
    graph.add_edge("run_triage", END)
    return graph.compile()