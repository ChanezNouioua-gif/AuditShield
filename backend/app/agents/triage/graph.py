"""
Sous-graphe LangGraph du TriageAgent.

Le TriageAgent prend les résultats du ScanAgent et applique le retrieval
CVE afin d'identifier et prioriser les vulnérabilités pertinentes.

Il ne termine pas l'audit : il transmet ensuite le contrôle au ReportAgent.
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
        logger.error(
            "TriageAgent : aucun résultat de scan disponible"
        )

        return {
            **state,
            "triaged_findings": [],
            "status": "failed",
            "stage": "failed",
            "error": (
                "Triage impossible : aucun résultat "
                "de scan en entrée."
            ),
        }

    try:
        findings = triage_scan_results(
            scan_results
        )

    except Exception as exc:
        logger.error(
            "TriageAgent : échec du triage : %s",
            exc,
        )

        return {
            **state,
            "triaged_findings": [],
            "status": "failed",
            "stage": "failed",
            "error": str(exc),
        }

    confirmed_count = sum(
        1
        for finding in findings
        if finding.get("confidence") == "confirmed"
    )

    logger.info(
        "TriageAgent : %d finding(s) généré(s), "
        "dont %d confirmé(s)",
        len(findings),
        confirmed_count,
    )

    return {
        **state,
        "triaged_findings": findings,
        "status": "triaging",
        "stage": "report",
        "error": None,
    }


def build_triage_graph():
    """Compile le sous-graphe TriageAgent."""

    graph = StateGraph(AuditState)

    graph.add_node(
        "run_triage",
        run_triage_node,
    )

    graph.set_entry_point(
        "run_triage"
    )

    graph.add_edge(
        "run_triage",
        END,
    )

    return graph.compile()