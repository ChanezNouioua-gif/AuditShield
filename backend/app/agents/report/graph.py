"""
Sous-graphe LangGraph du ReportAgent.

Dernière étape du pipeline :

Recon
  ↓
Verification
  ↓
Scan
  ↓
Triage
  ↓
Report
  ↓
Completed
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from langgraph.graph import END, StateGraph

from app.agents.report.tools import generate_report
from app.agents.state import AuditState

logger = logging.getLogger(__name__)


def run_report_node(state: AuditState) -> AuditState:
    audit_id = state["audit_id"]
    domain = state["domain"]

    logger.info(
        "ReportAgent : génération du rapport pour %s",
        domain,
    )

    try:
        report = generate_report(
            audit_id=audit_id,
            domain=domain,
            findings=state.get("triaged_findings") or [],
            scan_results=state.get("scan_results") or {},
            recon_results=state.get("recon_results") or {},
        )

    except Exception as exc:
        logger.error(
            "ReportAgent : échec génération rapport pour %s : %s",
            domain,
            exc,
        )

        return {
            **state,
            "report": {},
            "status": "failed",
            "stage": "failed",
            "error": str(exc),
        }

    completed_at = datetime.now(
        timezone.utc
    ).isoformat()

    logger.info(
        "ReportAgent : rapport généré pour %s, "
        "score global %s",
        domain,
        report["global_score"],
    )

    return {
        **state,
        "report": report,
        "global_score": report.get("global_score"),
        "category_scores": report.get(
            "category_scores",
            {},
        ),
        "status": "completed",
        "stage": "completed",
        "completed_at": completed_at,
        "error": None,
    }


def build_report_graph():
    """Compile le sous-graphe ReportAgent."""

    graph = StateGraph(AuditState)

    graph.add_node(
        "run_report",
        run_report_node,
    )

    graph.set_entry_point(
        "run_report"
    )

    graph.add_edge(
        "run_report",
        END,
    )

    return graph.compile()