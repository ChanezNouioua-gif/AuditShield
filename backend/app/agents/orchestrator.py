"""
Orchestrateur central du pipeline AuditShield.

Workflow :

    RECON
      ↓
    VERIFICATION_PENDING
      ↓
    SCAN
      ↓
    TRIAGE
      ↓
    REPORT
      ↓
    COMPLETED

La vérification de propriété est externe et asynchrone.

Le premier lancement s'arrête donc après ReconAgent.
Une fois le domaine vérifié, l'API reconstruit l'état et relance
l'orchestrateur à partir du stage "scan".
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from app.agents.state import AuditState

from app.agents.recon.graph import build_recon_graph
from app.agents.scan.graph import build_scan_graph
from app.agents.triage.graph import build_triage_graph
from app.agents.report.graph import build_report_graph


# ============================================================
# ROUTAGE INITIAL
# ============================================================

def route_from_dispatch(state: AuditState) -> str:
    """
    Détermine quelle étape doit être exécutée.

    Le stage est la source de vérité du workflow.
    Cela permet de reprendre un audit sans rejouer les étapes
    déjà terminées.
    """

    # --------------------------------------------------------
    # Audit déjà en erreur
    # --------------------------------------------------------

    if state.get("status") == "failed":
        return END

    if state.get("stage") == "failed":
        return END

    # --------------------------------------------------------
    # Stage courant
    # --------------------------------------------------------

    stage = state.get("stage")

    if stage is None:
      raise ValueError("AuditState invalide : stage manquant")

    # Première exécution
    if stage == "recon":
        return "recon"

    # Vérification externe encore nécessaire
    if stage == "verification_pending":
        return END

    # Domaine vérifié -> scan actif
    if stage == "scan":
        if not state.get("verified", False):
            return END

        return "scan"

    # Scan terminé
    if stage == "triage":
        return "triage"

    # Triage terminé
    if stage == "report":
        return "report"

    # Audit terminé
    if stage == "completed":
        return END

    return END


# ============================================================
# BUILD ORCHESTRATOR
# ============================================================

def build_orchestrator():
    """
    Construit l'orchestrateur principal.

    L'orchestrateur contient les sous-graphes des quatre agents,
    mais ne contient aucune logique métier propre aux agents.
    """

    graph = StateGraph(AuditState)

    # --------------------------------------------------------
    # Sous-graphes
    # --------------------------------------------------------

    graph.add_node(
        "recon",
        build_recon_graph(),
    )

    graph.add_node(
        "scan",
        build_scan_graph(),
    )

    graph.add_node(
        "triage",
        build_triage_graph(),
    )

    graph.add_node(
        "report",
        build_report_graph(),
    )

    # --------------------------------------------------------
    # Dispatcher
    # --------------------------------------------------------

    def dispatch_node(state: AuditState) -> AuditState:
        """
        Node neutre utilisé uniquement pour router l'état
        vers le bon sous-graphe.
        """

        return state

    graph.add_node(
        "dispatch",
        dispatch_node,
    )

    # START -> dispatch
    graph.add_edge(
        START,
        "dispatch",
    )

    # dispatch -> étape appropriée
    graph.add_conditional_edges(
        "dispatch",
        route_from_dispatch,
        {
            "recon": "recon",
            "scan": "scan",
            "triage": "triage",
            "report": "report",
            END: END,
        },
    )

    # --------------------------------------------------------
    # PIPELINE
    # --------------------------------------------------------

    # Recon s'arrête volontairement ici.
    #
    # Pourquoi ?
    #
    # Parce que la vérification DNS / .well-known est externe.
    # Le client doit avoir le temps de configurer son domaine.
    #
    # L'API relancera ensuite l'orchestrateur avec stage="scan".

    graph.add_edge(
        "recon",
        END,
    )

    # Scan -> Triage
    graph.add_edge(
        "scan",
        "triage",
    )

    # Triage -> Report
    graph.add_edge(
        "triage",
        "report",
    )

    # Report -> END
    graph.add_edge(
        "report",
        END,
    )

    return graph.compile()