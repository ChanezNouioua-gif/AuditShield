from langgraph.graph import StateGraph, END
from app.agents.state import AuditState
from app.agents.recon.graph import build_recon_graph
from app.agents.scan.graph import build_scan_graph
from app.agents.triage.graph import build_triage_graph
from app.agents.report.graph import build_report_graph

def route_after_recon(state: AuditState) -> str:
    return "scan" if state["verified"] else END

def build_orchestrator():
    graph = StateGraph(AuditState)
    graph.add_node("recon", build_recon_graph())
    graph.add_node("scan", build_scan_graph())
    graph.add_node("triage", build_triage_graph())
    graph.add_node("report", build_report_graph())

    graph.set_entry_point("recon")
    graph.add_conditional_edges("recon", route_after_recon, {"scan": "scan", END: END})
    graph.add_edge("scan", "triage")
    graph.add_edge("triage", "report")
    graph.add_edge("report", END)
    return graph.compile()