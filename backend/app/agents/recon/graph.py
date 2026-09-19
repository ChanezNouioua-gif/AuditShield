from langgraph.graph import StateGraph, END
from app.agents.state import AuditState
from app.agents.recon.tools import fetch_crtsh, fetch_dns_records, check_dangling_dns

def recon_node(state: AuditState) -> AuditState:
    subdomains = fetch_crtsh(state["domain"])
    dns = fetch_dns_records(state["domain"])
    dangling = check_dangling_dns(dns)
    state["recon_results"] = {"subdomains": subdomains, "dns": dns, "dangling": dangling}
    return state

def build_recon_graph():
    graph = StateGraph(AuditState)
    graph.add_node("recon", recon_node)
    graph.set_entry_point("recon")
    graph.add_edge("recon", END)
    return graph.compile()