from typing import TypedDict, Optional

class AuditState(TypedDict):
    domain: str
    audit_id: str
    recon_results: Optional[dict]
    verified: bool
    scan_results: Optional[dict]
    triaged_findings: Optional[list]
    report: Optional[dict]