from fastapi import FastAPI
from app.api.routes import audits, verification, reports

app = FastAPI(title="AuditShield API")
app.include_router(audits.router, prefix="/audits", tags=["audits"])
app.include_router(verification.router, prefix="/verify", tags=["verification"])
app.include_router(reports.router, prefix="/reports", tags=["reports"])

@app.get("/health")
def health():
    return {"status": "ok"}


from app.core.db import Base, engine
from app.core import models  # noqa: F401  (indispensable : enregistre les modèles sur Base)

Base.metadata.create_all(bind=engine)