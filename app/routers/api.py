from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select
from app.database import get_session
from app.models import Vulnerability
from app.schemas import VulnerabilityOut
from app.deps import require_login

router = APIRouter(prefix="/api/v1", tags=["api"])


@router.get("/vulns", response_model=list[VulnerabilityOut])
def list_vulns(
    q: Optional[str] = Query(None),
    severity: Optional[str] = Query(None, description="CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN"),
    exploited: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    _user=Depends(require_login)
):
    stmt = select(Vulnerability)
    if q:
        stmt = stmt.where(
            (Vulnerability.cve_id.contains(q)) |
            (Vulnerability.title.contains(q)) |
            (Vulnerability.description.contains(q)) |
            (Vulnerability.vendor.contains(q)) |
            (Vulnerability.product.contains(q))
        )
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity.upper())
    if exploited is not None:
        stmt = stmt.where(Vulnerability.exploited == exploited)

    stmt = stmt.order_by(Vulnerability.published_at.desc().nulls_last()).offset(offset).limit(limit)
    rows = session.exec(stmt).all()
    return rows


@router.get("/vulns/{cve_id}", response_model=VulnerabilityOut)
def get_vuln(cve_id: str, session: Session = Depends(get_session), _user=Depends(require_login)):
    vuln = session.get(Vulnerability, cve_id)
    if not vuln:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Not found")
    return vuln