from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, select, func
from app.database import get_session
from app.models import Vulnerability
from app.deps import require_login

router = APIRouter()


@router.get("/")
def dashboard(request: Request, session: Session = Depends(get_session), _user=Depends(require_login)):
    # Counts by severity
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    counts = {}
    for sev in severities:
        counts[sev] = session.exec(select(func.count()).where(Vulnerability.severity == sev)).one()

    total = session.exec(select(func.count()).select_from(Vulnerability)).one()
    exploited_count = session.exec(select(func.count()).where(Vulnerability.exploited == True)).one()  # noqa: E712

    # Recent vulns table
    recent = session.exec(
        select(Vulnerability).order_by(Vulnerability.published_at.desc().nulls_last()).limit(100)
    ).all()

    # Trend: last 14 days
    today = datetime.utcnow().date()
    labels = []
    data = []
    for i in range(13, -1, -1):
        day = today - timedelta(days=i)
        labels.append(day.isoformat())
        start = datetime.combine(day, datetime.min.time())
        end = datetime.combine(day, datetime.max.time())
        cnt = session.exec(
            select(func.count()).where(
                Vulnerability.published_at >= start,
                Vulnerability.published_at <= end
            )
        ).one()
        data.append(cnt)

    return request.app.state.templates.TemplateResponse("dashboard.html", {
        "request": request,
        "counts": counts,
        "total": total,
        "exploited_count": exploited_count,
        "recent": recent,
        "trend_labels": labels,
        "trend_data": data,
        "username": request.session.get("username"),
    })


@router.get("/vuln/{cve_id}")
def vuln_detail(cve_id: str, request: Request, session: Session = Depends(get_session), _user=Depends(require_login)):
    vuln = session.get(Vulnerability, cve_id)
    if not vuln:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Not found")
    return request.app.state.templates.TemplateResponse("detail.html", {
        "request": request,
        "v": vuln,
        "username": request.session.get("username"),
    })