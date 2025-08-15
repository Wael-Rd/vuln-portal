import asyncio
from typing import List
from sqlmodel import Session
from app.models import Vulnerability
from app.ingestion.nvd_client import fetch_recent_cves, parse_vulnerability
from app.ingestion.cisa_kev import fetch_kev_cves
from app.ingestion.epss_client import fetch_epss_scores
from app.config import settings


async def ingest_once(session: Session):
    # Fetch sources concurrently
    nvd_task = asyncio.create_task(fetch_recent_cves(settings.nvd_lookback_days, settings.nvd_api_key))
    kev_task = asyncio.create_task(fetch_kev_cves())

    nvd_items, kev_set = await asyncio.gather(nvd_task, kev_task)

    # Parse and upsert NVD items
    upserted_cves: List[str] = []
    for item in nvd_items:
        parsed = parse_vulnerability(item)
        cve_id = parsed.get("cve_id")
        if not cve_id:
            continue

        v = session.get(Vulnerability, cve_id)
        if not v:
            v = Vulnerability(**parsed)
            session.add(v)
        else:
            for k, val in parsed.items():
                setattr(v, k, val)

        # KEV mark
        v.exploited = v.exploited or (cve_id in kev_set)

        upserted_cves.append(cve_id)

    session.commit()

    # EPSS enrichment for upserted CVEs
    try:
        epss_map = await fetch_epss_scores(upserted_cves)
        if epss_map:
            for cve in upserted_cves:
                if cve in epss_map:
                    v = session.get(Vulnerability, cve)
                    if v:
                        v.epss_score = epss_map[cve]
            session.commit()
    except Exception:
        # non-fatal
        pass

    return {"nvd_upserted": len(upserted_cves), "kev_count": len(kev_set), "epss_enriched": len(epss_map) if 'epss_map' in locals() else 0}