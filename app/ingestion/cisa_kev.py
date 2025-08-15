import httpx
from typing import Set

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev_cves() -> Set[str]:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        # CISA uses "vulnerabilities": [ { "cveID": "...", ... }, ... ]
        out = set()
        for v in data.get("vulnerabilities", []):
            cve = v.get("cveID")
            if cve:
                out.add(cve)
        return out