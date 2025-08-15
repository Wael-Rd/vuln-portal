import httpx
from typing import Dict, List

EPSS_URL = "https://api.first.org/data/v1/epss"


async def fetch_epss_scores(cves: List[str]) -> Dict[str, float]:
    if not cves:
        return {}
    # Batch query up to ~1000 CVEs per request according to API guidance
    results: Dict[str, float] = {}
    async with httpx.AsyncClient(timeout=60) as client:
        batch_size = 100
        for i in range(0, len(cves), batch_size):
            batch = cves[i:i+batch_size]
            resp = await client.get(EPSS_URL, params={"cve": ",".join(batch)})
            resp.raise_for_status()
            data = resp.json()
            for row in data.get("data", []):
                cve = row.get("cve")
                score = row.get("epss")
                if cve and score is not None:
                    try:
                        results[cve] = float(score)
                    except Exception:
                        pass
    return results