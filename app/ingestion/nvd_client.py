from datetime import datetime, timedelta, timezone
import httpx
from typing import Any, Dict, List, Optional

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _iso(dt: datetime) -> str:
    # NVD requires Zulu time with milliseconds
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        # NVD returns e.g. 2024-10-03T16:15:00.000Z
        if dt_str.endswith("Z"):
            dt_str = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(dt_str)
    except Exception:
        return None


async def fetch_recent_cves(lookback_days: int = 3, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=lookback_days)
    params = {
        "pubStartDate": _iso(start),
        "pubEndDate": _iso(now),
        "resultsPerPage": "2000",
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    out: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=60) as client:
        start_index = 0
        while True:
            local_params = params | {"startIndex": str(start_index)}
            resp = await client.get(NVD_URL, params=local_params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            items = data.get("vulnerabilities", [])
            out.extend(items)
            total = data.get("totalResults", len(out))
            if len(out) >= total:
                break
            start_index += len(items) if items else 0
            if not items:
                break
    return out


def parse_vulnerability(item: Dict[str, Any]) -> Dict[str, Any]:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    descriptions = cve.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    pub = _parse_iso(cve.get("published"))
    mod = _parse_iso(cve.get("lastModified"))

    metrics = (cve.get("metrics") or {})
    cvss_score = None
    cvss_vector = None
    severity = "UNKNOWN"
    # Prefer v31 -> v30 -> v2
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]  # take first
            cvss = m.get("cvssData", {})
            cvss_score = cvss.get("baseScore")
            cvss_vector = cvss.get("vectorString")
            severity = (m.get("baseSeverity") or cvss.get("baseSeverity") or "UNKNOWN").upper()
            break

    refs = {"urls": [r.get("url") for r in (cve.get("references") or []) if r.get("url")]}
    vendors = []
    products = []
    cwes = []
    for vendor in (cve.get("vendors") or []):
        name = vendor.get("name")
        if name:
            vendors.append(name)
        for prod in (vendor.get("products") or []):
            pname = prod.get("name")
            if pname:
                products.append(pname)
    for weakness in (cve.get("weaknesses") or []):
        for desc in weakness.get("descriptions", []):
            if desc.get("lang") == "en" and desc.get("value"):
                cwes.append(desc["value"])

    return {
        "cve_id": cve_id,
        "source": "NVD",
        "title": cve.get("sourceIdentifier"),
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published_at": pub,
        "updated_at": mod,
        "vendor": ", ".join(sorted(set(vendors))) if vendors else None,
        "product": ", ".join(sorted(set(products))) if products else None,
        "cwe": ", ".join(sorted(set(cwes))) if cwes else None,
        "references": refs,
    }