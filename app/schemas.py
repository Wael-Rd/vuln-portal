from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel


class VulnerabilityOut(BaseModel):
    cve_id: str
    source: str
    title: Optional[str]
    description: Optional[str]
    severity: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    published_at: Optional[datetime]
    updated_at: Optional[datetime]
    exploited: bool
    epss_score: Optional[float]
    vendor: Optional[str]
    product: Optional[str]
    cwe: Optional[str]
    references: Optional[Dict]

    class Config:
        from_attributes = True