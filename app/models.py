from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, Column, JSON


class Vulnerability(SQLModel, table=True):
    cve_id: str = Field(primary_key=True, index=True)
    source: str = Field(default="NVD", index=True)
    title: Optional[str] = None
    description: Optional[str] = None

    severity: str = Field(default="UNKNOWN", index=True)  # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    cvss_score: Optional[float] = Field(default=None, index=True)
    cvss_vector: Optional[str] = None

    published_at: Optional[datetime] = Field(default=None, index=True)
    updated_at: Optional[datetime] = Field(default=None, index=True)

    exploited: bool = Field(default=False, index=True)  # From CISA KEV
    epss_score: Optional[float] = Field(default=None, index=True)

    vendor: Optional[str] = None
    product: Optional[str] = None
    cwe: Optional[str] = None

    references: Optional[dict] = Field(default=None, sa_column=Column(JSON))  # {"urls": [...], "tags": [...]}
