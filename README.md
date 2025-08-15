# Vuln Portal

A FastAPI-powered portal that aggregates new vulnerabilities with scoring and an “insane” neon/glassmorphism UI. Sources include:
- NVD (CVEs + CVSS v3.x)
- CISA Known Exploited Vulnerabilities (KEV)
- EPSS probability enrichment

## Features
- Username-only login (no password)
- Live dashboard: severity cards, trends, recent CVEs table, exploited flags, EPSS
- Filters: severity, exploited, query
- Detail pages with CVSS/EPSS, vectors, references, CWEs
- REST API endpoints
- Background ingestion (hourly by default)
- Dockerized

## Quick start
1) Python
   ```bash
   cp .env.example .env
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```
   Visit http://localhost:8000

2) Docker
   ```bash
   cp .env.example .env
   docker compose up --build
   ```
   Visit http://localhost:8080

## Login
- Go to /login, enter a username, you’ll get a session for the browser.

## API
- GET /api/v1/vulns
  - Query params: q, severity, exploited (true/false), limit, offset
- GET /api/v1/vulns/{cve_id}

## Environment
- SECRET_KEY: set this in production
- NVD_API_KEY: optional, recommended for higher rate limits
- NVD_LOOKBACK_DAYS: how many days back we fetch on each run
- INGEST_INTERVAL_MINUTES: default hourly

## Notes
- First run may take a bit to fetch CVEs depending on rate limits.
- EPSS is fetched in batches for newly ingested CVEs.