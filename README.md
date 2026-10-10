# Safe Website Vulnerability Scanner

A runnable defensive scanner for websites the user is explicitly authorized to assess. The project combines a React dashboard, authenticated FastAPI API, SQLite development storage / PostgreSQL production support, and a separately isolated scan worker behind an allowlisting egress proxy.

> **Safe-use boundary:** Scan only domains you own or have written permission to assess. The scanner makes bounded, unauthenticated `GET` requests, follows only same-host in-scope links, and does not exploit findings. It never logs in, guesses passwords, uploads files, submits forms, runs downloaded scripts, or changes target data. No findings is **not** proof that a site is vulnerability-free.

## Features

- Strict HTTP/HTTPS URL validation; rejects credentials, query strings, fragments, non-standard ports, local/reserved names and non-public IP addresses.
- Explicit authorization confirmation before a scan is queued.
- DNS TXT ownership challenge for deep scans and hosted deployments configured to require verification. Verification is for the exact hostname and expires after 180 days.
- Per-user bearer-token authentication, rate limits, private scan history, ownership checks, and deletion of scan records/findings.
- Host- and path-scoped crawling, manual redirect validation, DNS rebinding checks, safe GET-only requests, request pacing, response-size/page/time limits, and bounded public metadata checks.
- Custom passive observations for HTTPS/TLS certificate validation, security headers, cookie flags, public information-disclosure indicators, directory-listing signatures, safe backup/configuration-link indicators, DNS record presence, and known vulnerable jQuery/Bootstrap version patterns.
- Optional OWASP ZAP Baseline CLI adapter. Raw ZAP evidence/attack fields are discarded before reports are created. It is passive-only, bounded, requires the egress proxy, and runs only for root (`/`) scope.
- Deduplicated findings with severity, confidence, confirmed/potential status, timestamps, evidence, impact, and remediation.
- Downloadable HTML and JSON reports, with escaped HTML and secret/query redaction.
- Responsive dashboard with queued/running/completed/failed status, progress, coverage warnings, scan history, and deletion.

OWASP Top 10:2025 is used as a risk reference, not as a claim of comprehensive coverage or a certification.

## Run with Docker Compose (recommended)

Requires Docker Engine and the Docker Compose plugin.

```bash
# Optional: set your own development token and proxy key.
cp .env.example .env
# Review/edit .env before starting.
docker compose up --build
```

Open <http://localhost:5173>. The local-only default API token, when `SCANNER_API_TOKENS` is not set, is `dev-local-token`. If you copied `.env.example`, connect with the token configured there (`dev-local-token-change-me-123456`). This credential is for local development only; never expose it to the internet.

Compose runs:

- `web`: Vite + React development server (port 5173).
- `api`: FastAPI; API and worker share a persistent SQLite volume.
- `worker`: single-job-at-a-time scanner with read-only root filesystem, no Linux capabilities, CPU/memory/PID limits and no direct internet route.
- `egress-proxy`: private-network-only destination gate. The worker can reach public targets only through this proxy. It checks DNS answers on every connection, rejects any private/reserved answer, pins the validated address, limits the destination to the registered scan hostname and standard web ports, and rejects out-of-scope plain-HTTP paths. HTTPS path and redirect boundaries are revalidated by the scanner before each request; the proxy only tunnels TLS and does not intercept/decrypt it.

The proxy is not published to the host. Only it is attached to the outbound Docker network; the API and worker use internal networks. The proxy also applies connection and byte/time budgets. In production, add host/cloud egress firewall rules so the proxy can make only the outbound DNS and HTTP(S) connections required by your policy.

### Environment configuration

See `.env.example`.

| Variable | Purpose |
| --- | --- |
| `SCANNER_API_TOKENS` | JSON object mapping opaque bearer tokens (minimum 16 characters) to user IDs, for example `{"a-long-random-token-value":"alice"}`. Each identity sees only its own records. In development only, a local fallback token is available if unset. |
| `SCANNER_PROXY_KEY` | Shared secret for internal worker/proxy control. Use a unique randomly generated secret in every hosted environment. |
| `REQUIRE_DOMAIN_VERIFICATION` | Require DNS ownership verification for every scan. Defaults to false in local development and true in the production compose overlay. Deep scans always require verification. |
| `ZAP_BASELINE_ENABLED` | Opt in to OWASP ZAP Baseline. Keep the controlled egress proxy enabled. The base Python image does not bundle ZAP; install `zap-baseline.py` in a hardened worker image and set `ZAP_BASELINE_COMMAND` to its path. If the CLI is unavailable, the report explicitly marks ZAP coverage inconclusive. |
| `SCAN_TIMEOUT_SECONDS` | Custom HTTP crawl wall-clock budget; default 180 seconds, allowed 30–600. DNS and the optional ZAP process have separate bounded overhead. |
| `MAX_RESPONSE_BYTES` | Maximum inspected response prefix; default 512 KiB, allowed 16 KiB–2 MiB. |
| `WEB_PORT` | Published web port, default 5173. Set to `8080` when using the production web image. |

ZAP Baseline is not an active scan. It is disabled by default because the supplied base worker image intentionally omits the Java/ZAP runtime. When enabled, ZAP alerts are normalized and only their alert title, in-scope URL, severity and confidence are retained; payload/evidence fields are discarded. Non-root path scopes skip ZAP with an explicit warning. Do not enable the adapter in an image or deployment that can bypass the egress proxy.

## Production deployment

Use a managed PostgreSQL database or the included PostgreSQL overlay. Configure strong secrets, TLS termination, trusted proxy settings, backups, monitoring, and an ingress/shared rate limiter before hosting.

```bash
# Add to .env (use unique random values; quote JSON values as shown):
SCANNER_API_TOKENS={"<long-random-token>":"alice"}
SCANNER_PROXY_KEY=<at-least-32-random-characters>
POSTGRES_USER=scanner
POSTGRES_PASSWORD=<strong-url-safe-password>
POSTGRES_DB=scanner
WEB_PORT=8080

# Starts API, worker, restricted egress proxy, production SPA/Nginx and PostgreSQL.
docker compose -f docker-compose.yml -f docker-compose.production.yml up --build -d
```

The production overlay switches the database URL to PostgreSQL, requires ownership verification for all scans, and serves the built SPA from an unprivileged Nginx container. Place a TLS-terminating reverse proxy in front of the web service; do not publish FastAPI or the egress proxy directly. For production scale, use a shared rate-limit store at the ingress or replace the in-process API limiter with Redis, and use PostgreSQL for queue coordination. The supplied Compose setup intentionally runs one scanner worker to keep SQLite development behavior and rate guarantees simple.

A Docker network is not a complete host-level firewall. The Compose topology removes the worker's direct Internet route and forces it through the allowlisting proxy, but production operators should additionally enforce egress ACLs at the host/cloud layer and keep the proxy secret private.

## Run locally without Docker

Requires Python 3.11+ and Node.js 20+.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r backend/requirements.txt

# Terminal 1: API (SQLite database is created in the current directory).
PYTHONPATH=backend .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: worker. Without SCANNER_PROXY_URL it connects directly, but still
# resolves and pins each public IP before connecting.
PYTHONPATH=backend .venv/bin/python -m app.worker

# Terminal 3: frontend; Vite proxies relative /api requests to the local API.
cd frontend
npm ci
npm run dev -- --host 0.0.0.0
```

Open <http://localhost:5173> and use `dev-local-token` unless you configured `SCANNER_API_TOKENS`. For a hosted setup, do not use direct-worker mode; use the Compose isolation or an equivalent enforced egress proxy.

## API

All `/api/*` routes require `Authorization: Bearer <token>`. Tokens map to server-side user IDs; scan ownership is checked for every read, report, and delete. `/healthz` is a minimal unauthenticated liveness endpoint. API docs are available at `/docs` in development and disabled in production.

| Method / route | Description |
| --- | --- |
| `POST /api/scans` | Validate, authorize and queue a scan. Body: `{"url":"https://example.com/","path_scope":"/","mode":"basic","max_pages":8,"authorized":true}`. |
| `GET /api/scans` | List the authenticated user's scan history. Supports `limit` and `offset`. |
| `GET /api/scans/{scan_id}` | Get status and progress, after an ownership check. |
| `GET /api/scans/{scan_id}/findings` | Get normalized findings, after an ownership check. |
| `GET /api/scans/{scan_id}/report?format=json` | Download a completed JSON report. Set `format=html` for HTML. |
| `DELETE /api/scans/{scan_id}` | Delete a scan and its findings; unknown/other-user IDs return 404. |
| `POST /api/ownership/challenges` | Create a temporary DNS TXT challenge for a public hostname. |
| `POST /api/ownership/verify` | Verify the challenge and allow deep/hosted scans for that exact hostname. |
| `GET /api/ownership?hostname=example.com` | Check ownership-verification status for the current user. |

A false authorization confirmation is rejected. Basic scans are limited to 10 pages; deep scans to 30 pages and require verified ownership. The API rate-limits scan creation (5/hour per user), ownership operations (12/hour), and ordinary API requests (120/minute) in each process. Use an ingress/shared limiter for multiple API replicas.

Example:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H 'Authorization: Bearer dev-local-token' \
  -H 'Content-Type: application/json' \
  --data '{"url":"https://example.com/","path_scope":"/","mode":"basic","max_pages":8,"authorized":true}'
```

## Scan boundaries and interpretation

- Only public DNS names or public IP addresses, HTTP/HTTPS, and ports 80/443 are accepted. DNS is revalidated and pinned at connection time; mixed public/private answer sets are rejected.
- Input query strings and fragments are rejected to avoid transmitting or storing user-supplied secrets. Discovered query URLs are not followed. Credentials in URLs are rejected, and obvious token-like path values are rejected or redacted.
- Redirects are manual, limited to three hops, exact-host only, path-scope checked, and cannot downgrade HTTPS. Redirects outside scope are blocked and reported as a coverage warning.
- Crawl depth is at most two link levels; page limits are selected by mode. Requests are paced at least 0.75 seconds apart, response reads are bounded, request timeouts are five seconds, and scans have a global wall-clock timeout.
- Only inert HTML is parsed. Script sources can be used as version hints; scripts are never fetched or executed. Only `robots.txt`, `sitemap.xml`, and `/.well-known/security.txt` are requested as safe public metadata, and only when they are in scope. Backup/configuration-like links are reported as indicators but are never requested.
- Findings are **confirmed** only for directly observed response/configuration facts (such as an HTTP response or a visible directory index); version/banner and missing-control observations are **potential** and may need manual validation. Confidence is a triage aid, not a probability of exploitability.
- DNS record checks report presence only; they never include TXT record values. The component advisory catalog is deliberately small and must be maintained as dependencies/advisories change.
- Warnings identify timeouts, size/page limits, blocked redirects, missing coverage and inconclusive checks. A clean report is not an assurance that the site is safe, compliant, or free of OWASP Top 10 risks. Deletion removes records from the active database, but filesystem pages, SQLite WAL files, database snapshots and backups may retain prior bytes; apply retention, volume encryption and backup-expiration policies appropriate to your environment.

## Development and tests

```bash
PYTHONPATH=backend .venv/bin/pytest
cd frontend && npm run build
```

The tests cover URL validation, prohibited IP/DNS answers, path scope, redirect handling, severity mapping, and report escaping/redaction. API tests cover authentication, authorization confirmation, deep-scan ownership, per-user access, and deletion.
