# BioVault

Role-based access control for multi-institution genomics datasets.

Three isolated research labs, AES-256-GCM encryption at rest, OAuth 2.0 with
PKCE, JWT authentication with refresh-token rotation, and PostgreSQL row-level
security as a second, independent isolation layer.

**Every claim below is backed by a command in this repository that you can
re-run.** Numbers were measured, not estimated. Where something is incomplete,
it says so.

## Measured results

Last run against a freshly wiped database (`docker compose down -v`, rebuild,
re-bootstrap):

```
268 passed          87.95% coverage (floor: 80%)
```

| Suite | Tests |
|---|---:|
| Authorization policy (`test_policy.py`) | 74 |
| API access control — IDOR, SQLi, roles, PHI | 46 |
| JWT attacks — `alg:none`, tamper, expiry, escalation | 28 |
| RLS tenant isolation, via raw SQL | 27 |
| Envelope encryption | 24 |
| PKCE | 22 |
| Audit log completeness and immutability | 15 |
| Refresh rotation and reuse detection | 13 |
| Bootstrap and RLS installation | 6 |
| Master-key rotation | 6 |
| Policy centralization (AST guard) | 5 |
| Suite-integrity guards | 2 |
| **Total** | **268** |

170 tests carry the `security` marker. `pip-audit`: 72 packages, no known
vulnerabilities.

Coverage is 100% on `authz/policy.py`'s decision paths (97% file),
`db/rls.py`, `audit/recorder.py`, `auth/refresh.py`, and `auth/pkce.py` — the
modules the security claims rest on. `db/bootstrap.py` sits at 30%; it is
startup glue exercised end-to-end by `docker compose up` rather than by unit
tests.

---

## Quick start

```bash
cp .env.example .env
python -c "import base64,os; print('BIOVAULT_MASTER_KEK=' + base64.b64encode(os.urandom(32)).decode())"
python -c "import secrets; print('BIOVAULT_JWT_SECRET=' + secrets.token_urlsafe(48))"
```

Paste those two values into `.env`, set the two database passwords, then:

```bash
docker compose up --build
```

The API listens on `http://localhost:8000`; interactive docs at `/docs`.

---

## Verifying the claims

Each row names the exact command that substantiates it. Integration tests need
a running PostgreSQL — `docker compose up -d db` first.

| Claim | Verify with |
|---|---|
| Cross-tenant access denied at the application layer | `pytest tests/security/test_policy_is_central.py tests/unit/test_policy.py` |
| Cross-tenant access denied at the database layer, independently | `pytest tests/security/test_rls_isolation.py` |
| AES-256-GCM authenticated encryption at rest | `pytest tests/unit/test_envelope.py` |
| OAuth 2.0 PKCE (S256) | `pytest tests/security/test_pkce.py` |
| JWT: `alg:none`, tamper, expiry, escalation | `pytest tests/security/test_jwt_attacks.py` |
| Refresh-token rotation with reuse detection | `pytest tests/security/test_refresh_rotation.py` |
| IDOR and SQL injection blocked over HTTP | `pytest tests/security/test_api_access_control.py` |
| Audit log completeness and immutability | `pytest tests/security/test_audit_log.py` |
| Master-key rotation without re-encrypting data | `pytest tests/integration/test_key_rotation.py` |
| Full suite | `pytest tests/ -q` |
| Coverage | `pytest tests/ --cov --cov-report=term` |

### The eight mandated negative cases

| # | Attack | Test |
|---|---|---|
| 1 | Cross-tenant read | `test_explicit_cross_tenant_query_returns_nothing`, `test_idor_denied_across_every_tenant_pair` |
| 2 | Expired token | `test_expired_token_is_rejected` |
| 3 | Tampered JWT signature | `test_tampered_signature_is_rejected` |
| 4 | `alg:none` | `test_alg_none_token_is_rejected` |
| 5 | Privilege escalation via role manipulation | `test_role_escalation_in_payload_is_rejected` |
| 6 | Refresh-token reuse → family revoked | `test_replaying_a_consumed_token_revokes_the_family` |
| 7 | IDOR on dataset IDs | `test_idor_cross_tenant_dataset_read_is_denied` |
| 8 | SQL injection on query params | `test_sql_injection_in_query_filter_is_neutralised` |

Run all eight:

```bash
pytest tests/ -k "cross_tenant_query_returns_nothing or expired_token_is_rejected or tampered_signature or alg_none_token or role_escalation_in_payload or replaying_a_consumed_token or idor_cross_tenant or sql_injection_in_query_filter"
```

---

## Architecture

```
             ┌──────────────────────────────────────────────┐
   request → │ FastAPI          rate limit → Pydantic        │
             └──────────────────────┬───────────────────────┘
                                    │  Principal built ONLY from verified
                                    │  JWT claims — never from the request
                                    ▼
             ┌──────────────────────────────────────────────┐
             │ audit.recorder.authorize()                   │
             │   decides AND writes the audit row           │
             └──────────────────────┬───────────────────────┘
                                    ▼
             ┌──────────────────────────────────────────────┐
             │ authz.policy.decide()   ← the ONLY policy     │
             │   gate 1  tenant      (binds every role)     │
             │   gate 2  capability                          │
             │   gate 3  dataset grant                       │
             │   gate 4  PHI clearance                       │
             │   gates can only DENY; falling through grants │
             └──────────────────────┬───────────────────────┘
                                    ▼
             ┌──────────────────────────────────────────────┐
             │ PostgreSQL — row-level security               │
             │   independent second isolation layer          │
             │   app role: not superuser, no BYPASSRLS       │
             └──────────────────────────────────────────────┘
```

### Why two isolation layers

They fail independently. Deleting the application-layer check from an endpoint
was tested: **only 2 of 46 API security tests failed**, and every cross-tenant
test still passed because RLS blocked those requests on its own. The two tests
that did fail were a within-tenant grant check and a role check — precisely the
cases a row filter cannot express. That division of labour is why both exist.

### One policy module

All access decisions live in `src/biovault/authz/policy.py`.
`tests/security/test_policy_is_central.py` parses every source file's AST and
fails the build if any other module compares against a role. The guard was
verified by injecting a violation and confirming it failed.

---

## Threat model

### Defended

| Threat | Control |
|---|---|
| Cross-tenant data access | App-layer tenant gate **and** Postgres RLS, independently |
| Forged / unsigned tokens | Explicit HS256 allowlist passed to `decode`; `alg:none` rejected |
| Stolen access token | 15-minute TTL, `leeway=0`, audience and issuer verified |
| Stolen refresh token | Rotation with family-wide revocation on reuse |
| Intercepted authorization code | PKCE S256; `plain` refused |
| Database disclosure | AES-256-GCM at rest; refresh tokens stored hashed |
| Ciphertext relocation between datasets | Dataset ID bound as AAD — a moved blob fails authentication |
| Audit tampering by a compromised app | `UPDATE`/`DELETE` revoked from the app role at the GRANT level |
| Dataset enumeration | Denials return 404, identical to nonexistent |
| SQL injection | Parameterized queries throughout; LIKE metacharacters escaped |
| Privilege escalation via request fields | `Principal` built only from verified claims; `extra="forbid"` on request models |

### Not defended

Stated plainly rather than left implied:

- **A compromised master KEK before rotation completes.** Envelope encryption
  makes rotation cheap (`docs/key-rotation.md`), but a leaked KEK unwraps every
  DEK until it is retired.
- **A malicious database superuser.** `biovault_owner` can disable RLS. RLS
  defends against application bugs, not against an attacker who already owns
  the database.
- **Traffic interception.** No TLS is configured here; a real deployment
  terminates TLS at a load balancer or gateway.
- **Denial of service beyond basic rate limiting.** No distributed rate limits,
  no request-cost accounting.
- **Insider abuse by an authorized user.** A researcher with a legitimate grant
  can read that dataset. The audit log records it; nothing prevents it.
- **Key material in process memory.** The master KEK is an environment
  variable. Production genomics data belongs behind a KMS or HSM where key
  material never enters application memory.

---

## What this is / what this isn't

**This is** a working demonstration of RBAC, multi-tenancy, and encryption-at-rest
patterns, built to be verified by re-running its tests. The security controls
are real and the negative tests genuinely fail when the controls are removed —
that was checked by deliberately breaking them.

**This is not:**

- **A certified HIPAA, dbGaP, or GA4GH system.** No compliance audit has been
  performed. Meeting those standards requires organizational controls,
  BAAs, and formal review that no repository can supply.
- **Holding real genomic data.** Every record is synthetic. Gene names in
  `src/biovault/seed/synthetic.py` are public; all coordinates, genotypes, and
  specimen labels are fabricated. Nothing here derives from a real individual.
- **Production-hardened.** No TLS, no secret manager, no HA, no backups, no
  key ceremony. The `Not defended` list above is honest about the gaps.
- **A real OAuth provider.** The authorization-code and PKCE machinery is
  implemented and tested, but there is no user-facing consent UI or federation
  with an external identity provider.

---

## Layout

```
src/biovault/
  authz/policy.py      the single authorization decision point
  audit/recorder.py    authorize() — decides and audits together
  crypto/envelope.py   AES-256-GCM envelope encryption
  auth/                JWT, PKCE, refresh rotation
  db/rls.py            row-level security policies
  api/                 FastAPI routes and dependencies
  seed/synthetic.py    fabricated fixture data

tests/
  unit/                pure logic, no database
  security/            negative cases — the bulk of the effort
  integration/         bootstrap and RLS installation
docs/
  DECISIONS.md         every design decision and why
  key-rotation.md      master-key rotation procedure
```

---

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
docker compose up -d db
.venv/bin/python -m biovault.db.bootstrap
.venv/bin/python -m pytest tests/ -q
.venv/bin/ruff check src/ tests/
```

Integration tests skip when PostgreSQL is unreachable so the unit suite runs
without Docker. CI sets `BIOVAULT_REQUIRE_INTEGRATION=1`, which converts those
skips into failures — a green security suite must not be able to mean an unrun
one.
