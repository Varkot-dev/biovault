# BioVault

### Query three hospitals' genomes. See none of them.

Three research labs. One aggregate answer. No lab ever sees another's records.

**→ [Break it yourself](https://claude.ai/code/artifact/338d9894-9820-46f7-8833-b14c85b04555)** — an
interactive demo where *you* are the attacker. Run a real differencing attack
against the real mechanism, watch the privacy budget cut you off mid-attack,
and see exactly where the defense fails.

```bash
git clone https://github.com/Varkot-dev/biovault && cd biovault
cp .env.example .env    # then fill in two generated secrets
docker compose up
```

---

Multi-institution genomics has a standing problem. The scientifically valuable
question — *"how many patients across all our labs carry this variant?"* — is
usually unanswerable, because answering it means one lab shipping raw genomes
to another, which consent agreements and GDPR forbid. So the query never gets
asked.

BioVault answers it without moving a single record. Each lab counts inside its
own isolation boundary; only differentially private noised integers cross
between institutions.

Strict tenant isolation and cross-institution collaboration normally trade off
against each other. Here both hold at once — and most of the test suite exists
to prove the second did not quietly undermine the first.

Underneath: role-based access control across three isolated tenants,
AES-256-GCM encryption at rest with envelope key management, OAuth 2.0 with
PKCE, JWT with refresh-token rotation and reuse detection, and PostgreSQL
row-level security as a second, independent isolation layer.

## Private federated queries

```bash
curl -X POST localhost:8000/federation/cohort-count \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"gene": "BRCA1", "epsilon": 0.1}'
```

```json
{
  "total": 150,
  "interval": { "lower": 65, "upper": 235, "tolerance": 84.7, "confidence": 0.95 },
  "sites_queried": 3,
  "sites_contributing": 2,
  "epsilon_spent": 0.3,
  "epsilon_remaining": 0.7,
  "contributions": [
    {"tenant_id": "lab-broad",  "suppressed": false},
    {"tenant_id": "lab-riken",  "suppressed": false},
    {"tenant_id": "lab-sanger", "suppressed": true}
  ]
}
```

The true total across the three labs is 226; the interval covers it. Sanger is
suppressed here: small cohorts are withheld, because noise cannot hide the
difference between *nobody* and *somebody*. That decision is itself randomized
— comparing the true count to the threshold would publish an exact bit of
`count > 5` per lab per query, free of charge, which is a differencing attack
delivered one bit at a time. No record, identifier, or exact per-site count appears anywhere in
that response — asserted by
`test_response_contains_no_record_level_data`, which scans the raw body for
known specimen labels, dataset ids, and payload content.

### The answer is an interval, not a number

`total` is never returned alone. A bare noised count invites an analyst to
treat it as exact and publish a finding that isn't there. In the response
above, a total of `150` carries a 95% interval of `65–235` — and the true
answer is 226. Reporting `150` on its own would have been a fabricated finding;
reporting the interval is honest about what a private query can tell you.

The interval derives from `accuracy = -scale · ln(α)` (the Laplace tail bound,
matching OpenDP's `laplacian_scale_to_accuracy`). Measured coverage lands
within 0.15% of nominal across scales 2/10/20 and α of 0.01/0.05/0.10. For a
federated sum, per-site variances add, so the combined tolerance is the
root-sum-of-squares — wider than any single site's, which is the honest
direction.

**It bounds only the privacy noise.** Not sampling error, not selection bias.
Presenting it as a total error bar would understate real uncertainty.

Analysts can size a study *before* spending anything:

```bash
curl "localhost:8000/federation/precision?epsilon=0.1&sites=3"
# {"single_site_tolerance": 29.96, "federated_tolerance": 51.89,
#  "queries_affordable": 3, "confidence": 0.95}
```

| ε | 95% tolerance | federated queries affordable (3 sites) |
|---:|---:|---:|
| 0.01 | ±299.6 | 33 |
| 0.05 | ±59.9 | 6 |
| 0.1 | ±30.0 | 3 |
| 0.5 | ±6.0 | 0 |
| 1.0 | ±3.0 | 0 |

That table is the entire design space, and it is deliberately uncomfortable:
precision and privacy trade directly against each other, the budget caps how
many times you can make the trade, and at high ε a single query exhausts
everything. A system that let you have both would be lying about one of them.



### Why the budget matters more than the noise

Noise is zero-mean, so a determined querier can repeat a question and average
the noise away. Measured on this implementation:

| Queries | Attacker's estimate of a true count of 500 | Error |
|---:|---:|---:|
| 10 | 503.10 | 3.10 |
| 100 | 500.98 | 0.98 |
| 2,000 | 499.86 | **0.14** |

Unlimited queries defeat differential privacy entirely, however correct the
noise. The enforced per-tenant epsilon budget is therefore the actual control,
and its default was chosen by **measuring this attack rather than copying a
convention**.

The right metric is an **attacker success rate**, not a median error — a median
says what happens on a typical attempt, but an attacker only needs to succeed
once. A federated query costs ε × (number of sites), so across three labs a
budget of 1.0 at ε=0.1 buys 3 queries. Over 400 full attacks each:

| ε_total | queries allowed | attacker pins the individual (±1) |
|---:|---:|---:|
| 10.0 — *the tutorial default* | 33 | **14.2%** |
| **1.0 — BioVault default** | 3 | **4.5%** |

ε_total = 10.0 appears in plenty of DP tutorials. It lets an attacker state a
specific person's genotype in roughly **one attempt in seven** — not a privacy
guarantee in any useful sense.

**What 1.0 does not do:** it does not defeat the differencing attack. It cuts
the attacker's per-attempt success rate from ~14% to ~5%. Differential privacy
bounds *expected* leakage; it does not eliminate it.

Two corrections are recorded rather than quietly folded in, because a privacy
claim you can't falsify isn't a claim. An earlier version of these docs said
"differencing defeated" at ε=1.0 — wrong; a nonzero success rate is not defeat.
This table has moved twice. It read 40.3%/14.3% while the budget charged ε once
per federated query instead of **once per site** — undercounting real privacy
loss threefold — and moved again when the suppression decision started paying
for itself out of the same budget. Both fixes tightened the real guarantee,
which is why the honest figures kept going down rather than up.

Run the numbers yourself in the
[demo](https://claude.ai/code/artifact/338d9894-9820-46f7-8833-b14c85b04555)
(*Run 400 full attacks*), or read the reasoning in
[`budget.py`](src/biovault/federation/budget.py).

**Every claim below is backed by a command in this repository that you can
re-run.** Numbers were measured, not estimated. Where something is incomplete,
it says so.

## Measured results

Last run against a freshly wiped database (`docker compose down -v`, rebuild,
re-bootstrap):

```
383 passed          ruff clean          pip-audit: 72 packages, 0 vulnerabilities
```

| Suite | Tests |
|---|---:|
| Authorization policy | 79 |
| API access control — IDOR, SQLi, roles, PHI | 46 |
| Differential privacy — noise, suppression, differencing | 34 |
| JWT attacks — `alg:none`, tamper, expiry, escalation | 28 |
| RLS tenant isolation, via raw SQL | 27 |
| Envelope encryption | 24 |
| OAuth 2.0 authorization-code flow | 23 |
| PKCE | 22 |
| Federated cohort discovery over HTTP | 22 |
| Privacy budget enforcement | 15 |
| Audit log completeness and immutability | 15 |
| Refresh rotation and reuse detection | 13 |
| Pre-auth identity-lookup blast radius | 10 |
| Bootstrap and RLS installation | 7 |
| Master-key rotation | 6 |
| Policy centralization (AST guard) | 5 |
| Suite-integrity guards | 2 |
| **Total** | **383** |

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
| Differential privacy and the differencing attack | `pytest tests/security/test_differential_privacy.py` |
| Privacy budget stops the averaging attack | `pytest tests/security/test_privacy_budget.py` |
| Federation leaks no record-level data | `pytest tests/security/test_federation_api.py` |
| OAuth 2.0 + PKCE end to end | `pytest tests/security/test_oauth_flow.py` |
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
