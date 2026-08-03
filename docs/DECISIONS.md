# Decision log

Running record of design decisions, why they were made, and what was rejected.
Newest entries at the bottom of each section.

---

## D1 — Least-privilege database role so RLS is genuinely enforced

**Decision.** Two Postgres roles. `biovault_owner` owns the schema and is used
only by migrations and RLS setup. `biovault_app` owns nothing and is what the
API connects as at request time.

**Why.** PostgreSQL *bypasses* row-level security for superusers and for the
table owner unless `FORCE ROW LEVEL SECURITY` is set. If the API connected as
the owner, every RLS policy would be inert and tenant isolation would quietly
degrade to application-layer-only — while still appearing to work in tests.
That is exactly the "bug in one layer breaches isolation" failure the spec
(requirement 3) asks to defend against.

**Rejected.** Single-role setup. Simpler, but makes the RLS layer decorative,
which would make the defense-in-depth claim false.

**Verified by.** `tests/security/test_rls_isolation.py` connects to Postgres
directly as `biovault_app`, bypassing the API entirely, and asserts that rows
from other tenants are invisible even to raw SQL.

---

## D2 — Envelope encryption rather than direct field encryption

**Decision.** Each dataset gets its own AES-256 data encryption key (DEK). DEKs
are wrapped with a master key-encryption key (KEK) held in the environment and
stored alongside the ciphertext. Field encryption uses the DEK.

**Why.** Rotating the master key only requires unwrapping and rewrapping N
small DEKs, not re-encrypting every genomic record. It also limits blast radius:
compromise of one DEK exposes one dataset, not the corpus. This is why the spec
(requirement 4) asks for envelope encryption specifically rather than "encrypt
the field."

**Rejected.** Encrypting fields directly with the master key. Simpler, but
rotation would require a full re-encryption pass over all data, and there would
be no per-dataset compromise boundary.

---

## D3 — AES-256-GCM, with the nonce and tag stored explicitly

**Decision.** AEAD via `cryptography`'s `AESGCM`. A fresh 96-bit nonce per
encryption operation, stored with the ciphertext. Dataset ID bound in as
additional authenticated data (AAD).

**Why.** GCM is authenticated: tampering with ciphertext is *detected* rather
than silently decrypting to garbage. The spec explicitly rules out ECB and
unauthenticated CBC. Binding the dataset ID as AAD means a ciphertext blob
physically moved from dataset A to dataset B fails authentication — this
defends against a database-level record-swapping attack that field-level
encryption alone would not catch.

**Rejected.** AES-CBC + separate HMAC (encrypt-then-MAC). Cryptographically
sound but hand-assembled composition is a classic source of bugs, and the spec
directs toward vetted primitives.

---

## D4 — Dependency versions verified against PyPI, not recalled

**Decision.** Every pin in `pyproject.toml` was checked with `pip index versions`
before being written.

**Why.** The first draft guessed `pytest-cov==8.0.0`, `pytest-asyncio==2.0.0`,
and `httpx==0.29.2` — none of which exist. Install failed. Correct versions are
7.1.0, 1.4.0, and 0.28.1. Guessing version numbers wastes a full install cycle
per mistake.

**Side note.** The failing command was written as
`pip install -q ... 2>&1 | tail -15 && echo "=== INSTALL OK ==="`, and the
success echo fired *despite* the failure, because the pipe masked pip's exit
code. Subsequent shell steps use `set -o pipefail`. Worth remembering: a
verification step that can print "OK" on failure is worse than no verification
step, because it manufactures false confidence.
