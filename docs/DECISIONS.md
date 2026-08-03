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

---

## D5 — Dataset ID bound as AAD at both key-wrap and field layers

**Decision.** The dataset ID is passed as additional authenticated data when
wrapping a DEK *and* when encrypting a field.

**Why.** Without it, an attacker with database write access could move an
encrypted blob from lab A's dataset into lab B's dataset and read it through
lab B's legitimate decryption path. RBAC would not catch this: every access
check would pass, because the attacker is authorized for the record they moved
the ciphertext *into*. AAD makes the ciphertext refuse to decrypt outside the
dataset it was created for, so the crypto layer enforces an invariant the
authorization layer structurally cannot see.

**Verified by.** `test_ciphertext_moved_to_another_dataset_fails` and
`test_data_key_from_one_dataset_cannot_unwrap_for_another`.

---

## D6 — `DecryptionError` carries no diagnostic detail

**Decision.** All authentication failures raise the same error with a generic
message. The underlying `InvalidTag` is preserved via `raise ... from exc` for
local debugging but never surfaces in the message.

**Why.** An error that distinguishes "wrong key" from "tampered ciphertext"
is an oracle. Attackers use exactly that signal to mount adaptive attacks.
The cause chain keeps the information available to a developer with stack
access without exposing it to a caller.

---

## D7 — Crypto verified empirically, not just via a green suite

**Decision.** Beyond the 24 unit tests, the cipher was checked directly:
ciphertext length equals plaintext + 16 bytes (confirming a GCM tag is
present), nonce is 96 bits, DEK is 256 bits, and encrypting 64 identical bytes
produces four *distinct* 16-byte blocks.

**Why.** That last check is a direct empirical disproof of ECB mode — the
property behind the well-known "ECB penguin." A passing test suite proves the
code does what I wrote; this proves the cipher has the property the résumé
claims. The spec's honesty rule makes that distinction worth the extra step.

**Observed output.** `ciphertext len: 48 (pt 32 + 16B tag)`, `nonce bits: 96`,
`DEK bits: 256`, `ECB-like repeat blocks: False`.

---

## D8 — Policy as an ordered gate chain where gates can only deny

**Decision.** `decide()` runs four gates in order — tenant, capability, dataset
grant, record sensitivity. Every gate may only return a denial. A grant is
returned solely by falling through all four.

**Why.** Default-deny becomes structural instead of aspirational. Adding a new
`Action` to the enum without a matching entry in `_CAPABILITIES` results in
denial by construction — the capability gate finds nothing and denies. The
opposite shape (accumulating permissions and granting if any matched) fails
open when someone forgets a case.

**Ordering matters.** The tenant gate runs first and unconditionally, including
for `lab_admin`. No later gate can re-grant what it denied, so tenant isolation
cannot be undone by any subsequent rule.

---

## D9 — `decide()` is pure; audit logging happens at the caller

**Decision.** No I/O, no clock, no database access inside the policy function.

**Why.** Purity is what makes exhaustive testing possible — the 160-combination
sweep in `test_tenant_isolation_holds_across_entire_input_space` runs in
milliseconds precisely because there is nothing to mock. The tradeoff is that
audit logging must be enforced at the call site, which is handled by routing
all endpoint checks through a single dependency (task #6/#7) rather than by
trusting each endpoint to remember.

---

## D10 — Centralization enforced by AST inspection, not code review

**Decision.** `test_no_role_comparisons_outside_the_policy_module` parses every
source file and fails if any module outside `authz/policy.py` compares against
a role.

**Why.** The spec forbids scattered `if role ==` checks. A convention that is
only documented gets violated during the first deadline. AST parsing rather
than `grep` avoids false positives from strings and comments.

**Verified to actually fail.** A temporary file containing
`if user.role == Role.LAB_ADMIN` was added; the test failed with
`assert not ['_tmp_violation.py:3']`, then passed after removal. A guard test
that has never been observed failing is not known to work.

---

## D11 — PHI clearance gates disclosure, not destruction

**Decision.** Gate 4 applies to `READ` and `WRITE` only. `DELETE` is exempt, so
a `lab_admin` may delete a PHI record without PHI clearance.

**Why.** Clearance is a confidentiality control: it governs who may *see*
protected content. Deleting a record discloses nothing. Destruction is an
integrity/availability concern, already gated by `DELETE` being a lab_admin-only
capability. Conflating the two would mean the only person who can clean up a
mis-uploaded PHI record is someone authorized to read it — which increases
disclosure, not decreases it.

**Guarded by.** `test_phi_clearance_gates_disclosure_not_destruction`, written
specifically so this stays a decision rather than becoming an accident of gate
ordering that someone later "fixes."

---

## D12 — Two database roles, and RLS is FORCEd

**Decision.** `biovault_owner` owns the schema and runs migrations.
`biovault_app` owns nothing, is not a superuser, lacks `BYPASSRLS`, and is what
the API connects as. Every tenant-scoped table has RLS both `ENABLE`d and
`FORCE`d.

**Why `FORCE` and not just `ENABLE`.** Plain `ENABLE` still exempts the table
owner. Since migrations run as owner, a maintainer inspecting data as owner
would see all tenants, possibly conclude RLS was broken, and "fix" it. Forcing
subjects even the owner to policy.

**Verified against the live database, not assumed.**

```
relname         | rls_enabled | rls_forced
genomic_records | t           | t          (all 6 tables identical)

rolname        | rolsuper | rolbypassrls
biovault_owner | t        | t
biovault_app   | f        | f
```

---

## D13 — RLS policies fail closed when tenant context is unset

**Decision.** Policies compare `tenant_id = current_setting('biovault.tenant_id', true)`.
The `true` is the missing-ok flag.

**Why.** Without it, `current_setting` *raises* when the setting is absent.
Application code tends to catch and swallow such errors, which fails open. With
it, the function returns NULL, `tenant_id = NULL` evaluates to NULL rather than
TRUE, and the policy denies. Failing closed here is SQL's three-valued logic
used deliberately.

**Measured.** With no tenant context set, `SELECT count(*) FROM genomic_records`
as the app role returns `0` — verified for all six tenant-scoped tables.

---

## D14 — Tenant context via `SET LOCAL`, not `SET`

**Decision.** `set_config(..., is_local => true)` inside the transaction.

**Why.** Connections are pooled. A plain `SET` persists on the connection after
the request finishes, so the next request to borrow that connection inherits
the previous tenant's context — a cross-tenant leak caused purely by connection
reuse, and one that would not reproduce under single-threaded testing.
`SET LOCAL` is reverted by PostgreSQL at COMMIT or ROLLBACK.

**Guarded by.** `test_tenant_context_does_not_leak_between_transactions`.

---

## D15 — Audit append-only enforced by GRANT, not convention

**Decision.** `GRANT SELECT, INSERT ON audit_entries` then
`REVOKE UPDATE, DELETE`. Confirmed the app role holds only INSERT and SELECT.

**Why.** An application that can rewrite its own audit trail has no audit
trail. If the API is compromised, the attacker inherits its database
privileges — so the restriction has to live below the application, in
PostgreSQL.

**Verified two ways.** The privilege table shows only INSERT/SELECT, *and*
`test_audit_update_actually_fails_at_runtime` inserts a row then attempts an
UPDATE, asserting `permission denied`. Checking the GRANT alone would not prove
it bites.

---

## D16 — Integration tests skip locally but are forced in CI

**Decision.** Database-backed tests skip when PostgreSQL is unreachable, so the
unit suite runs without Docker. CI sets `BIOVAULT_REQUIRE_INTEGRATION=1`, which
turns those skips into hard failures.

**Why.** The skip is a genuine convenience but creates a dangerous failure
mode: a misconfigured CI job reporting a green *security* suite having verified
nothing about tenant isolation. The guard closes that gap.

**Verified to fire.** Pointed at a dead database with the flag set, both guard
tests failed as intended. Without the flag, 27 RLS tests reported
`27 skipped` — not `27 passed`, which is the outcome that would have been
dangerous.

---

## D17 — Seed data ordering: explicit flushes between dependency levels

**Decision.** `bootstrap._seed` flushes after tenants, and again after users
and datasets, before inserting rows that reference them.

**Why.** SQLAlchemy batches INSERTs by mapper, not by `session.add()` call
order. The first run failed with
`ForeignKeyViolation: Key (tenant_id)=(lab-broad) is not present in table "tenants"`
because every `Dataset` was sent before any `Tenant`. Adding objects in
dependency order does not imply they are written in that order.

---

## D18 — Guard against vacuous isolation tests

**Decision.** `test_every_tenant_has_data_so_isolation_tests_are_not_vacuous`
asserts each of the three labs actually holds records.

**Why.** Every cross-tenant test asserts a count is zero. If seeding failed and
all tables were empty, all of them would pass while proving nothing. The claim
"3 isolated research labs" requires three *populated* labs to mean anything.

---

## D19 — Explicit JWT algorithm allowlist passed to `decode`

**Decision.** `jwt.decode(..., algorithms=["HS256"])`. The token's own `alg`
header is never consulted.

**Why.** This is the `alg:none` bypass. A verifier that reads `alg` from the
token accepts an unsigned token as valid, letting anyone mint arbitrary
claims.

**Proven, not assumed.** A forged `alg:none` token was constructed and shown to
be *structurally valid* — `jwt.decode(..., verify_signature=False)` parses it
and returns `{'sub': 'attacker', 'role': 'lab_admin', 'tenant': 'lab-broad'}`.
The same token is rejected by `verify_access_token`. Demonstrating it parses
cleanly matters: had the test passed because of malformed base64, it would have
proven nothing about the allowlist. Case variants (`None`, `NONE`, `nOnE`) are
covered too.

---

## D20 — `leeway=0` on expiry, and refresh tokens rejected as access tokens

**Decision.** No clock-skew grace period. The `typ` claim is checked so a
refresh token cannot be presented where an access token is expected.

**Why.** Leeway is a deliberate extension of a stolen token's useful life. And
since refresh tokens live 7 days versus 15 minutes for access tokens, accepting
one as an access token would silently extend session lifetime by ~672x.

---

## D21 — Uniform error messages across all token failures

**Decision.** Every failure path raises `TokenError("token verification failed")`.

**Why.** Distinguishing "expired" from "bad signature" from "wrong audience"
is an oracle an attacker can probe. `test_error_message_does_not_reveal_which_check_failed`
asserts the message set has exactly one element across three different failure
causes.

---

## D22 — PKCE: S256 only, `plain` explicitly refused

**Decision.** `verify_challenge` raises on any method other than `S256`.

**Why.** RFC 7636 permits `plain`, but an attacker positioned to intercept the
authorization code can also read the plaintext challenge in the authorization
request — so `plain` defends against nothing. Supporting it for compatibility
would let a client downgrade itself out of protection.

**Also.** Comparison uses `hmac.compare_digest`. A short-circuiting `==` leaks
the expected challenge byte-by-byte under timing analysis.

**Conformance checked independently.** `test_challenge_matches_rfc7636_s256_definition`
computes `BASE64URL(SHA256(verifier))` inline rather than calling the
implementation, so a self-consistent but non-conformant change would fail
rather than pass.

---

## D23 — Refresh reuse detection runs before the expiry check

**Decision.** In `rotate()`, the `used_at is not None` branch is evaluated
before expiry.

**Why.** An expired *and* replayed token is still evidence of theft. Checking
expiry first would return "expired" and discard that signal, leaving the
attacker's family intact. Order matters here for security, not just tidiness.

**Guarded by.** `test_reuse_of_an_expired_token_still_revokes_the_family`.

---

## D24 — Reuse revokes the whole family, and the successor dies with it

**Decision.** On replay, every token sharing the `family_id` is revoked —
including the successor the attacker just obtained.

**Why.** The server cannot distinguish the thief from the victim; both present
a token descended from the same login. Revoking only the replayed token would
leave the attacker holding a valid successor, making detection pointless.
Forcing both parties to re-authenticate is the only safe resolution.

**Guarded by.** `test_successor_is_unusable_after_reuse_revokes_the_family`,
which is the test that would catch a "revoke just this token" regression.

---

## D25 — Test assertion corrected rather than code changed

`test_reuse_detection_survives_a_long_rotation_chain` initially asserted 7
tokens in the family. The real count is 6 — initial plus five successors. The
replay attempt raises *before* minting anything, which is correct: a detected
replay must not issue a token. The assertion was wrong, not the implementation.
Noted because the honesty rule cuts both ways — a failing test is not
automatically a bug in the code.

---

## D26 — `authorize()` fuses the policy call with the audit write

**Decision.** Endpoints call `audit.recorder.authorize()`, never
`policy.decide()`. `authorize` calls the policy, writes the audit row, and
returns the decision.

**Why.** "Remember to log every decision" is a convention, and conventions get
skipped. Fusing the operations makes an unaudited decision unobtainable through
the supported path. `test_api_modules_do_not_call_decide_directly` inspects the
API package's AST and fails if any endpoint reaches past the recorder — the
failure mode being guarded is an endpoint that passes every authorization test
while silently breaking the compliance requirement.

---

## D27 — Audit rows are attributed to the principal's tenant, not the resource's

**Decision.** On a denied cross-tenant attempt, the row is written under the
*attempting* user's tenant.

**Why — ownership.** Lab-broad's auditor is the party who needs to see that
their own user is probing other labs. Lab-sanger learns nothing actionable from
a request that was blocked before touching their data.

**Why — mechanics, and this is the decisive reason.** Writing the row under the
target tenant is *blocked by the RLS WITH CHECK policy*, because the session is
bound to the principal's tenant. Verified directly:

```
SET biovault.tenant_id = 'lab-broad';
INSERT INTO audit_entries (..., tenant_id='lab-sanger', ...);
ERROR:  new row violates row-level security policy for table "audit_entries"

INSERT INTO audit_entries (..., tenant_id='lab-broad', ...);
INSERT 0 1
```

Had I chosen the intuitive-seeming attribution, every cross-tenant intrusion
attempt would have raised an error instead of being recorded. A security
control (RLS) would have destroyed a security signal (the audit trail) — and
the bug would only surface during an actual intrusion, when the log is needed.

---

## D28 — Denials logged at WARNING in addition to the database

**Decision.** `authorize` emits a WARNING log line on every denial.

**Why.** A repeated pattern of denied cross-tenant reads is the signal an
intrusion investigation needs, and requiring a database query to notice it
means nobody notices in real time. The database row is the compliance record;
the log line is the operational alert.

---

## OPEN-1 — `rotate_kek` script referenced but not yet written

`docs/key-rotation.md` step 3 documents
`python -m biovault.scripts.rotate_kek --from kek-1 --to kek-2`. The
`rewrap_data_key` primitive it depends on exists and is tested, but the CLI
wrapper does not exist yet. It needs the database layer (task #4) first.

**Must be resolved before the README claims key rotation is operational.**
Tracked so the doc does not silently become a false claim.
