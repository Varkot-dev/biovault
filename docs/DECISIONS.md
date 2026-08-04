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

## D29 — Denials return 404, never 403

**Decision.** Every authorization denial returns the same 404 and body as a
genuinely missing resource.

**Why.** A 403 confirms the resource exists. An attacker enumerating
`/datasets/<id>` against a 403/404 boundary maps another lab's holdings without
reading a single record — and dataset names alone can disclose research
direction (`huntingtons-cohort-2024`). Returning an identical 404 for both
collapses that oracle.

**Guarded by.** `test_denied_and_nonexistent_are_indistinguishable`, which
compares both status code *and* response body.

---

## D30 — Missing-resource requests are still audited

**Decision.** Handlers call `authorize()` before raising 404 on a dataset that
does not exist.

**Why.** Probing for valid dataset identifiers is itself an attack signal.
Without this call, an enumeration sweep would leave *no trace* in the audit
log precisely because none of the guesses landed — the reconnaissance phase
would be invisible while the successful hit was recorded.

---

## D31 — LIKE metacharacters escaped in the query filter

**Decision.** `%`, `_`, and `\` are escaped in `specimen_label` before binding,
with an explicit `escape="\\"`.

**Why.** Parameterization stops SQL injection but not *filter widening*: a
bound value of `%` is still a valid LIKE wildcard matching every row. That
turns a narrow lookup into a full dataset scan, which is an exfiltration
primitive rather than an injection one.

**Guarded by.** `test_like_wildcards_are_escaped`, which asserts a bare `%`
returns zero rows while an unfiltered query returns many.

---

## D32 — Rate limiting keyed by subject, falling back to IP

**Decision.** `rate_limit_key` prefers the JWT `sub` claim, read *without*
signature verification, and falls back to the client address.

**Why.** Keying purely on IP would let one user behind a shared institutional
NAT exhaust the budget for their entire lab — a realistic scenario for research
networks with a single egress address.

**Why unverified decoding is safe here.** The value selects a rate-limit bucket
and grants no access. A forged token can at worst move an attacker into a
different bucket, which does not help them. The authorization path verifies
signatures properly; conflating the two would be the mistake.

---

## D33 — Test pollution fixed by scoping, not by deleting rows

**Problem.** Ten audit tests passed in isolation but failed in the full suite.
The API tests run first and commit 232 audit rows for `u-broad-research`, so
assertions like `len(entries) == 1` saw 233.

**Decision.** Each audit test gets a unique random actor id via fixture.

**Why not clean the table.** The append-only design deliberately makes deletion
impossible for the app role. Granting a test path the ability to delete audit
rows would weaken the exact property `test_app_role_cannot_delete_audit_entries`
verifies. Scoping the assertions is the fix that does not compromise the
control.

**Verified.** Suite passes twice consecutively (data accumulating between runs)
and with the file order reversed. A fix that only worked once would not be a
fix.

---

## D34 — Defense-in-depth demonstrated by deliberate sabotage

**Observation.** With the application-layer `authorize()` gate deleted from the
query endpoint, only 2 of 46 API security tests failed —
`test_idor_within_own_tenant_without_grant_is_denied` and
`test_auditor_cannot_read_dataset_contents`.

**Every cross-tenant IDOR test still passed**, because PostgreSQL RLS blocked
those requests independently. That is the defense-in-depth claim demonstrated
rather than asserted: one full layer removed, and tenant isolation held.

The two tests that did fail are exactly the cases RLS cannot cover — a
*within*-tenant grant check and a role-capability check, neither of which is
expressible as a row filter. That division of labour is the reason both layers
exist.

---

## D35 — CI gates coverage with `--cov-fail-under`, not a custom parser

**Decision.** The first draft wrote `coverage.xml` and parsed it in Python to
enforce the floor. Replaced with coverage.py's own `--cov-fail-under=80`.

**Why.** A tooling hook flagged the stdlib XML parser as XXE-prone. The better
fix was removing the parsing step entirely rather than reaching for
`defusedxml`: a hand-rolled gate has a silent-pass failure mode. If
`coverage.xml` were never written — test crash, wrong path, changed flag — a
parser that caught the exception or defaulted to `0` would let the build
through. Letting the tool that owns the data enforce its own threshold has no
such gap.

---

## D36 — `pip-audit` runs against a frozen requirements list

**Decision.** `pip freeze --exclude-editable` into a file, then
`pip-audit --strict -r <file>`.

**Why.** A bare `pip-audit --strict` fails with
`biovault: Dependency not found on PyPI` because our own package is installed
editable and unpublished. `--skip-editable` also errors under `--strict`. Both
produce a red build that *looks* like a vulnerability finding but is a
configuration error — the worst kind of CI failure, because it trains people to
ignore the job.

**Measured.** 72 packages audited, no known vulnerabilities.

---

## D37 — CI asserts RLS preconditions in SQL before running any test

**Decision.** The `security-smoke` job runs a `DO $$ ... $$` block that raises
unless RLS is enabled *and* forced on all six tenant-scoped tables, and unless
`biovault_app` lacks both `SUPERUSER` and `BYPASSRLS`.

**Why.** Those are the conditions under which the isolation tests are
meaningful. Without them the tests would pass while proving nothing — the
failure mode this project most needs to avoid.

**Verified to fail.** `NO FORCE ROW LEVEL SECURITY` on a single table made the
block exit 3 with `RLS not enabled/forced on 1 table(s)`. A guard never
observed failing is not known to work.

---

## RESOLVED-1 — `rotate_kek` script now exists and is verified

Previously tracked as OPEN-1: `docs/key-rotation.md` documented a CLI that had
not been written.

**Now implemented** at `src/biovault/scripts/rotate_kek.py` with `--dry-run`,
and exercised end-to-end against the live database:

```
BEFORE                    kek-1 | 4
DRY RUN                   would rotate 4 dataset key(s)   → kek-1 | 4  (unchanged)
ROTATE                    rotated 4 dataset key(s)        → kek-2 | 4
plaintext before          BRCA1:c.0000A>T:GT=0/1:DP=42;dataset=ds-broad-cohort-1;idx=0
plaintext after (new KEK) BRCA1:c.0000A>T:GT=0/1:DP=42;dataset=ds-broad-cohort-1;idx=0
```

`test_rotation_preserves_plaintext_without_touching_ciphertext` additionally
asserts the record's `payload_ciphertext` column is **byte-identical** across
rotation, which is the actual proof that bulk data was never re-encrypted —
the entire operational justification for envelope encryption.

The script aborts the whole run if any key fails to unwrap, rather than leaving
a half-rotated estate that would make "is anything still on the old key?"
unanswerable.

---

## D38 — Every private count ships with a confidence interval

**Decision.** `FederatedCohortResult.total` is never returned without
`interval`. Derived from the Laplace tail bound `accuracy = -scale * ln(alpha)`,
matching OpenDP's `laplacian_scale_to_accuracy`.

**Why.** A bare noised integer is a misleading answer. At the default epsilon a
returned count of `12` has a 95% interval of `0-55` — an analyst without that
interval will publish a finding that isn't there. Returning the interval is the
difference between a number and a measurement.

**Verified, not assumed.** Empirical coverage across scales 2/10/20 and alpha
0.01/0.05/0.10 lands within 0.15% of nominal in all nine configurations.

**Federated combination.** Per-site variances add, so the combined tolerance is
the root-sum-of-squares. Applying a single-Laplace tail bound to that combined
scale is conservative — a sum of independent Laplace variables has lighter
tails — measured at 95.5-96.0% against a nominal 95%.

**Scope stated in the code.** The interval bounds *only* the privacy noise. Not
sampling error, not selection bias. Presenting it as a total error bar would
understate the real uncertainty.

---

## D39 — `/federation/precision` costs no budget

**Decision.** An endpoint returning the tolerance implied by an epsilon, before
any query runs.

**Why.** Tolerance depends only on epsilon and site count, never on the data,
so exposing it is free. Without it an analyst discovers mid-study that every
answer is too noisy to publish — having already burned the budget producing
nothing. At epsilon=0.1 the answer is +/-30 with 10 queries affordable, which is
often enough to establish that a question is not answerable at all.

---

## D40 — Review corrections to the accuracy work

An independent review re-derived the math and simulated the bounds. Zero
critical or high findings; the derivation and the conservative federated
combination both held. Three things it surfaced were worth writing down:

**The fingerprint comment was framed wrong.** I had written that `alpha` is
excluded from `CohortQuery.fingerprint()` to stop an attacker fragmenting their
audit trail. The reasoning is right but the framing implied alpha needed a
special carve-out — in fact the hash only ever covered `variant_prefix`, so the
protection is structural. The real risk is a *future* field being added "for
completeness." The comment now states the rule: before adding a field to the
hash, ask whether two queries differing only in that field are asking about the
same people.

**Interval width is data-dependent, and now says so.** Suppression is decided
from each site's true count, so `sites_contributing` — and therefore the
reported tolerance — depends on the data. This is not a new disclosure, since
`sites_contributing` is already returned in plaintext deliberately. But the
accuracy module's data-independence claim was true only in isolation from its
caller, and the coupling is now documented at the call site.

**Clamping before summation does not break the bound.** Each site clamps at
zero before the federated sum, which the tolerance formula does not model —
this looks like a hole. It is not: true counts are non-negative, so clamping
only moves an estimate toward the truth. Verified at the worst available case
(epsilon=0.01, counts at the suppression floor, a site clamping ~half the
time): coverage 96.6-97.2% against nominal 95%. Recorded in the docstring so a
future reader does not have to rediscover why it is safe.

---

## D41 — Federated queries cost ε × sites, not ε (bug fix)

**The bug.** `run_federated_cohort_query` charged the budget once per query
while calling `privatize_count` once per *site*. With three labs, one query
made three Laplace releases and recorded 0.1. Actual privacy loss was 0.3.

**Impact.** A tenant with a budget of 1.0 believed it had 10 queries and
received 30 releases' worth of leakage. This also made the published
attacker-success table wrong: it was calibrated against an accounting that
undercounted threefold.

**Confirmed empirically before fixing:**

```
sites queried            : 3
Laplace releases made    : 3
epsilon CHARGED to ledger: 0.1
UNDERCOUNT FACTOR        : 3x
```

**Fix.** Enumerate sites before charging; charge `epsilon * len(sites)`; report
the same figure. Affordable queries at the default drop from a false 10 to a
true 3.

**The composition question this exposed, now written down.** If the labs held
*disjoint* patient populations, parallel composition would apply and ε would be
the correct charge — a given person appears at one site, so the releases do not
compound for them. BioVault does not assume disjointness. In a real genomics
consortium patients appear at multiple institutions, which is exactly why
cross-lab queries are valuable, and overlap cannot be detected without linking
identities across tenants — the thing the system exists to prevent. Sequential
composition is the safe reading. The original code assumed neither consistently:
it charged as though populations were disjoint while releasing as though they
were not.

**The corrected numbers are better, not worse.** Attacker success at the default
fell from a reported 14.3% to a measured 8.0%, and at the tutorial default from
40.3% to 25.0%. Fixing the accounting tightened the real guarantee.

---

## D42 — Clamp once at the federated total, not per site (bug fix)

**The bug.** Each site clamped its noised count at zero *before* the federated
sum. Clamping truncates the negative tail only, so summing clamped values
compounds an upward bias.

**Measured, three sites at ε=0.1:**

```
true per site   clamped sum   truth   bias
            3         20.07       9   +11.07
            6         26.32      18    +8.32
           10         35.53      30    +5.53
          100        300.03     300    +0.03
```

A federated total more than double the truth for small cohorts — precisely the
regime rare-variant genomics queries live in. The confidence interval was then
centred on that biased estimate, so its nominal coverage of the *true* total
was not what was delivered.

**Fix.** `NoisyCount` carries `raw_value`, the unclamped float. Federated sums
use it and clamp once at the end. Bias at three sites × six records fell from
+8.32 to +3.31, and to ~0.25 for cohorts large enough to be usable. The residual
is the single final clamp, which is unavoidable.

`raw_value` is never returned to a caller — it is an internal intermediate, not
a second, less-noisy view of the data.

---

## D43 — The suppression flag was a free, noiseless oracle (bug fix)

**The bug.** `privatize_count` compared the **true** count to the threshold. An
earlier comment defended this as the safe choice, reasoning that deciding on a
noised value would let an attacker infer which side of the threshold the truth
fell on. That was backwards, and it was the most serious hole in the module.

Comparing the true count makes `suppressed` a deterministic function of private
data — an exact bit of `count > 5`, published per site on every query, costing
nothing. Measured on the old code:

```
true=3 -> ALWAYS True     true=6  -> ALWAYS False
true=5 -> ALWAYS True     true=20 -> ALWAYS False
```

Invariant across 500 draws at every count. Vary the query predicate to
binary-search the boundary and an attacker recovers exact small counts at a
named lab — the differencing attack this module exists to stop, one free bit at
a time.

**Fix.** Compare a *noised* count instead, so the decision is itself a DP
release. The budget now splits between the threshold test and the count. The
5-versus-6 distinguishability gap fell from **1.000 to 0.014**.

**The split was tuned by measurement, and the first attempt was wrong.** A
draft used 0.25 with a comment claiming under 1% spurious suppression at
true=20; measurement said 35.6%. The final table:

```
fraction   count scale   suppressed@50   gap 5v6
  0.25         13.3          15.1%        0.010
  0.50         20.0           5.0%        0.021
  0.75         40.0           1.5%        0.050
```

0.50 balances both costs. Privacy barely varies across the range; utility
varies a lot, in two opposing directions.

**The 2x count-noise penalty is real and is the price.** The old code produced
a sharp count *and* a sharp flag because the flag was free — paid for by
leaking. Once the flag pays its own way, one budget covers two releases. There
was never a version where both were sharp and the guarantee held.

---

## D44 — Federated queries now match a real gene, not a specimen-ID substring

**The gap.** The query parameter was `variant_prefix` and the README promised
"how many patients carry this variant?", but the filter was a substring LIKE on
`specimen_label` — which holds `SPEC-{dataset}-{index}` and no variant
information whatsoever. The advertised capability did not exist.

**Fix.** `GenomicRecord.gene_symbol`, an indexed plaintext column. A gene symbol
is public knowledge and non-identifying alone; the identifying remainder of the
call (position, genotype, depth) stays encrypted and is never decrypted in the
federated path. Queries match on exact equality against a controlled
vocabulary, not LIKE — substring matching lets a caller narrow a predicate
character by character until it isolates one record, which is the setup for a
differencing attack.

**Seed rescaled.** Cohorts held at most three records per gene against a
threshold of five, so every cell suppressed correctly but uninformatively. Now
62–84 carriers per lab per gene.

---

## D45 — Consortium participation is opt-in, with an inbound extraction ceiling

**The gap.** Any lab in `tenants` was silently enrolled as a data source. The
README frames federation as the consent-compatible alternative to shipping
genomes; being enrolled by existing is the opposite.

Worse, nothing bounded extraction *from* a lab. The budget is charged to the
querier, so with N labs each holding an independent budget, total leakage
against any one lab scales with N and went untracked.

**Fix.** `consortium_participation` (absence means non-participating, so the
default is exclusion) and `inbound_epsilon_entries`, an append-only ledger
scoped to the lab being *queried*. Withdrawal is an UPDATE, not a DELETE — a
deleted row cannot be distinguished from a lab that never joined, losing
exactly the fact an ethics audit needs.

**Found while wiring it live: RLS hid the roster from itself.** Enumerating
participants inherently spans tenants, so a querier bound to its own tenant saw
only its own consent row and concluded it was the sole participant —
`sites=0/1` on a three-lab consortium, silently reducing federation to a
self-query. Fixed with a narrow SELECT-only policy, the same shape as the
pre-auth identity exception. Writes stay tenant-scoped, so no lab can opt
another in or forge a withdrawal.

---

## D46 — The README quickstart did not work from a clean clone (bug fix)

**The bug.** `.env.example` set `POSTGRES_HOST=localhost`. Docker Compose loads
`.env` into the service environment *and* gives it precedence over the compose
file's own `environment:` block, so `localhost` overrode the `db` service name
and the API could not resolve the database from inside the network:

```
sqlalchemy.exc.OperationalError: failed to resolve host 'db'
```

`docker compose up` — the first command in the README — failed for anyone
following it. It worked locally only because the development `.env` had been
hand-edited months of commits ago and never regenerated from the example.

**How it was found.** By cloning the public repo into a fresh directory and
running the documented quickstart verbatim, rather than assuming the local
working copy represented what a reader gets. Every prior verification ran
against a `.env` that no new user would ever have.

**Fix.** `.env.example` now ships `POSTGRES_HOST=db`, which is what the
documented path needs, with a comment explaining the precedence trap and how to
override it for host-side work. `docker-compose.yml` uses
`${POSTGRES_HOST:-db}` so the default survives a missing variable. The README's
verification and development sections now say to export
`POSTGRES_HOST=localhost` when running tests from the host, because those
connect from outside the Compose network.

**Verified.** Fresh clone → fill `.env` from the example → `docker compose up`
→ API healthy in 5 polls, federated query returns all three sites contributing
(total 329, interval 225–433 covering the true 226), unauthenticated requests
still 401.

**Worth noting.** CI was correct only by accident: its docker job writes a
`.env` that omits `POSTGRES_HOST` entirely, so the compose default applied,
while the test jobs get `localhost` from the workflow environment. Both paths
happened to be right for different reasons.

---

## D47 — Ledger writes commit independently of the query (critical bug fix)

**The bug.** `charge()` flushed but did not commit; the enclosing session
committed only after the query returned and rolled back on any exception. The
debit and the disclosure shared a transaction and failed together — while the
rows had already been read off disk.

**Measured.** 30 deliberately-aborted queries, 90 site reads across three labs,
both ledgers at exactly `0.0`. The `budget.py` docstring claimed "debiting
first means the failure mode is a paid-for answer the analyst never received."
The behaviour was the exact inverse.

Needed no attacker: a statement timeout, connection reset, or client disconnect
unwinds identically.

**The general lesson.** A privacy ledger and a data transaction have **opposite
atomicity requirements**. The ledger must survive the failure of the thing it
pays for; a data write must not. They cannot share a transaction. Added
`ledger_session()`, which commits on its own connection before any reading.

**Verified.** The same attack now charges 0.9 across 3 queries and the next 27
are refused.

---

## D48 — Sensitivity is a property of the query, not a constant

**The bug.** `COUNT_SENSITIVITY = 1.0` was justified as "one person changes any
count by at most 1", but the query counted **rows**. Nothing constrained a
subject to one row per gene — verified against the live schema: no uniqueness
constraint exists, and a second BRCA1 row for an existing specimen inserts
fine. Compound heterozygosity is the textbook case for BRCA1 and CFTR, both in
the seed vocabulary.

Delivered privacy degraded to `k·ε` while every ledger recorded `ε`. Same class
as the per-site undercount (D41), on the sensitivity axis rather than the
composition axis, and invisible to any test using the seed.

**Fix.** `COUNT(DISTINCT specimen_label)`. `specimen_label` is a *within-tenant*
identifier, so this needs no cross-tenant linkage and does not touch the
isolation model. Bounding a subject's exposure *across* labs is the separate,
architecturally harder problem tracked as issue #2.

---

## D49 — The planner must describe the mechanism

**The bug.** `/federation/precision` computed tolerance from `1/ε` while the
mechanism used `1/(ε · count_share)`. They were computed independently and
diverged the instant the epsilon split landed. Live: the planner advertised
±51.89 while a real query on identical parameters returned ±103.78. An analyst
sizing a study against a nominal 95% interval got roughly 75% real coverage.

**Fix.** `count_noise_scale()` is now the single place that knows the split;
`epsilon_to_tolerance` and the endpoint both derive from it. Invariants assert
planner and mechanism agree at every epsilon.

---

## D50 — What actually changed about the method

Six critical or high defects came out of one adversarial sweep — more than
every prior review combined. What made the difference was not more reviewers
but **assigning each a different lens**:

| Lens | What it found |
|---|---|
| Attack the *design*, not the code | Unit of privacy is the tenant, not the patient (#2); sensitivity unenforced (#1) |
| Attack the *seams* between subsystems | Ledger rollback (#7); missing federated audit trail (#8) |
| Red team with *legitimate credentials* | Per-lab holdings oracle (#9); `/participants` volume leak (#10) |
| *Falsify* every published number | Headline attacker figure wrong; precision endpoint 2× off; suite flaky |

Reviewers sharing a lens find the same bug repeatedly. The falsification lens
mattered most and is the one usually skipped — it treats the project's own
measurements as claims to disprove rather than as evidence.

Two structural changes came out of it, both aimed at the bug *class* rather
than its instances:

**Conservation invariants** (`test_privacy_invariants.py`) encode relationships,
not values — ε in equals ε out, planner agrees with mechanism, more sites never
narrows an interval. Changing a parameter leaves them passing; breaking the
accounting does not. Verified by injecting all three historical bugs.

**Guards proven to fail first.** Every guard added here was checked against the
defect it describes before being committed. A guard never observed failing is
not known to work — a lesson from the `.replace()` that silently no-opped and
left a stale figure in the demo.

---

## Final measured state

Clean database (`docker compose down -v`, rebuild, re-bootstrap), full run:

```
268 passed          87.95% coverage (floor 80%)          ruff: clean
pip-audit: 72 packages, no known vulnerabilities
```

100% coverage on the modules the security claims rest on: `db/rls.py`,
`audit/recorder.py`, `auth/refresh.py`, `auth/pkce.py`, `api/dependencies.py`.
`authz/policy.py` is at 97%. `db/bootstrap.py` sits at 30% — startup glue
verified end-to-end by `docker compose up` rather than by unit tests.
