"""The sensitivity assumption, asserted against the database rather than trusted.

Every epsilon figure in this system is calibrated to a sensitivity of 1: one
subject joining or leaving moves a federated count by at most 1. That is the
input to the Laplace scale, so if it is wrong, every published privacy figure
overstates the protection delivered — and nothing about the failure is visible.
Noise still gets added, ledgers still balance, the suite still passes.

The original code counted rows. It was correct only because the seed happened
to give each specimen one row per gene. A test that used that seed could never
have found the problem, so these tests deliberately construct the violating
case instead.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from biovault.federation.privacy import COUNT_SENSITIVITY

pytestmark = [pytest.mark.security, pytest.mark.integration]

BROAD = "lab-broad"


def _count_via_query(session, tenant: str, gene: str) -> int:
    """Call the real counting function the federated path uses."""
    from biovault.federation.cohort import _count_matching_records

    return _count_matching_records(session, tenant_id=tenant, gene=gene)


def test_one_extra_row_for_an_existing_subject_does_not_move_the_count(
    owner_session,
) -> None:
    """THE test. A subject already counted must not be counted twice.

    Compound heterozygosity — two pathogenic variants in the same gene — is the
    textbook clinical case for BRCA1 and CFTR, both of which are in the seed
    vocabulary. Under a row count this moves the answer by 1 while the
    mechanism adds noise sized for a maximum movement of 1, so the delivered
    epsilon doubles for that subject with nothing recording it.
    """
    from biovault.db.rls import set_tenant_context

    set_tenant_context(owner_session.connection(), BROAD)
    before = _count_via_query(owner_session, BROAD, "BRCA1")
    assert before > 0, "no BRCA1 subjects seeded; this test would be vacuous"

    existing = owner_session.execute(
        text(
            "SELECT specimen_label, dataset_id FROM genomic_records "
            "WHERE tenant_id = :t AND gene_symbol = 'BRCA1' LIMIT 1"
        ).bindparams(t=BROAD)
    ).one()

    # A second BRCA1 call for a subject already in the cohort.
    owner_session.execute(
        text(
            "INSERT INTO genomic_records "
            "(id, tenant_id, dataset_id, specimen_label, gene_symbol, "
            " contains_phi, payload_ciphertext) "
            "VALUES ('sens-probe-compound-het', :t, :d, :s, 'BRCA1', false, 'x')"
        ).bindparams(t=BROAD, d=existing.dataset_id, s=existing.specimen_label)
    )
    owner_session.flush()

    after = _count_via_query(owner_session, BROAD, "BRCA1")
    assert after == before, (
        f"a second row for an already-counted subject moved the count "
        f"{before} -> {after}. Sensitivity is not 1, so every epsilon figure "
        f"understates the real privacy loss."
    )


def test_a_genuinely_new_subject_moves_the_count_by_exactly_one(
    owner_session,
) -> None:
    """The other half. Deduplicating must not make the count insensitive.

    Without this, `COUNT(DISTINCT ...)` over a constant would also pass the
    test above while answering nothing.
    """
    from biovault.db.rls import set_tenant_context

    set_tenant_context(owner_session.connection(), BROAD)
    before = _count_via_query(owner_session, BROAD, "BRCA1")

    dataset_id = owner_session.execute(
        text(
            "SELECT dataset_id FROM genomic_records "
            "WHERE tenant_id = :t AND gene_symbol = 'BRCA1' LIMIT 1"
        ).bindparams(t=BROAD)
    ).scalar_one()

    owner_session.execute(
        text(
            "INSERT INTO genomic_records "
            "(id, tenant_id, dataset_id, specimen_label, gene_symbol, "
            " contains_phi, payload_ciphertext) "
            "VALUES ('sens-probe-new-subject', :t, :d, "
            "        'SPEC-SENSITIVITY-PROBE', 'BRCA1', false, 'x')"
        ).bindparams(t=BROAD, d=dataset_id)
    )
    owner_session.flush()

    after = _count_via_query(owner_session, BROAD, "BRCA1")
    assert after == before + 1, (
        f"a new subject moved the count {before} -> {after}; expected +1"
    )


@pytest.mark.parametrize("extra_rows", [2, 3, 5])
def test_sensitivity_holds_however_many_rows_a_subject_contributes(
    owner_session, extra_rows: int
) -> None:
    """Longitudinal resequencing and tumour/normal pairs, not just het pairs.

    The row count would have moved by `extra_rows`; the subject count must not
    move at all.
    """
    from biovault.db.rls import set_tenant_context

    set_tenant_context(owner_session.connection(), BROAD)
    before = _count_via_query(owner_session, BROAD, "TP53")

    existing = owner_session.execute(
        text(
            "SELECT specimen_label, dataset_id FROM genomic_records "
            "WHERE tenant_id = :t AND gene_symbol = 'TP53' LIMIT 1"
        ).bindparams(t=BROAD)
    ).one()

    for n in range(extra_rows):
        owner_session.execute(
            text(
                "INSERT INTO genomic_records "
                "(id, tenant_id, dataset_id, specimen_label, gene_symbol, "
                " contains_phi, payload_ciphertext) "
                "VALUES (:i, :t, :d, :s, 'TP53', false, 'x')"
            ).bindparams(
                i=f"sens-probe-multi-{extra_rows}-{n}",
                t=BROAD,
                d=existing.dataset_id,
                s=existing.specimen_label,
            )
        )
    owner_session.flush()

    after = _count_via_query(owner_session, BROAD, "TP53")
    assert after == before, (
        f"{extra_rows} extra rows for one subject moved the count "
        f"{before} -> {after}; sensitivity is {after - before}, not 1"
    )


def test_the_declared_sensitivity_matches_what_the_query_delivers(
    owner_session,
) -> None:
    """`COUNT_SENSITIVITY` must describe the query that is actually run.

    A future change to the counting expression that raises real sensitivity
    without raising this constant would leave every epsilon figure overstating
    the protection. Measured as the largest movement one subject can cause.
    """
    from biovault.db.rls import set_tenant_context

    set_tenant_context(owner_session.connection(), BROAD)
    before = _count_via_query(owner_session, BROAD, "CFTR")

    existing = owner_session.execute(
        text(
            "SELECT specimen_label, dataset_id FROM genomic_records "
            "WHERE tenant_id = :t AND gene_symbol = 'CFTR' LIMIT 1"
        ).bindparams(t=BROAD)
    ).one()

    for n in range(4):
        owner_session.execute(
            text(
                "INSERT INTO genomic_records "
                "(id, tenant_id, dataset_id, specimen_label, gene_symbol, "
                " contains_phi, payload_ciphertext) "
                "VALUES (:i, :t, :d, :s, 'CFTR', false, 'x')"
            ).bindparams(
                i=f"sens-probe-declared-{n}",
                t=BROAD,
                d=existing.dataset_id,
                s=existing.specimen_label,
            )
        )
    owner_session.flush()

    observed_sensitivity = abs(_count_via_query(owner_session, BROAD, "CFTR") - before)
    assert observed_sensitivity <= COUNT_SENSITIVITY, (
        f"one subject moved the count by {observed_sensitivity}, but "
        f"COUNT_SENSITIVITY is {COUNT_SENSITIVITY}. Laplace noise is sized "
        f"for {COUNT_SENSITIVITY}, so delivered epsilon is "
        f"{observed_sensitivity / COUNT_SENSITIVITY:.0f}x what is recorded."
    )
