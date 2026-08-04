"""A privacy debit must survive the failure of the query that incurred it.

The disclosure and the response are separate events. Rows are read off disk
whether or not the caller ever sees an answer, so a debit that rolls back with
a failed query makes the read free — and free reads defeat the budget, which is
the actual privacy control.

This was a live bug. With the charge sharing the query's transaction, 30
deliberately-aborted queries performed 90 site reads across three labs and left
both ledgers at exactly zero. It needed no attacker: a statement timeout, a
connection reset, or a client disconnect unwinds identically.

The tests below abort a query *after* the charge and *after* the reads, then
assert the ledgers still moved. They are written against the observable ledger
rather than against `ledger_session`, so a future refactor that keeps the
behaviour passes and one that reintroduces shared-transaction semantics fails
however it is spelled.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text

import biovault.federation.cohort as cohort_module
from biovault.federation.budget import BudgetExhausted
from biovault.federation.cohort import CohortQuery, run_federated_cohort_query

pytestmark = [pytest.mark.security, pytest.mark.integration]

BROAD = "lab-broad"


@pytest.fixture
def ledgers(live_settings):
    """Read totals from both privacy ledgers on an independent connection.

    Independent because the point of these tests is what survived a *committed*
    transaction; reading through the same session under test would beg the
    question.
    """
    engine = create_engine(live_settings.database_url(as_owner=True), future=True)

    with engine.begin() as conn:
        conn.execute(text("TRUNCATE privacy_budget_entries, inbound_epsilon_entries"))

    def read() -> tuple[float, float]:
        with engine.begin() as conn:
            outbound = conn.execute(
                text("SELECT COALESCE(SUM(epsilon_spent), 0) FROM privacy_budget_entries")
            ).scalar_one()
            inbound = conn.execute(
                text(
                    "SELECT COALESCE(SUM(epsilon_extracted), 0) "
                    "FROM inbound_epsilon_entries"
                )
            ).scalar_one()
        return float(outbound), float(inbound)

    yield read

    with engine.begin() as conn:
        conn.execute(text("TRUNCATE privacy_budget_entries, inbound_epsilon_entries"))
    engine.dispose()


@pytest.fixture
def failing_combine(monkeypatch):
    """Make the query fail after the charge and after every site is read.

    Patching the combine step puts the failure as late as possible — past the
    debit, past all disclosure — which is the worst case for durability.
    """

    def explode(*_args, **_kwargs):
        raise RuntimeError("simulated late failure")

    monkeypatch.setattr(cohort_module, "combine_federated_counts", explode)


def test_outbound_charge_survives_a_failure_after_the_read(
    ledgers, failing_combine
) -> None:
    """The querier pays even when the query dies before returning."""
    before_outbound, _ = ledgers()

    with pytest.raises(RuntimeError):
        run_federated_cohort_query(
            query=CohortQuery(gene="BRCA1", epsilon=0.1),
            requesting_tenant=BROAD,
            actor_id="u-broad-research",
        )

    after_outbound, _ = ledgers()
    assert after_outbound > before_outbound, (
        "the outbound charge rolled back with the failed query; the site reads "
        "already happened, so this read was free"
    )


def test_inbound_charges_survive_a_failure_after_the_read(
    ledgers, failing_combine
) -> None:
    """Source labs' extraction ceilings must record what was taken from them.

    The querier overpaying is a utility loss. A source lab failing to record an
    extraction that actually occurred is a privacy loss, and the one that lets
    a lab be drained without its own ledger noticing.
    """
    _, before_inbound = ledgers()

    with pytest.raises(RuntimeError):
        run_federated_cohort_query(
            query=CohortQuery(gene="BRCA1", epsilon=0.1),
            requesting_tenant=BROAD,
            actor_id="u-broad-research",
        )

    _, after_inbound = ledgers()
    assert after_inbound > before_inbound, (
        "inbound extraction charges rolled back; the source labs' records were "
        "read but their ceilings did not move"
    )


def test_repeated_aborted_queries_exhaust_the_budget(ledgers, failing_combine) -> None:
    """THE regression test.

    Under the bug, aborting repeatedly gave unlimited free queries and the
    ledger stayed at zero forever. Now the budget must run out, exactly as it
    would for honest use.
    """
    charged = refused = 0
    for _ in range(30):
        try:
            run_federated_cohort_query(
                query=CohortQuery(gene="BRCA1", epsilon=0.1),
                requesting_tenant=BROAD,
                actor_id="attacker",
            )
        except BudgetExhausted:
            refused += 1
        except RuntimeError:
            charged += 1

    assert charged > 0, "no query got far enough to be charged"
    assert refused > 0, (
        f"30 aborted queries and none were refused: {charged} were charged but "
        "the budget never ran out, so aborting still buys free queries"
    )

    outbound, inbound = ledgers()
    assert outbound > 0 and inbound > 0, (
        f"both ledgers must record the aborted queries; got "
        f"outbound={outbound}, inbound={inbound}"
    )


def test_an_aborted_query_costs_the_same_as_a_successful_one(ledgers) -> None:
    """Aborting must not be cheaper than completing.

    If it were, an attacker would simply always abort. The comparison is the
    property; the absolute figure is incidental.
    """
    before, _ = ledgers()
    run_federated_cohort_query(
        query=CohortQuery(gene="BRCA1", epsilon=0.1),
        requesting_tenant=BROAD,
        actor_id="u-broad-research",
    )
    honest_cost = ledgers()[0] - before

    import biovault.federation.cohort as module

    original = module.combine_federated_counts
    module.combine_federated_counts = lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("late failure")
    )
    try:
        before_aborted, _ = ledgers()
        with pytest.raises(RuntimeError):
            run_federated_cohort_query(
                query=CohortQuery(gene="BRCA1", epsilon=0.1),
                requesting_tenant=BROAD,
                actor_id="attacker",
            )
        aborted_cost = ledgers()[0] - before_aborted
    finally:
        module.combine_federated_counts = original

    assert aborted_cost == pytest.approx(honest_cost), (
        f"aborting cost {aborted_cost} but completing cost {honest_cost}; "
        "the cheaper path is the one an attacker takes"
    )
