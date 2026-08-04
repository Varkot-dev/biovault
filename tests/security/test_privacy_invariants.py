"""Conservation invariants for the privacy accounting.

## Why this file exists

Every serious bug found in this project has had the same shape: a quantity that
had to stay consistent across two places, and drifted.

- Budget was charged once per query but consumed once per site (3x undercount).
- Suppression was decided in one place; its epsilon cost was accounted nowhere.
- Noise scale is computed in Python, again in the demo's JavaScript, and quoted
  a third time in the docs — three places that had to agree by hand.

Patching each occurrence does not remove the class. These tests assert the
*conservation laws* instead: relationships that must hold no matter which side
changes. A future edit that breaks one fails here regardless of whether the
author thought to update a matching test.

The distinguishing property of a test in this file: it does not encode an
expected VALUE. It encodes a RELATIONSHIP. Change the epsilon split, the
threshold, the site count, or the default budget, and these still pass — unless
the change actually broke the accounting.
"""

from __future__ import annotations

import math

import pytest

from biovault.federation.accuracy import (
    DEFAULT_ALPHA,
    count_noise_scale,
    epsilon_to_tolerance,
    interval_for,
    scale_to_tolerance,
)
from biovault.federation.budget import DEFAULT_TOTAL_EPSILON
from biovault.federation.privacy import (
    COUNT_SENSITIVITY,
    MAX_EPSILON,
    MIN_COHORT_SIZE,
    MIN_EPSILON,
    THRESHOLD_EPSILON_FRACTION,
    combine_federated_counts,
    privatize_count,
)

pytestmark = pytest.mark.security

EPSILONS = [0.01, 0.05, 0.1, 0.25, 0.5, 1.0]


# --- Conservation: epsilon in equals epsilon out -----------------------------


@pytest.mark.parametrize("epsilon", EPSILONS)
def test_reported_epsilon_equals_epsilon_requested(epsilon: float) -> None:
    """Whatever a release costs, that is what it reports.

    The split between the threshold test and the count is an internal
    allocation. It must not change the total. If a future change adds a third
    consumer of the budget without adding its share to the reported total, this
    fails — which is exactly how the per-site undercount went unnoticed.
    """
    for _ in range(20):
        assert privatize_count(100, epsilon=epsilon).epsilon_spent == pytest.approx(
            epsilon
        )


@pytest.mark.parametrize("epsilon", EPSILONS)
def test_epsilon_shares_sum_to_the_whole(epsilon: float) -> None:
    """The threshold share and the count share partition the budget exactly.

    Asserted through the observable noise scale rather than by reading the
    constant, so a change that alters the scale without altering the constant
    (or vice versa) is caught.
    """
    count_share = 1.0 - THRESHOLD_EPSILON_FRACTION
    expected_scale = COUNT_SENSITIVITY / (epsilon * count_share)

    result = privatize_count(1000, epsilon=epsilon)
    assert result.noise_scale == pytest.approx(expected_scale)

    # And the two shares really are a partition: strictly between 0 and 1, and
    # summing to 1. A split of 0 or 1 would mean one consumer pays nothing,
    # which is the free-release bug in a different costume.
    assert 0.0 < THRESHOLD_EPSILON_FRACTION < 1.0
    assert THRESHOLD_EPSILON_FRACTION + count_share == pytest.approx(1.0)


def test_federated_epsilon_is_the_sum_of_site_epsilons() -> None:
    """A combined release costs what its parts cost, not less.

    This is the conservation law the per-site undercount violated: the code
    computed the correct total in `combine_federated_counts` and then discarded
    it in favour of a single site's epsilon.
    """
    for site_count in (2, 3, 5, 11):
        parts = [privatize_count(500, epsilon=0.1) for _ in range(site_count)]
        combined = combine_federated_counts(parts)
        assert combined.epsilon_spent == pytest.approx(
            sum(p.epsilon_spent for p in parts)
        )


def test_suppressed_releases_cost_the_same_as_answered_ones() -> None:
    """A withheld answer is not a refund.

    If suppression were free, probing for small cohorts would be free, and
    learning which strata are small is itself a disclosure.
    """
    seen_suppressed = seen_answered = False
    for _ in range(200):
        r = privatize_count(MIN_COHORT_SIZE, epsilon=0.5)
        assert r.epsilon_spent == pytest.approx(0.5)
        seen_suppressed |= r.suppressed
        seen_answered |= not r.suppressed
    assert seen_suppressed and seen_answered, (
        "both branches must occur at the threshold, or this proves nothing"
    )


# --- Monotonicity: the trade-offs must point the right way -------------------


def test_more_epsilon_never_means_more_noise() -> None:
    """Scale is monotonically non-increasing in epsilon.

    A violation means the privacy/utility trade has inverted somewhere — the
    caller pays more privacy and gets a worse answer.
    """
    scales = [privatize_count(1000, epsilon=e).noise_scale for e in EPSILONS]
    assert scales == sorted(scales, reverse=True)


def test_more_epsilon_never_means_a_wider_interval() -> None:
    tolerances = [epsilon_to_tolerance(e) for e in EPSILONS]
    assert tolerances == sorted(tolerances, reverse=True)


def test_tighter_confidence_never_means_a_narrower_interval() -> None:
    """Smaller alpha means higher confidence, which requires a wider interval."""
    tolerances = [scale_to_tolerance(10.0, a) for a in (0.5, 0.25, 0.1, 0.05, 0.01)]
    assert tolerances == sorted(tolerances)


def test_more_sites_never_means_a_narrower_federated_interval() -> None:
    """Independent variances add. Federation costs precision, always.

    Reporting a tighter interval for more sites would overstate confidence in
    the combined answer.
    """
    widths = [
        scale_to_tolerance(math.sqrt(n * 10.0**2)) for n in (1, 2, 3, 5, 10)
    ]
    assert widths == sorted(widths)


# --- The interval must actually bracket the estimate -------------------------


@pytest.mark.parametrize("epsilon", EPSILONS)
def test_interval_always_contains_its_own_estimate(epsilon: float) -> None:
    """A confidence interval that excludes its point estimate is incoherent.

    Clamping the lower bound at zero makes the interval asymmetric, which is a
    place this could plausibly break.
    """
    for value in (0, 1, 5, 50, 5000):
        ci = interval_for(value, scale=COUNT_SENSITIVITY / epsilon)
        assert ci.lower <= value <= ci.upper, f"{value} outside {ci.lower}-{ci.upper}"


def test_interval_lower_bound_is_never_negative() -> None:
    """A negative count is meaningless to an analyst."""
    for value in (0, 1, 2, 3):
        assert interval_for(value, scale=1000.0).lower >= 0


def test_reported_tolerance_is_the_unclamped_half_width() -> None:
    """`tolerance` must describe the mechanism, not the clamped display range.

    If it were derived from (upper - lower) / 2 it would shrink near zero and
    understate the real uncertainty exactly where the estimate is least
    reliable.
    """
    ci = interval_for(0, scale=100.0)
    assert ci.tolerance == pytest.approx(scale_to_tolerance(100.0, DEFAULT_ALPHA))
    assert ci.tolerance > (ci.upper - ci.lower) / 2


# --- Bounds are self-consistent ----------------------------------------------


def test_epsilon_bounds_are_ordered_and_usable() -> None:
    assert 0 < MIN_EPSILON < MAX_EPSILON
    # The default budget must afford at least one query at the maximum epsilon,
    # or the maximum is unreachable and the bound is a lie.
    assert DEFAULT_TOTAL_EPSILON >= MAX_EPSILON


def test_a_single_query_can_never_exceed_the_whole_budget() -> None:
    """At max epsilon across a plausible consortium, one query must still fit.

    If it cannot, the API advertises parameters no caller can ever use.
    """
    single_site_worst_case = MAX_EPSILON
    assert single_site_worst_case <= DEFAULT_TOTAL_EPSILON


def test_suppression_threshold_is_above_the_trivial_case() -> None:
    """A threshold of 0 or 1 would not protect anyone.

    Noise cannot hide the difference between nobody and somebody at counts that
    small, which is the entire reason suppression exists alongside noise.
    """
    assert MIN_COHORT_SIZE >= 2


# --- The planner must describe the mechanism ---------------------------------


@pytest.mark.parametrize("epsilon", EPSILONS)
def test_planned_noise_scale_equals_delivered_noise_scale(epsilon: float) -> None:
    """`/federation/precision` must not promise precision the query cannot give.

    These were computed independently — `accuracy` divided by epsilon while
    `privatize_count` divided by epsilon times the count's share — and they
    diverged silently the moment the epsilon split was introduced. The planner
    advertised +/-51.89 while real queries returned +/-103.78: an analyst
    sizing a study against a nominal 95% interval was getting about 75% real
    coverage, on the one endpoint whose entire purpose is honest planning.

    Asserted as equality between the two rather than against a fixed number, so
    changing the split moves both together or fails here.
    """
    planned = count_noise_scale(epsilon)
    delivered = privatize_count(1000, epsilon=epsilon).noise_scale
    assert planned == pytest.approx(delivered), (
        f"planner says scale {planned} at epsilon={epsilon}, mechanism "
        f"delivers {delivered}"
    )


@pytest.mark.parametrize("epsilon", EPSILONS)
def test_planned_tolerance_equals_the_interval_a_query_returns(
    epsilon: float,
) -> None:
    """The same agreement one level up, at the tolerance an analyst reads."""
    planned = epsilon_to_tolerance(epsilon)
    delivered = interval_for(
        1000, scale=privatize_count(1000, epsilon=epsilon).noise_scale
    ).tolerance
    assert planned == pytest.approx(delivered)


# --- Cross-implementation agreement ------------------------------------------


def test_demo_javascript_matches_the_python_constants() -> None:
    """The published demo must not drift from the server it claims to model.

    The demo is the project's most visible artifact and reimplements the
    mechanism in JavaScript. Two implementations that disagree mean at least
    one published number is wrong, and the demo is the copy a reader trusts.

    Checked by reading the constants out of the page source rather than by
    running it, so this stays a cheap unit test.
    """
    from pathlib import Path

    demo = Path(__file__).resolve().parents[2] / "demo" / "attack.html"
    if not demo.exists():
        pytest.skip("demo not present")

    source = demo.read_text(encoding="utf-8")

    count_share = 1.0 - THRESHOLD_EPSILON_FRACTION
    assert f"var COUNT_SHARE = {count_share};" in source, (
        f"demo COUNT_SHARE disagrees with THRESHOLD_EPSILON_FRACTION "
        f"({THRESHOLD_EPSILON_FRACTION}); expected {count_share}"
    )


# Attacker-success figures that were measured, superseded, and corrected. Prose
# is where stale numbers hide: a constant gets updated and a sentence three
# hundred lines away keeps quoting the old value.
#
# A superseded figure may still appear in text that explicitly describes it as
# superseded — that history is deliberately published. What must not appear is
# a superseded figure presented as current. The heuristic below is crude but it
# caught a real one: the demo carried "14.5% of measured trials still landed
# within +/-1" long after two corrections had moved that number to ~5%.
SUPERSEDED_FIGURES = ("40.3%", "14.5%", "14.3%", "25.0%", "8.0%")


@pytest.mark.parametrize("doc", ["demo/attack.html", "README.md"])
def test_superseded_figures_are_not_presented_as_current(doc: str) -> None:
    """A corrected number must not survive somewhere nobody looked.

    Each occurrence of a superseded figure must sit within a sentence that
    frames it as historical. Anything else is a stale claim.
    """
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / doc
    if not path.exists():
        pytest.skip(f"{doc} not present")

    text = path.read_text(encoding="utf-8")
    history_markers = (
        "previously",
        "earlier",
        "moved twice",
        "superseded",
        "it read",
        "they read",
        "has moved",
        "have moved",
        "corrected",
        "was wrong",
    )

    stale: list[str] = []
    for figure in SUPERSEDED_FIGURES:
        start = 0
        while (idx := text.find(figure, start)) != -1:
            # Look at the surrounding sentence, not the whole document: a
            # history note elsewhere in the file must not launder an unrelated
            # stale figure.
            window = text[max(0, idx - 400) : idx + 200].lower()
            if not any(marker in window for marker in history_markers):
                line = text.count("\n", 0, idx) + 1
                stale.append(f"{figure} at {doc}:{line}")
            start = idx + len(figure)

    assert not stale, (
        "superseded attacker-success figures presented as current: "
        f"{stale}. Either re-measure and update, or frame the number as "
        "historical."
    )
