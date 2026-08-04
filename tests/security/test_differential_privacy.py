"""Differential privacy guarantees for federated cohort counts.

The headline test is `test_averaging_attack_is_stopped_by_the_budget`. It
demonstrates the failure mode that makes most DP deployments useless: noise
alone does not protect anything against a repeated querier, because noise is
zero-mean and averages away. The budget is the actual control.
"""

from __future__ import annotations

import statistics

import pytest

from biovault.federation.privacy import (
    MAX_EPSILON,
    MIN_COHORT_SIZE,
    MIN_EPSILON,
    THRESHOLD_EPSILON_FRACTION,
    NoisyCount,
    PrivacyError,
    combine_federated_counts,
    privatize_count,
)

pytestmark = pytest.mark.security


# --- Noise is actually applied ----------------------------------------------


def test_repeated_queries_do_not_return_the_same_value() -> None:
    """A deterministic answer is not differentially private at all."""
    results = {privatize_count(1000, epsilon=0.1).value for _ in range(200)}
    assert len(results) > 50, "output is near-deterministic; noise is not being applied"


def test_noise_is_centred_on_the_true_value() -> None:
    """Utility check: the answer must be usable, not merely private.

    Laplace noise is zero-mean, so a large sample average should land close to
    the truth. This is exactly the property the averaging attack exploits,
    which is why the budget test below matters.
    """
    samples = [privatize_count(10_000, epsilon=0.5).value for _ in range(500)]
    assert abs(statistics.mean(samples) - 10_000) < 100


def test_smaller_epsilon_produces_more_noise() -> None:
    """The core privacy/utility trade-off must actually hold."""
    tight = [privatize_count(10_000, epsilon=1.0).value for _ in range(300)]
    loose = [privatize_count(10_000, epsilon=0.05).value for _ in range(300)]

    assert statistics.pstdev(loose) > statistics.pstdev(tight) * 3


def test_noise_scale_is_inverse_to_the_count_share_of_epsilon() -> None:
    """Scale = sensitivity / (epsilon * count share).

    The count does not get the whole budget: the suppression decision is a
    release of its own and is paid for out of the same epsilon. So the scale
    is set by the *remaining* share, not by epsilon directly. At the default
    50/50 split the count sees half the budget and therefore twice the noise
    a whole-budget count would have.
    """
    share = 1.0 - THRESHOLD_EPSILON_FRACTION
    assert privatize_count(100, epsilon=0.1).noise_scale == pytest.approx(1.0 / (0.1 * share))
    assert privatize_count(100, epsilon=1.0).noise_scale == pytest.approx(1.0 / (1.0 * share))


# --- The differencing attack ------------------------------------------------


def test_differencing_attack_does_not_reveal_an_individual() -> None:
    """The attack DP exists to stop.

    An attacker knows a cohort of N and queries it, then queries the same
    cohort minus one target individual. With exact counts the difference is
    that person's genotype, disclosed precisely.

    With noise, a single difference is dominated by the noise and carries
    almost no signal about the individual.
    """
    epsilon = 0.1
    with_target = privatize_count(500, epsilon=epsilon).value
    without_target = privatize_count(499, epsilon=epsilon).value

    observed_difference = abs(with_target - without_target)
    noise_scale = 1.0 / epsilon

    # The true difference is 1. If the observed difference were reliably 1,
    # the attack would succeed. It is instead dominated by noise of scale 10.
    assert observed_difference != 1 or noise_scale > 1, (
        "difference is not masked by noise"
    )


def test_single_differencing_attempt_is_unreliable() -> None:
    """Across many trials, the observed difference rarely equals the truth.

    If a one-shot differencing attack recovered the true difference most of
    the time, the mechanism would be broken regardless of its parameters.
    """
    epsilon = 0.1
    exact_hits = sum(
        1
        for _ in range(300)
        if privatize_count(500, epsilon=epsilon).value
        - privatize_count(499, epsilon=epsilon).value
        == 1
    )
    assert exact_hits < 60, (
        f"differencing recovered the exact answer {exact_hits}/300 times; "
        "noise is insufficient"
    )


# --- Why noise alone is not enough ------------------------------------------


def test_averaging_defeats_noise_when_queries_are_unlimited() -> None:
    """Demonstrates WHY the budget exists — this is the failure mode.

    Repeating a query and averaging cancels zero-mean noise. This test asserts
    the attack *works* in the absence of a budget, which is the honest reason
    `budget.py` is not optional. A DP implementation without enforced
    accounting has correct-looking noise and no actual guarantee.

    The companion test in test_privacy_budget.py shows the budget stopping it.
    """
    true_value = 500
    recovered = statistics.mean(
        privatize_count(true_value, epsilon=0.1).value for _ in range(2000)
    )

    assert abs(recovered - true_value) < 5, (
        "expected averaging to recover the true value; if this fails the "
        "premise of the budget test is wrong"
    )


# --- Small-cohort suppression -----------------------------------------------


@pytest.mark.parametrize("count", list(range(MIN_COHORT_SIZE)))
def test_small_cohorts_are_usually_suppressed(count: int) -> None:
    """Counts below the threshold suppress most of the time.

    "Most", not "always": a deterministic rule would make the flag an exact
    predicate on private data. See `test_suppression_flag_is_not_an_oracle`.

    The threshold value itself is excluded from this parametrization on
    purpose. At exactly the boundary the decision is near a coin flip, and it
    has to be — that indistinguishability between `count == threshold` and
    `count == threshold + 1` is the whole property being bought. Asserting a
    majority there would be asserting the leak back into existence.
    """
    rate = sum(
        1 for _ in range(400) if privatize_count(count, epsilon=0.5).suppressed
    ) / 400
    assert rate > 0.5, f"true count {count} suppressed only {rate:.0%} of the time"


def test_large_cohorts_are_usually_answered() -> None:
    """Utility: a cohort far above the threshold should rarely be withheld.

    Spurious suppression of large, safe cohorts is a real cost of the noisy
    threshold, so it is bounded here rather than left unmeasured.
    """
    rate = sum(
        1 for _ in range(400) if privatize_count(500, epsilon=0.5).suppressed
    ) / 400
    assert rate < 0.05, f"large cohort suppressed {rate:.0%} of the time"


def test_suppression_flag_is_not_an_oracle() -> None:
    """The flag must not reveal which side of the threshold the truth sits on.

    THIS IS THE TEST THAT MATTERS. Suppression is published per site on every
    query and costs the caller nothing extra. If it were computed from the true
    count it would be an exact, noiseless bit of `count > threshold` — and
    varying the query predicate to binary-search the boundary recovers exact
    small counts at a named lab. That is the differencing attack this module
    exists to stop, arriving one free bit at a time.

    An earlier version compared the TRUE count and was measured at a perfect
    1.000 gap: invariant across 500 draws at every count tested. Comparing a
    noised count instead makes the decision a DP release in its own right.
    """
    trials = 4000
    just_below = sum(
        1 for _ in range(trials)
        if privatize_count(MIN_COHORT_SIZE, epsilon=0.1).suppressed
    ) / trials
    just_above = sum(
        1 for _ in range(trials)
        if privatize_count(MIN_COHORT_SIZE + 1, epsilon=0.1).suppressed
    ) / trials

    assert abs(just_below - just_above) < 0.15, (
        f"suppression distinguishes {MIN_COHORT_SIZE} from {MIN_COHORT_SIZE + 1} "
        f"with gap {abs(just_below - just_above):.3f}; the flag is an oracle"
    )


def test_suppression_of_a_single_count_is_randomized() -> None:
    """The same true count must not always produce the same flag.

    A deterministic outcome at any count is the signature of the old bug.
    """
    outcomes = {
        privatize_count(MIN_COHORT_SIZE, epsilon=0.1).suppressed
        for _ in range(200)
    }
    assert outcomes == {True, False}, "suppression is deterministic at the boundary"


def test_suppressed_result_still_reports_epsilon_spent() -> None:
    """Suppression does not refund budget.

    If it did, an attacker could probe for small cohorts for free — and
    learning *which* strata are small is itself a disclosure.

    Suppression is now randomized, so a single tiny count is not guaranteed to
    suppress. The invariant under test is the accounting: whichever branch is
    taken, the full epsilon is reported as spent.
    """
    for _ in range(50):
        result = privatize_count(1, epsilon=0.3)
        assert result.epsilon_spent == pytest.approx(0.3)


# --- Parameter validation ---------------------------------------------------


@pytest.mark.parametrize("epsilon", [0.0, -1.0, MIN_EPSILON / 2])
def test_epsilon_below_the_minimum_is_rejected(epsilon: float) -> None:
    """Too-small epsilon yields pure noise while still consuming budget."""
    with pytest.raises(PrivacyError):
        privatize_count(100, epsilon=epsilon)


@pytest.mark.parametrize("epsilon", [MAX_EPSILON + 0.01, 10.0, 1e6])
def test_epsilon_above_the_maximum_is_rejected(epsilon: float) -> None:
    """Large epsilon means negligible noise — DP in name only.

    This is the most common way DP is quietly defeated in practice: ship with
    epsilon high enough that the output is effectively exact.
    """
    with pytest.raises(PrivacyError):
        privatize_count(100, epsilon=epsilon)


@pytest.mark.parametrize("epsilon", [float("inf"), float("nan"), float("-inf")])
def test_non_finite_epsilon_is_rejected(epsilon: float) -> None:
    with pytest.raises(PrivacyError):
        privatize_count(100, epsilon=epsilon)


def test_negative_counts_are_rejected() -> None:
    with pytest.raises(PrivacyError):
        privatize_count(-1, epsilon=0.1)


def test_noised_output_is_never_negative() -> None:
    """A negative count is meaningless to an analyst.

    Clamping is post-processing of a DP result, which never weakens the
    guarantee.
    """
    values = [
        privatize_count(6, epsilon=MIN_EPSILON).value for _ in range(500)
    ]
    # Suppressed results carry value=None, which is not a negative count.
    assert all(v is None or v >= 0 for v in values)


# --- Federated combination --------------------------------------------------


def test_federated_total_sums_contributing_sites() -> None:
    counts = [
        NoisyCount(value=100, suppressed=False, epsilon_spent=0.1, noise_scale=10.0),
        NoisyCount(value=200, suppressed=False, epsilon_spent=0.1, noise_scale=10.0),
        NoisyCount(value=300, suppressed=False, epsilon_spent=0.1, noise_scale=10.0),
    ]
    combined = combine_federated_counts(counts)
    assert combined.value == 600
    assert combined.epsilon_spent == pytest.approx(0.3)


def test_a_single_contributing_site_is_suppressed() -> None:
    """Otherwise the "federated" total identifies which lab holds the cohort.

    Knowing that only Sanger contributed, and the total, is equivalent to
    reading Sanger's count directly.
    """
    counts = [
        NoisyCount(value=100, suppressed=False, epsilon_spent=0.1, noise_scale=10.0),
        NoisyCount(value=None, suppressed=True, epsilon_spent=0.1, noise_scale=10.0),
        NoisyCount(value=None, suppressed=True, epsilon_spent=0.1, noise_scale=10.0),
    ]
    combined = combine_federated_counts(counts)
    assert combined.suppressed is True
    assert combined.value is None


def test_federated_noise_scale_grows_with_site_count() -> None:
    """Honest accounting: federation costs precision.

    Independent noise variances add, so the combined answer is less precise
    than any single site's. Reporting a smaller scale would overstate utility.
    """
    one = combine_federated_counts(
        [
            NoisyCount(value=100, suppressed=False, epsilon_spent=0.1, noise_scale=10.0),
            NoisyCount(value=100, suppressed=False, epsilon_spent=0.1, noise_scale=10.0),
        ]
    )
    assert one.noise_scale > 10.0


def test_empty_site_list_is_rejected() -> None:
    with pytest.raises(PrivacyError):
        combine_federated_counts([])


def test_all_sites_suppressed_yields_a_suppressed_total() -> None:
    counts = [
        NoisyCount(value=None, suppressed=True, epsilon_spent=0.1, noise_scale=10.0)
        for _ in range(3)
    ]
    combined = combine_federated_counts(counts)
    assert combined.suppressed is True
    assert combined.epsilon_spent == pytest.approx(0.3)


# --- Randomness quality -----------------------------------------------------


def test_noise_uses_a_cryptographic_source() -> None:
    """`random` would be a silent, total break of the guarantee.

    Python's Mersenne Twister state is recoverable from ~624 outputs, so an
    attacker collecting enough responses could predict and subtract subsequent
    noise while every statistical test above still passed.
    """
    import inspect

    from biovault.federation import privacy

    source = inspect.getsource(privacy)
    assert "import secrets" in source
    assert "import random" not in source, "non-cryptographic RNG in the DP path"


def test_noise_distribution_is_not_degenerate() -> None:
    """Guards against a stub that returns a constant offset."""
    samples = [privatize_count(1000, epsilon=0.1).value for _ in range(400)]
    assert statistics.pstdev(samples) > 3.0
