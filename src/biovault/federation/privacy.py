"""Differential privacy for federated cohort counts.

The problem this solves: three labs each hold genomic cohorts. The
scientifically valuable question — "how many patients across all three labs
carry this variant?" — currently cannot be asked, because answering it means
one lab shipping records to another, which consent agreements and GDPR forbid.

So the query never gets asked, and the science does not happen.

This module makes the aggregate answerable without any lab seeing another's
records. Each lab computes its own count locally; only noised counts leave the
tenant boundary.

## Why a raw count is not safe

An exact count is a disclosure. Suppose an attacker knows a cohort has 100
patients and queries "carriers of variant X" → 7. They then query a filter
matching the same cohort minus one specific patient → 6. Subtracting reveals
that patient's genotype exactly. This is the *differencing attack*, and it does
not require any bug — it works against a perfectly correct exact-count API.

## Why noise alone is not enough

Adding Laplace noise to each answer blunts a single differencing attempt. But
noise is zero-mean: repeat the same query 1000 times and average, and the noise
cancels, recovering the true value. Differential privacy is only meaningful
with a *budget* that is spent and cannot be replenished — which is why
`budget.py` exists and why the two must be used together.

## Parameters

Epsilon (ε) is the privacy loss parameter: smaller means more noise and
stronger privacy. For counting queries the sensitivity is 1 — one person
joining or leaving changes any count by at most 1 — so Laplace noise with
scale `1/ε` gives ε-differential privacy.
"""

from __future__ import annotations

import math
import secrets
from typing import Final

from pydantic import BaseModel, ConfigDict

# Sensitivity of a counting query: adding or removing one individual changes
# the result by at most 1.
#
# This is a claim about the QUERY, not just a constant. It holds only because
# `_count_matching_records` counts DISTINCT subjects rather than rows -- see
# that function. Counting rows would make sensitivity equal to the maximum
# number of rows one subject can contribute, which nothing bounds, and every
# epsilon figure downstream would silently overstate the protection delivered.
#
# Anything that changes what the federated query counts must revisit this
# value. `test_sensitivity_assumption_holds` asserts the property directly
# against the database rather than trusting this comment.
COUNT_SENSITIVITY: Final[float] = 1.0

# Counts below this are suppressed entirely rather than noised. Noise protects
# against inference from a *distribution*; it cannot hide the difference
# between "nobody" and "somebody" when the true count is 1, because the
# attacker often knows the answer is small already.
MIN_COHORT_SIZE: Final[int] = 5

# Bounds on epsilon per query. Above the maximum the noise is too small to
# protect anyone; below the minimum the answer is pure noise and wastes budget
# for no scientific value.
MIN_EPSILON: Final[float] = 0.01
MAX_EPSILON: Final[float] = 1.0

# Fraction of a query's epsilon spent deciding whether to suppress, with the
# remainder spent on the count itself.
#
# The split has to exist because the suppression decision is a release in its
# own right (see `privatize_count`). Its size is a genuine trade: epsilon spent
# on the threshold sharpens the suppress/report boundary, and epsilon spent on
# the count sharpens the answer. Both come out of the same budget.
#
# Tuned against BOTH costs, measured at threshold 5 and epsilon 0.1 over 5000
# draws per cell. Spending more on the threshold reduces spurious suppression
# of large cohorts but directly inflates the noise on every answer:
#
#     fraction   count scale   suppressed@50   suppressed@20   gap 5v6
#       0.10          11.1          32.1%           44.0%       0.025
#       0.25          13.3          15.1%           34.4%       0.010
#       0.50          20.0           5.0%           23.8%       0.021
#       0.75          40.0           1.5%           16.2%       0.050
#
# The `gap` column is the privacy property -- how much an observer learns from
# the flag when the truth sits either side of the threshold. It is near zero at
# every split, against 1.000 for the old deterministic test. So privacy is not
# what varies here; utility is, in two directions that oppose each other.
#
# 0.50 is the balance point. At 0.25 a cohort of fifty carries no individual
# risk and is still suppressed one time in seven -- a useless answer bought for
# nothing. At 0.75 spurious suppression nearly vanishes but every count carries
# four times the noise it would have, which makes the answers that do come back
# unusable. 0.50 halves the suppression of large cohorts relative to 0.25 while
# holding the count penalty to 2x.
#
# THE 2x IS REAL AND IS THE PRICE OF THE FIX. The old code produced both a
# sharp count and a sharp suppression flag, because the flag was free -- paid
# for by leaking an exact bit of private data. Once the flag pays its own way,
# one budget covers two releases and both get noisier. There was never a
# version where both were sharp and the guarantee held; the earlier one just
# kept the cost off the ledger.
THRESHOLD_EPSILON_FRACTION: Final[float] = 0.50


class PrivacyError(Exception):
    """Raised when a query cannot be answered within privacy constraints."""


class NoisyCount(BaseModel):
    """A differentially private count.

    `suppressed` is part of the answer, not an error: telling the analyst that
    a stratum was too small is itself useful, and hiding the distinction would
    make a suppressed cell indistinguishable from a genuine zero.

    `value` is clamped at zero for presentation. `raw_value` keeps the
    unclamped float so that federated sums can be computed without compounding
    clamping bias — see `combine_federated_counts`. It is never returned to a
    caller.
    """

    model_config = ConfigDict(frozen=True)

    value: int | None
    suppressed: bool
    epsilon_spent: float
    noise_scale: float
    raw_value: float | None = None


def _laplace_noise(scale: float) -> float:
    """Sample from Laplace(0, scale) using a cryptographic RNG.

    `secrets` rather than `random`: the Mersenne Twister behind `random` is
    fully reconstructible from ~624 outputs, so an attacker who observed enough
    query responses could predict subsequent noise and subtract it — removing
    the privacy guarantee entirely while every test still passed.

    Uses inverse transform sampling on a uniform in (0, 1).
    """
    # secrets.randbits gives uniform integers; scale into the open interval
    # (0, 1) to keep log() finite at both ends.
    precision = 1 << 53
    uniform = (secrets.randbits(53) + 0.5) / precision

    # Inverse CDF of Laplace(0, b): -b * sgn(u - 0.5) * ln(1 - 2|u - 0.5|)
    centred = uniform - 0.5
    return -scale * math.copysign(1.0, centred) * math.log1p(-2.0 * abs(centred))


def validate_epsilon(epsilon: float) -> None:
    """Reject epsilon values outside the safe operating range.

    Raises:
        PrivacyError: If epsilon is non-finite or out of bounds.
    """
    if not math.isfinite(epsilon):
        raise PrivacyError("epsilon must be a finite number")
    if epsilon < MIN_EPSILON:
        raise PrivacyError(
            f"epsilon {epsilon} is below the minimum {MIN_EPSILON}; "
            "the answer would be pure noise and would still consume budget"
        )
    if epsilon > MAX_EPSILON:
        raise PrivacyError(
            f"epsilon {epsilon} exceeds the maximum {MAX_EPSILON}; "
            "noise would be too small to protect individuals"
        )


def privatize_count(
    true_count: int,
    *,
    epsilon: float,
    min_cohort_size: int = MIN_COHORT_SIZE,
) -> NoisyCount:
    """Return a differentially private version of `true_count`.

    Args:
        true_count: The exact count. Never returned or logged.
        epsilon: Privacy loss for this query. Smaller is more private.
        min_cohort_size: Counts at or below this are suppressed.

    Raises:
        PrivacyError: If epsilon is outside the permitted range.
    """
    validate_epsilon(epsilon)

    if true_count < 0:
        raise PrivacyError("count cannot be negative")

    # The budget splits between two releases: the suppression decision and the
    # count itself. Both touch private data, so both must be paid for.
    threshold_epsilon = epsilon * THRESHOLD_EPSILON_FRACTION
    count_epsilon = epsilon - threshold_epsilon
    scale = COUNT_SENSITIVITY / count_epsilon

    # THE SUPPRESSION DECISION IS ITSELF A DP RELEASE.
    #
    # An earlier version compared the TRUE count to the threshold and defended
    # it as the safe choice -- reasoning that deciding on a noised value would
    # let an attacker infer which side of the threshold the truth fell on.
    # That was backwards, and it was the most serious hole in this module.
    #
    # Comparing the true count makes `suppressed` a deterministic function of
    # private data: an exact, noiseless bit of `count > threshold`, published
    # per site on every query, costing nothing. Measured on the old code, the
    # flag was invariant across 500 draws at every true count tested -- a
    # perfect oracle. Vary the query predicate and binary-search the boundary
    # and an attacker recovers exact small counts at a named lab, which is the
    # differencing attack this module exists to stop, one free bit at a time.
    #
    # Comparing a NOISED count instead makes the decision randomized, so the
    # bit carries bounded information rather than complete information. Near
    # the boundary it genuinely flips between calls, which is the point: an
    # observer cannot distinguish "true count 5" from "true count 6". This is
    # the shape of propose-test-release.
    noisy_threshold_test = true_count + _laplace_noise(
        COUNT_SENSITIVITY / threshold_epsilon
    )
    if noisy_threshold_test <= min_cohort_size:
        return NoisyCount(
            value=None, suppressed=True, epsilon_spent=epsilon, noise_scale=scale
        )

    noised = true_count + _laplace_noise(scale)

    # Clamp at zero for presentation. A negative count is nonsense to an
    # analyst, and post-processing a DP result never weakens the guarantee.
    #
    # `raw_value` retains the unclamped float. Clamping is not symmetric --
    # it truncates the negative tail only -- so summing already-clamped
    # per-site values biases a federated total upward, badly for small
    # cohorts. Measured at three sites with three records each and scale 10:
    # the clamped sum averaged 20.07 against a true total of 9. Federated
    # sums therefore use raw_value and clamp once at the end.
    return NoisyCount(
        value=max(0, round(noised)),
        suppressed=False,
        epsilon_spent=epsilon,
        noise_scale=scale,
        raw_value=noised,
    )


def combine_federated_counts(
    counts: list[NoisyCount], *, min_contributing_sites: int = 2
) -> NoisyCount:
    """Sum per-site noisy counts into a federated total.

    Each site noises its own count before release, so the sum is the sum of
    independent DP releases and remains differentially private. Noise variance
    adds, which is the honest cost of federation: the total is less precise
    than any single site's answer would be.

    Args:
        counts: One noisy count per participating site.
        min_contributing_sites: Below this, the result is suppressed.

    Raises:
        PrivacyError: If no counts are supplied.
    """
    if not counts:
        raise PrivacyError("no sites contributed to this query")

    contributing = [c for c in counts if not c.suppressed and c.value is not None]
    total_epsilon = sum(c.epsilon_spent for c in counts)

    # With a single contributing site the "federated" total is that site's
    # count, which re-identifies which lab holds the cohort. Requiring two
    # keeps the aggregate genuinely aggregate.
    if len(contributing) < min_contributing_sites:
        return NoisyCount(
            value=None,
            suppressed=True,
            epsilon_spent=total_epsilon,
            noise_scale=max((c.noise_scale for c in counts), default=0.0),
        )

    # Sum the UNCLAMPED per-site values, then clamp once. Summing clamped
    # values compounds the truncation bias described in `privatize_count`;
    # clamping only the final total keeps the estimator unbiased wherever the
    # true total is comfortably positive, which is the regime an analyst can
    # actually use.
    raw_total = sum(
        c.raw_value if c.raw_value is not None else float(c.value or 0)
        for c in contributing
    )

    return NoisyCount(
        value=max(0, round(raw_total)),
        suppressed=False,
        epsilon_spent=total_epsilon,
        noise_scale=math.sqrt(sum(c.noise_scale**2 for c in contributing)),
        raw_value=raw_total,
    )
