"""Small dependency-free statistics helpers for noisy timing measurements."""
from __future__ import annotations

import math
import random
from typing import Sequence


def median(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def quantile(values: Sequence[float], q: float) -> float | None:
    if not values:
        return None
    if not 0 <= q <= 1:
        raise ValueError("q must be in [0, 1]")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    pos = (len(ordered) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(ordered[lo])
    return ordered[lo] * (hi - pos) + ordered[hi] * (pos - lo)


def stdev(values: Sequence[float]) -> float | None:
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    return math.sqrt(sum((x - mean) ** 2 for x in values) / (len(values) - 1))


def median_abs_deviation(values: Sequence[float]) -> float | None:
    med = median(values)
    if med is None:
        return None
    return median([abs(x - med) for x in values])


def describe(values: Sequence[float]) -> dict[str, float | int | None]:
    if not values:
        return {"n": 0}
    med = median(values)
    return {
        "n": len(values),
        "mean_ms": round(sum(values) / len(values), 3),
        "median_ms": round(med, 3) if med is not None else None,
        "stdev_ms": round(stdev(values), 3) if stdev(values) is not None else None,
        "mad_ms": round(median_abs_deviation(values) or 0.0, 3),
        "p25_ms": round(quantile(values, 0.25) or 0.0, 3),
        "p75_ms": round(quantile(values, 0.75) or 0.0, 3),
        "p90_ms": round(quantile(values, 0.90) or 0.0, 3),
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
    }


def cliffs_delta(a: Sequence[float], b: Sequence[float]) -> float | None:
    """Cliff's delta: positive means A tends to be larger than B."""
    if not a or not b:
        return None
    greater = less = 0
    for x in a:
        for y in b:
            if x > y:
                greater += 1
            elif x < y:
                less += 1
    return (greater - less) / (len(a) * len(b))


def bootstrap_median_diff_ci(
    existing: Sequence[float],
    nonexisting: Sequence[float],
    replicates: int = 3000,
    confidence: float = 0.95,
    seed: int = 20261126,
) -> dict[str, float | None]:
    if len(existing) < 2 or len(nonexisting) < 2:
        observed = None
        me = median(existing)
        mn = median(nonexisting)
        if me is not None and mn is not None:
            observed = me - mn
        return {"difference_ms": round(observed, 3) if observed is not None else None, "low_ms": None, "high_ms": None}

    rng = random.Random(seed)
    observed = median(existing) - median(nonexisting)  # type: ignore[operator]
    diffs: list[float] = []
    for _ in range(replicates):
        ea = [rng.choice(existing) for _ in existing]
        nb = [rng.choice(nonexisting) for _ in nonexisting]
        diffs.append(median(ea) - median(nb))  # type: ignore[operator]

    alpha = (1 - confidence) / 2
    low = quantile(diffs, alpha)
    high = quantile(diffs, 1 - alpha)
    return {
        "difference_ms": round(observed, 3),
        "low_ms": round(low, 3) if low is not None else None,
        "high_ms": round(high, 3) if high is not None else None,
        "confidence": confidence,
        "replicates": replicates,
    }


def permutation_test_median_diff(
    existing: Sequence[float],
    nonexisting: Sequence[float],
    replicates: int = 3000,
    seed: int = 20261127,
) -> float | None:
    if len(existing) < 2 or len(nonexisting) < 2:
        return None
    observed = abs(median(existing) - median(nonexisting))  # type: ignore[operator]
    pooled = list(existing) + list(nonexisting)
    n_existing = len(existing)
    rng = random.Random(seed)
    extreme = 0
    for _ in range(replicates):
        rng.shuffle(pooled)
        a = pooled[:n_existing]
        b = pooled[n_existing:]
        stat = abs(median(a) - median(b))  # type: ignore[operator]
        if stat >= observed - 1e-12:
            extreme += 1
    return (extreme + 1) / (replicates + 1)


def mann_whitney_permutation_p(
    a: Sequence[float],
    b: Sequence[float],
    replicates: int = 5000,
    seed: int = 20261128,
) -> float | None:
    """Two-sided permutation test on rank sums (Mann-Whitney/Cliff effect)."""
    if len(a) < 2 or len(b) < 2:
        return None

    pooled = [(float(x), 0) for x in a] + [(float(y), 1) for y in b]
    pooled.sort(key=lambda item: item[0])

    ranks = [0.0] * len(pooled)
    i = 0
    while i < len(pooled):
        j = i + 1
        while j < len(pooled) and pooled[j][0] == pooled[i][0]:
            j += 1
        # Average 1-based ranks for ties.
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    n_a = len(a)
    observed_rank_sum = sum(rank for rank, item in zip(ranks, pooled) if item[1] == 0)
    expected = n_a * (len(pooled) + 1) / 2.0
    observed_stat = abs(observed_rank_sum - expected)

    rng = random.Random(seed)
    extreme = 0
    rank_values = ranks[:]
    for _ in range(replicates):
        rng.shuffle(rank_values)
        stat = abs(sum(rank_values[:n_a]) - expected)
        if stat >= observed_stat - 1e-12:
            extreme += 1
    return (extreme + 1) / (replicates + 1)
