"""Backtest pathology demonstrations.

Four controlled experiments showing how a worthless trading strategy can
produce a great-looking backtest. All "market data" here is synthetic, so we
KNOW the ground truth: in experiments 1-3 there is nothing to find (pure
random walks), and in experiment 4 there is a tiny real edge that costs erase.

Run: python3 backtest_pathology_demo.py
Outputs: results printed + JSON dump for the report.
"""

import json
import numpy as np

RNG = np.random.default_rng(42)
TRADING_DAYS = 252


def sharpe(returns: np.ndarray) -> float:
    s = returns.std()
    if s == 0:
        return 0.0
    return float(returns.mean() / s * np.sqrt(TRADING_DAYS))


def random_walk_returns(n_days: int, rng, vol: float = 0.01) -> np.ndarray:
    """Zero-drift i.i.d. gaussian daily log returns: NO predictability at all."""
    return rng.normal(0.0, vol, n_days)


def ar1_returns(n_days: int, rng, phi: float = 0.05, vol: float = 0.01) -> np.ndarray:
    """Daily returns with slight positive autocorrelation: a small REAL edge."""
    r = np.zeros(n_days)
    eps = rng.normal(0.0, vol, n_days)
    for t in range(1, n_days):
        r[t] = phi * r[t - 1] + eps[t]
    return r


def ma(x: np.ndarray, window: int) -> np.ndarray:
    """Trailing moving average, NaN-padded to full length."""
    out = np.full(len(x), np.nan)
    c = np.cumsum(np.insert(x, 0, 0.0))
    out[window - 1:] = (c[window:] - c[:-window]) / window
    return out


def crossover_strategy(returns: np.ndarray, fast: int, slow: int,
                       lookahead_bug: bool = False,
                       cost_per_side: float = 0.0):
    """Long/short MA-crossover on the price implied by cumulative returns.

    Correct version: the position for day t is decided from data up to t-1
    (signal shifted by one day). Buggy version: position for day t uses the
    MA computed INCLUDING day t's close - information you cannot have when
    you trade during day t.
    Returns (net strategy returns, annualized turnover in position units).
    """
    prices = np.exp(np.cumsum(returns))
    f, s = ma(prices, fast), ma(prices, slow)
    signal = np.where(f > s, 1.0, -1.0)
    signal[np.isnan(f) | np.isnan(s)] = 0.0

    if lookahead_bug:
        pos = signal                      # uses day t close to trade day t
    else:
        pos = np.roll(signal, 1)          # decided yesterday, held today
        pos[0] = 0.0

    gross = pos * returns
    trades = np.abs(np.diff(pos, prepend=0.0))
    net = gross - trades * cost_per_side
    turnover = float(trades.sum() / (len(returns) / TRADING_DAYS))
    return net, turnover


results = {}

# ----------------------------------------------------------------------------
# EXPERIMENT 1 - Multiple testing / selection bias.
# One FIXED strategy (20/100 crossover), applied honestly to 200 different
# random-walk "assets". Every asset is pure noise, yet the best of the 200
# backtests looks like a career-making discovery.
# ----------------------------------------------------------------------------
n_series, n_days = 200, 10 * TRADING_DAYS
short_days = 3 * TRADING_DAYS  # a typical retail backtest window
sharpes = []
for _ in range(n_series):
    r = random_walk_returns(short_days, RNG)
    net, _ = crossover_strategy(r, 20, 100)
    sharpes.append(sharpe(net))
sharpes = np.array(sharpes)
results["exp1_multiple_testing"] = {
    "n_assets": n_series,
    "years": 3,
    "mean_sharpe": round(float(sharpes.mean()), 3),
    "median_sharpe": round(float(np.median(sharpes)), 3),
    "best_sharpe": round(float(sharpes.max()), 3),
    "worst_sharpe": round(float(sharpes.min()), 3),
    "pct_above_0.5": round(float((sharpes > 0.5).mean() * 100), 1),
    "pct_above_1.0": round(float((sharpes > 1.0).mean() * 100), 1),
}

# ----------------------------------------------------------------------------
# EXPERIMENT 2 - Parameter mining, then honest out-of-sample test.
# For each of 200 random-walk series: grid-search 21 (fast, slow) pairs on
# the first 5 years, keep the best in-sample Sharpe, then run those exact
# parameters on the NEXT 5 years. Ground truth: nothing is learnable.
# ----------------------------------------------------------------------------
grid = [(f, s) for f in (5, 10, 20, 30, 50, 75, 100)
        for s in (20, 50, 100, 150, 200) if f < s]
best_is, oos = [], []
example = None
for i in range(n_series):
    r = random_walk_returns(n_days, RNG)
    half = n_days // 2
    r_is, r_oos = r[:half], r[half:]
    scored = [(sharpe(crossover_strategy(r_is, f, s)[0]), f, s) for f, s in grid]
    sh_is, f_best, s_best = max(scored)
    sh_oos = sharpe(crossover_strategy(r_oos, f_best, s_best)[0])
    best_is.append(sh_is)
    oos.append(sh_oos)
    if sh_is > 1.0 and (example is None or sh_oos < example["sharpe_oos"]):
        eq_is = np.cumsum(crossover_strategy(r_is, f_best, s_best)[0])
        eq_oos = eq_is[-1] + np.cumsum(crossover_strategy(r_oos, f_best, s_best)[0])
        example = {
            "params": [f_best, s_best],
            "sharpe_is": round(sh_is, 2),
            "sharpe_oos": round(sh_oos, 2),
            "equity_is": [round(x, 4) for x in eq_is[::10]],
            "equity_oos": [round(x, 4) for x in eq_oos[::10]],
        }
best_is, oos = np.array(best_is), np.array(oos)
results["exp2_parameter_mining"] = {
    "grid_size": len(grid),
    "median_best_in_sample_sharpe": round(float(np.median(best_is)), 3),
    "pct_in_sample_above_1.0": round(float((best_is > 1.0).mean() * 100), 1),
    "median_out_of_sample_sharpe": round(float(np.median(oos)), 3),
    "pct_out_of_sample_above_1.0": round(float((oos > 1.0).mean() * 100), 1),
    "pct_out_of_sample_negative": round(float((oos < 0).mean() * 100), 1),
    "example": example,
}

# ----------------------------------------------------------------------------
# EXPERIMENT 3 - Lookahead bias (the classic off-by-one bug).
# Same fixed 20/100 strategy, same 200 random-walk series, but the buggy
# version decides today's position using today's close. One line of code.
# ----------------------------------------------------------------------------
sh_correct, sh_buggy = [], []
for _ in range(n_series):
    r = random_walk_returns(n_days, RNG)
    sh_correct.append(sharpe(crossover_strategy(r, 3, 10)[0]))
    sh_buggy.append(sharpe(crossover_strategy(r, 3, 10, lookahead_bug=True)[0]))
results["exp3_lookahead"] = {
    "strategy": "3/10 MA crossover, long/short",
    "median_sharpe_correct": round(float(np.median(sh_correct)), 3),
    "median_sharpe_with_bug": round(float(np.median(sh_buggy)), 3),
    "pct_bug_above_1.0": round(float((np.array(sh_buggy) > 1.0).mean() * 100), 1),
}

# ----------------------------------------------------------------------------
# EXPERIMENT 4 - Transaction costs vs a small REAL edge.
# AR(1) returns with phi=0.08: genuine short-term momentum. Holding
# sign(yesterday's return) really does capture it... until you pay
# 10 bps per side on a strategy that flips position every other day.
# ----------------------------------------------------------------------------
def sign_momentum(returns: np.ndarray, cost_per_side: float = 0.0):
    pos = np.roll(np.sign(returns), 1)
    pos[0] = 0.0
    trades = np.abs(np.diff(pos, prepend=0.0))
    net = pos * returns - trades * cost_per_side
    turnover = float(trades.sum() / (len(returns) / TRADING_DAYS))
    return net, turnover

gross_sh, net_sh, turnovers = [], [], []
for _ in range(n_series):
    r = ar1_returns(n_days, RNG, phi=0.08)
    g, _ = sign_momentum(r)
    n, to = sign_momentum(r, cost_per_side=0.0010)
    gross_sh.append(sharpe(g))
    net_sh.append(sharpe(n))
    turnovers.append(to)
results["exp4_costs"] = {
    "true_edge": "AR(1) phi=0.08 daily momentum, sign(yesterday) strategy",
    "cost_assumed": "10 bps per side",
    "median_gross_sharpe": round(float(np.median(gross_sh)), 3),
    "median_net_sharpe": round(float(np.median(net_sh)), 3),
    "median_annual_turnover_x": round(float(np.median(turnovers)), 1),
    "pct_profitable_gross": round(float((np.array(gross_sh) > 0).mean() * 100), 1),
    "pct_profitable_net": round(float((np.array(net_sh) > 0).mean() * 100), 1),
}

print(json.dumps(results, indent=2))
with open("pathology_results.json", "w") as fh:
    json.dump(results, fh, indent=2)
