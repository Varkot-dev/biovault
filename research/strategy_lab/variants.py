"""Test strategy variants against the forward log, side by side.

Each variant is a named filter (and optional holding period) applied to the
same deduped event log. All variants share one set of price downloads, so
this costs no more than grading once.

Usage:
    python variants.py filings_log.csv

READ THE WARNING THE SCRIPT PRINTS. Trying K variants on the same data is
multiple testing — the best-looking one is partly luck (see Experiment 2 in
the research notes). The workflow that keeps you honest:
  1. Write the hypothesis in hypotheses.md BEFORE running.
  2. Run, and compare against baseline.
  3. If a variant wins, precommit it and confirm on the NEXT months of log
     data before believing it.
"""

import math
import sys

import pandas as pd

from grade_log import fetch_closes


def load_events(path):
    df = pd.read_csv(path, parse_dates=["entry_date"])
    df = df.drop_duplicates(subset=["symbol", "insider", "txn_date", "amount"])
    df["relationship"] = df["relationship"].fillna("")
    # cluster: >= 2 distinct insiders in the same symbol within 5 calendar days
    df["txn"] = pd.to_datetime(df["txn_date"])
    cluster = set()
    for sym, g in df.groupby("symbol"):
        for i, ev in g.iterrows():
            near = g[(g["txn"] - ev["txn"]).abs() <= pd.Timedelta(days=5)]
            if near["insider"].nunique() >= 2:
                cluster.add(i)
    df["is_cluster"] = df.index.isin(cluster)
    exec_words = ("CEO", "CHIEF EXEC", "CFO", "CHIEF FINANCIAL", "PRESIDENT")
    df["is_exec"] = df["relationship"].str.upper().apply(
        lambda r: any(w in r for w in exec_words))
    return df


VARIANTS = {
    # name:            (row filter,                                hold days)
    "baseline":        (lambda d: d,                               10),
    "price >= $5":     (lambda d: d[d["price"] >= 5],              10),
    "size >= $150k":   (lambda d: d[d["amount"] >= 150_000],       10),
    "execs only":      (lambda d: d[d["is_exec"]],                 10),
    "cluster buys":    (lambda d: d[d["is_cluster"]],              10),
    "same-day filers": (lambda d: d[d["lag_days"] == 0],           10),
    "hold 5d":         (lambda d: d,                               5),
    "hold 20d":        (lambda d: d,                               20),
}


def grade_events(events, bench, px_cache, hold, cost_bps=20.0):
    calendar = bench.index
    alphas = []
    for _, ev in events.iterrows():
        px = px_cache.get(ev["symbol"])
        if px is None:
            continue
        pos = calendar.searchsorted(ev["entry_date"])
        if pos >= len(calendar) or pos + hold >= len(calendar):
            continue
        e_day, x_day = calendar[pos], calendar[pos + hold]
        try:
            ret = px.loc[x_day] / px.loc[e_day] - 1 - 2 * cost_bps / 1e4
            alphas.append(ret - (bench.loc[x_day] / bench.loc[e_day] - 1))
        except KeyError:
            continue
    return pd.Series(alphas)


def main(path):
    df = load_events(path)
    start = df["entry_date"].min() - pd.Timedelta(days=5)
    end = pd.Timestamp.today() + pd.Timedelta(days=1)

    bench = fetch_closes("SPY", start, end)
    if bench is None:
        sys.exit("cannot fetch SPY")
    px_cache = {}
    for sym in df["symbol"].unique():
        px_cache[sym] = fetch_closes(sym, start, end)

    print(f"\n{'variant':<16}{'trades':>7}{'mean alpha':>12}"
          f"{'t-stat':>8}{'hit rate':>10}")
    print("-" * 53)
    for name, (flt, hold) in VARIANTS.items():
        a = grade_events(flt(df), bench, px_cache, hold)
        if len(a) < 3:
            print(f"{name:<16}{len(a):>7}{'too few':>12}")
            continue
        t = a.mean() / (a.std(ddof=1) / len(a) ** 0.5)
        print(f"{name:<16}{len(a):>7}{a.mean():>+11.2%}"
              f"{t:>8.2f}{(a > 0).mean():>9.0%}")

    k = len(VARIANTS)
    print(f"\nWARNING - multiple testing: you just ran {k} experiments. Even "
          f"if the strategy\nhas ZERO edge, the best of {k} t-stats is "
          f"expected to reach ~{math.sqrt(2 * math.log(k)):.1f} by luck.\n"
          "A variant is only believable if (a) its t clears that bar, "
          "(b) the reason it\nshould win was written down beforehand, and "
          "(c) it holds up on the NEXT months\nof forward data.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "filings_log.csv")
