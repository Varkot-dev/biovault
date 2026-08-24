"""Grade the kjkjkj insider-buy forward log.

Implements the precommitted test: enter at the first available close on/after
the logged entry_date, hold 10 trading days (~2 weeks), exit at the close,
compare each round-trip against the benchmark over the same window.

Handles the known log defects: duplicate rows (each filing logged 2-4x) and
weekend entry dates ("next session" bug) are corrected here, not ignored.

Usage:
    pip install requests pandas
    python grade_log.py filings_log.csv [--benchmark SPY] [--hold 10]
                        [--cost-bps 20]

Needs open internet (Stooq, Yahoo fallback) — run locally or in CI, not in a
sandboxed environment. Writes graded_trades.csv next to the input.
"""

import argparse
import io
import json
import sys
import time

import pandas as pd
import requests

UA = {"User-Agent": "Mozilla/5.0 (research script)"}


def fetch_stooq(symbol, start, end):
    s = symbol.lower().replace(".", "-") + ".us"
    url = (f"https://stooq.com/q/d/l/?s={s}"
           f"&d1={start:%Y%m%d}&d2={end:%Y%m%d}&i=d")
    r = requests.get(url, headers=UA, timeout=30)
    r.raise_for_status()
    if not r.text.startswith("Date"):
        raise ValueError("no data")
    df = pd.read_csv(io.StringIO(r.text), parse_dates=["Date"])
    return df.set_index("Date")["Close"]


def fetch_yahoo(symbol, start, end):
    url = (f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}"
           f"?period1={int(start.timestamp())}&period2={int(end.timestamp())}"
           f"&interval=1d")
    r = requests.get(url, headers=UA, timeout=30)
    r.raise_for_status()
    res = json.loads(r.text)["chart"]["result"][0]
    idx = pd.to_datetime(res["timestamp"], unit="s").normalize()
    close = res["indicators"]["quote"][0]["close"]
    return pd.Series(close, index=idx).dropna()


def fetch_closes(symbol, start, end):
    for fn in (fetch_stooq, fetch_yahoo):
        try:
            ser = fn(symbol, start, end)
            if len(ser):
                return ser
        except Exception as e:
            print(f"  {symbol}: {fn.__name__} failed ({e})", file=sys.stderr)
        time.sleep(0.4)
    return None


def grade(log_path, benchmark="SPY", hold_days=10, cost_bps=20.0):
    df = pd.read_csv(log_path, parse_dates=["entry_date"])
    n_raw = len(df)
    df = df.drop_duplicates(subset=["symbol", "insider", "txn_date", "amount"])
    print(f"{n_raw} rows -> {len(df)} unique filings after dedup")

    start = df["entry_date"].min() - pd.Timedelta(days=5)
    end = pd.Timestamp.today() + pd.Timedelta(days=1)

    bench = fetch_closes(benchmark, start, end)
    if bench is None:
        sys.exit(f"cannot fetch benchmark {benchmark}; aborting")
    calendar = bench.index  # actual trading days

    rows, skipped = [], {}
    for sym, grp in df.groupby("symbol"):
        px = fetch_closes(sym, start, end)
        if px is None:
            skipped[sym] = "no price data"
            continue
        for _, ev in grp.iterrows():
            # roll weekend/holiday entry dates forward to a real trading day
            pos = calendar.searchsorted(ev["entry_date"])
            if pos >= len(calendar):
                skipped[sym] = "entry beyond data"
                continue
            entry_day = calendar[pos]
            exit_pos = pos + hold_days
            if exit_pos >= len(calendar):
                continue  # not matured yet
            exit_day = calendar[exit_pos]
            try:
                p_in, p_out = px.loc[entry_day], px.loc[exit_day]
                b_in, b_out = bench.loc[entry_day], bench.loc[exit_day]
            except KeyError:
                skipped[sym] = "missing bar"
                continue
            gross = p_out / p_in - 1
            net = gross - 2 * cost_bps / 1e4  # entry + exit
            rows.append({
                "symbol": sym, "insider": ev["insider"],
                "amount": ev["amount"], "logged_price": ev["price"],
                "entry_day": entry_day.date(), "exit_day": exit_day.date(),
                "entry_close": round(p_in, 4), "exit_close": round(p_out, 4),
                "ret_gross": round(gross, 5), "ret_net": round(net, 5),
                "bench_ret": round(b_out / b_in - 1, 5),
                "alpha_net": round(net - (b_out / b_in - 1), 5),
            })

    g = pd.DataFrame(rows)
    if g.empty:
        sys.exit("no matured, gradeable trades yet")
    out = log_path.replace(".csv", "") + "_graded.csv"
    g.to_csv(out, index=False)

    a = g["alpha_net"]
    t = a.mean() / (a.std(ddof=1) / len(a) ** 0.5) if len(a) > 2 else float("nan")
    print(f"\n=== {len(g)} matured trades | hold {hold_days}d | "
          f"cost {cost_bps}bps/side | vs {benchmark} ===")
    print(f"mean net alpha : {a.mean():+.2%}   (t = {t:.2f})")
    print(f"median         : {a.median():+.2%}")
    print(f"hit rate       : {(a > 0).mean():.0%}")
    print(f"best / worst   : {a.max():+.2%} / {a.min():+.2%}")
    low = g[g["logged_price"] < 5]["alpha_net"]
    if len(low) > 2:
        print(f"sub-$5 names   : {low.mean():+.2%} over {len(low)} trades")
    if skipped:
        print(f"skipped: {skipped}")
    print(f"written: {out}")
    print("\nRead the t-stat honestly: |t| < 2 means the result is "
          "indistinguishable from luck at this sample size. Keep logging.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?", default="filings_log.csv")
    ap.add_argument("--benchmark", default="SPY")
    ap.add_argument("--hold", type=int, default=10)
    ap.add_argument("--cost-bps", type=float, default=20.0)
    args = ap.parse_args()
    grade(args.log, args.benchmark, args.hold, args.cost_bps)
