# Strategy Lab

A self-contained workspace for testing and improving the insider-buying
strategy. The collector (your friends' kjkjkj repo) produces the raw
material — `filings_log.csv`, one row per qualifying insider purchase. This
lab is where that log gets graded and where improvements get tested honestly.

Background reading, in order:
1. `../trading-strategy-autopsy.md` — how backtests lie (the four experiments)
2. `../kjkjkj-audit.md` — the bugs found in the collector, and why they matter

## Setup (once, on your own machine)

```
pip install requests pandas
```

Everything here needs open internet for price data (Stooq, Yahoo fallback),
so run it locally — not in a sandboxed environment.

## The three tools

**1. `grade_log.py` — the report card.** Grades every matured trade in the
log under the precommitted rule: dedupe the known double-logging, enter at
the first close on/after the entry date (weekend dates rolled forward), hold
10 trading days, exit at the close, subtract 20 bps/side costs, compare to
SPY over the same window.

```
python grade_log.py filings_log.csv
```

Read the output like this: `mean net alpha` is the average edge per trade
after costs; the **t-stat is the honesty number** — it says how many standard
errors the result is from zero. Below ~2, the result is indistinguishable
from luck; don't celebrate or panic, just keep logging. Roughly, the t-stat
grows with the square root of the trade count, so 4× more data doubles it.

**2. `variants.py` — the experiment engine.** Grades eight variants of the
strategy side by side on the same price data: baseline, price floor, size
floor, executives-only, cluster buys, same-day filers, and 5/20-day holds.

```
python variants.py filings_log.csv
```

It prints a multiple-testing warning at the end. Take it seriously — it is
the whole game. Eight experiments on the same data means the best t-stat
reaches ~2.0 by pure luck even when nothing works.

**3. `hypotheses.md` — the lab notebook.** The discipline that separates
research from curve-fitting: write down *what* you expect to win, *why* in
economic terms, and *how* you'll test it — **before** running. Two starter
hypotheses are already in there, written before any real grading was run.

## The improvement loop (this is the method)

```
idea → write it in hypotheses.md → add a variant → run → record the result
     → if it wins: PRECOMMIT it, then wait for NEXT months' log data
     → only a win on data that didn't exist yet counts as confirmation
```

Concretely, to add your own variant, edit the `VARIANTS` dict in
`variants.py`. Each entry is a name, a row filter, and a hold period:

```python
"big execs": (lambda d: d[d["is_exec"] & (d["amount"] >= 250_000)], 10),
```

Rules that keep you honest:
- **Never tune on the whole log and judge on the same log.** The log grows
  every week — the data you tuned on is in-sample forever; only new rows are
  out-of-sample.
- **Every variant needs an economic story first.** "Who is selling to this
  insider, and why are they wrong?" If you can't answer, the variant is
  numerology even if the t-stat is pretty.
- **Failed hypotheses stay in the journal.** If you test 20 ideas and report
  the 1 winner, you've rebuilt Experiment 1 from the autopsy note.
- **Costs are part of the strategy.** 22% of logged names trade under $5;
  re-run anything promising with `--cost-bps 40` and see if it survives.

## Fix the collector first

`patches/kjkjkj-fixes.patch` fixes the three data-corrupting bugs in the
collector (double-logging, Saturday entry dates, Friday buys excluded by the
calendar-day lag). Apply it in a checkout of the kjkjkj repo:

```
git apply kjkjkj-fixes.patch
```

Then dedupe the existing CSV once (grade_log.py already dedupes defensively,
but the alerts and the raw log should be clean too). Until the patch is
applied, every new day of data arrives doubled.

## Upgrades worth building next (roughly in order of value)

1. **Market cap column** at logging time (company facts are on EDGAR's
   `companyfacts` API, or any quote API) → unlocks the small-cap/large-cap
   split, which the literature says is the single biggest conditioner.
2. **Cluster flag** at logging time (the lab currently reconstructs it).
3. **Routine-buyer flag**: query the insider's past Form 4s once per alert;
   an insider who buys on a schedule carries no information.
4. **Average daily volume column** → position-size realism for the sub-$5
   names, where the paper alpha is least capturable.
5. **A weekly CI job** that runs `grade_log.py` and commits the graded CSV —
   the report card updates itself and nobody gets to "forget" a bad month.

## What a result will look like

Be calibrated: with ~126 clean events/month, six months of log is ~750
trades. If the true edge is +0.5%/trade (a realistic good outcome for this
class of signal), the t-stat lands around 2.5–3 — a real but modest signal,
worth trading small. If the true edge is zero, expect mean alpha within
±0.4% of zero and a t under 1.5. Anything showing +3%/trade with this
methodology means a bug, not a fortune — go hunting for the bug first.
