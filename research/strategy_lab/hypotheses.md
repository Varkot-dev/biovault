# Hypothesis journal

The rule of this file: **write the entry BEFORE running the test.** An
improvement you thought of after seeing the results is data-mining, not
research (see Experiment 2 in `../trading-strategy-autopsy.md` for what that
manufactures from pure noise). Date every entry. Never delete a failed one —
failed hypotheses are what make the surviving ones believable.

Template:

```
## H<number> — <one-line name>            (<date>)
Prediction: <what will beat baseline, and by roughly how much>
Reasoning:  <WHY, in economic terms — who is on the other side of this trade
             and why are they wrong?>
Test:       <exact variant / filter / hold period>
Result:     <filled in AFTER running — numbers, and keep or kill>
Confirmed OOS: <filled in months later, on log data that didn't exist
                when the hypothesis was written>
```

---

## H1 — Cluster buys beat singleton buys        (2026-08-24)
Prediction: events where ≥2 distinct insiders bought the same stock within
5 days outperform the baseline by ≥1% over the 2-week hold.
Reasoning: one insider buying can be idiosyncratic (rebalancing, optics,
contrarian ego). Several insiders independently paying cash in the same week
is much harder to explain without shared positive information. This is the
strongest documented variant in the literature (Cohen–Malloy–Pomorski line
of work), decided on before any grading was run.
Test: `variants.py` "cluster buys" vs "baseline".
Result: 2026-08-25 first reading (report-2026-08-25.md): cluster +5.11%
(t = 2.25, 71% hit, n = 14) vs baseline −0.33% (t = −0.21, n = 39).
Direction and size as predicted — but n = 14 is tiny and the t barely clears
the 8-experiment luck bar (~2.0). Verdict: KEEP, rule frozen as-is,
re-read when cluster n ≥ 30, most of it from post-2026-08-25 log data.
Confirmed OOS: (pending)

## H2 — The signal is worthless in large caps   (2026-08-24)
Prediction: purchases in mega-cap names (e.g. the logged TSM, TM, ETN rows)
show ~0 alpha; the edge concentrates in small/micro caps.
Reasoning: a $150k insider buy is invisible relative to a trillion-dollar
company's information flow, and large caps are the most heavily analyzed
securities on earth. Nobody's $150k opinion moves the needle there.
Test: needs a market-cap column in the log first (see README upgrades), then
split above/below ~$2B.
Result: (pending)
Confirmed OOS: (pending)
