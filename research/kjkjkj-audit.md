# Audit: kjkjkj insider-buy monitor

*Code reviewed from the uploaded `Kjkjkj_main.zip` (9 files). Companion to
`trading-strategy-autopsy.md`, which covers the general evaluation framework.*

## What it actually is

Not a backtest — a **live SEC Form 4 insider-buying monitor**, and that's a
compliment. Two GitHub Actions jobs poll EDGAR (an hourly ATOM-feed pass and a
nightly full daily-index reconcile), filter for meaningful open-market insider
purchases (code P, common stock only, ≥ $50k, filing lag ≤ 1 day, no 10%
owners, no fund-like vehicles), email alerts via Brevo, and append every
qualifying filing to `filings_log.csv` with a precommitted entry rule
(same-day close if accepted before 15:45 ET, else next session). The README's
own words: "the log is the point... ~500 rows over six months is the
out-of-sample test."

**That is the correct methodology.** A forward log with precommitted rules is
immune to lookahead, survivorship, and parameter mining by construction. The
underlying signal also has real academic support: insider open-market
purchases predict abnormal returns (Lakonishok & Lee 2001; Jeng, Metrick &
Zeckhauser 2003 — roughly 6%/yr abnormal for purchases; Cohen, Malloy &
Pomorski 2012 — the alpha concentrates in "opportunistic", non-routine buys
and in cluster buys by multiple insiders).

## Bug 1 (confirmed, corrupts the experiment): every filing is logged 2–4×

`filings_log.csv` holds 261 rows but only **126 unique filings** — 100% of
rows are duplicated, always within the same run (identical `logged_at`
second), never across runs.

Root cause, `edgar_common.py::process()`:

```python
for r in rows:
    k = key_for(r)
    if k in seen:          # checks persisted state...
        continue
    new_keys.append(k)     # ...but 'seen' isn't updated until after the loop
    ...
seen.update(new_keys)      # too late: N in-batch copies all passed
```

EDGAR's `getcurrent` feed with `owner=include` lists each Form 4 **twice**
(once under the issuer, once under each reporting owner; multi-owner filings
appear more), and the daily index does the same — so every batch contains ≥2
copies of each filing, and every alert email and log row doubles. Fix:

```python
for r in rows:
    k = key_for(r)
    if k in seen:
        continue
    seen.add(k)            # dedup within this batch too
    new_keys.append(k)
```

Also dedupe the existing CSV once (`drop_duplicates` on everything except
`logged_at`/`source`), or all later stats double-count every event and
overstate cluster sizes.

**Key design note:** `key_for` = `symbol|txn_date|amount(rounded)`. Two
insiders buying the same dollar amount of the same stock on the same day
collide and the second is silently dropped — plausible in exactly the cluster
situations that matter most. The robust key is EDGAR's **accession number**
(unique per filing, already present in the URLs both jobs fetch). Migrating
keys re-alerts history once; keep matching old-style keys during transition or
accept one noisy day.

## Smaller defects, in priority order

2. **Friday buys are systematically excluded.** `qualifies()` computes lag in
   calendar days with `MAX_LAG_DAYS = 1`. A Friday purchase filed Monday
   (perfectly prompt under the SEC's 2-business-day rule) has lag 3 → rejected.
   ~2/7 of prompt filings never enter the sample, and not at random. Use
   business days.
3. **Evening acceptance gap.** EDGAR accepts filings until 22:00 ET; the daily
   reconcile runs 19:45 ET (and 18:45 ET in winter — the cron is fixed UTC,
   `17 11-22` / `45 23`, so both schedules shift an hour off across DST).
   Filings accepted after the reconcile are only caught if they survive in the
   next morning's 500-deep feed window. Have the daily job also re-reconcile
   day D−1, or run it after 22:00 ET.
4. **Amendments (4/A) inconsistently handled.** The hourly feed's
   `title.startswith('4')` matches "4/A"; the daily index's
   `startswith('4 ')` doesn't. An amendment with a corrected amount gets a new
   dedup key → duplicate alert for the same economic purchase. Detect `/A`
   and either skip or supersede.
5. **Foreign-listing rows pollute the log.** e.g. TSM logged from a purchase
   of "Common Shares (2330.TW)" at $73.39 — the Taiwan line, not the NYSE ADR
   (which trades ~2.5× higher and represents 5 ordinary shares). Entering the
   ADR at that logged price/size is a category error. Flag or exclude
   non-US-listed security titles.
6. **Multi-date filings.** A single Form 4 with P transactions on several
   dates sums them all but keeps only the last date; lag and entry are then
   computed against the wrong date for part of the money. Minor; take the
   max date explicitly or split rows.
7. **Zero-price footnote transactions are silently dropped** (price given
   only in a footnote parses as 0). Fine as a filter, but count them in the
   skip log so coverage is measurable.

## Strategy-level assessment

**What's right:** forward collection with precommitted entry rules; prompt-lag
filter (staleness kills this signal); $50k floor; 10%-owner and fund-vehicle
exclusions; the plan to grade week-2 alpha vs SPY on ~500 events. With ~126
real events/month, six months ≈ 700+ events; at a typical 5% two-week
event-level dispersion, the standard error on mean alpha is ≈ 0.2%, enough to
detect the effect sizes the literature reports — the experiment is actually
powered, *if* the duplicates are fixed.

**What the signal research says to add (cheap, at logging time):**
- **Market-cap normalization.** A $147k VP buy in TSM (~$1T) is noise; a $77k
  CEO buy in micro-cap BYRN is signal. Log market cap and `amount / mktcap`;
  the literature's alpha lives almost entirely in small caps.
- **Cluster flag.** Count distinct insiders buying the same symbol within a
  trailing window — the log already caught a real one (GBFH: four insiders,
  ~$1.2M, one day). Cluster buys are the strongest documented variant.
- **Routine-vs-opportunistic tag.** An insider who buys every August is
  routine (no alpha per Cohen–Malloy–Pomorski); one who never buys and
  suddenly does is the signal. Needs each insider's filing history — one
  extra EDGAR query per alert.
- **Officer seniority weight.** CEO/CFO purchases outperform director/other.
- **Liquidity guard.** 22% of logged names trade under $5; log average daily
  volume and cap assumed position size, or week-2 "alpha" won't be capturable
  after spreads.

**Precommit the grading now, in the repo:** horizon (week-2), benchmark
(SPY — better: a small-cap benchmark like IWM for like-for-like), entry price
definition, assumed cost per side, and the success criterion, *before* the
log matures. Writing the grading script today is what makes the six-month
result unarguable.

## Housekeeping

- The README already says it: **rotate the Brevo API key that was shared in
  chat**, and confirm the repo stays private (it also contains a personal
  email in the User-Agent, which SEC requires, but it shouldn't go public).
- Manual columns added to `filings_log.csv` (fills, week-2 prices) will
  collide with bot commits; keep manual grading in a separate file keyed by
  accession number.
