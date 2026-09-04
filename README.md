# The Argus record — machine-readable

[Argus Labs](https://arguslabs.io) publishes a daily book fixing for
prudent crypto carry: a simulated $100M BTC/ETH carry book run
mechanically under a published venue-risk rulebook, shown beside the
market average — the gap between the two being the price of prudence.
Named for the hundred-eyed sentinel of Greek mythology, Argus keeps an
eye on every venue's risk profile. Nothing is managed or sold; Argus
is a measurement service, the way an index provider is.

This repository is that record, machine-readable and independently
verifiable.


The published record of **ARGUS-PC-100M** (the Argus Prudent Carry
book) and its family — the two reference rates
(ARGUS-BTC-100M, ARGUS-stETH-100M), the market-average comparator, the
book's decision record, every detection episode, the per-fix envelope,
and the restatement ledger (freeze-era corrections plus one pre-freeze
memorial, each with its reason) — exactly as fixed daily at
[arguslabs.io](https://arguslabs.io).

The full specification is the standard under
**[arguslabs.io/documentation#methodology](https://arguslabs.io/documentation#methodology)**; the version change log is [arguslabs.io/methodology-changelog](https://arguslabs.io/methodology-changelog).
Operational failures are published on the
[incident log](https://arguslabs.io/incidents).

## What is in here

| file | contents |
|---|---|
| `data/portfolio_fixes.json` | one row per daily fix: carry-accounting NAV, full-marks NAV, basis, cumulative carry and costs, mix, active de-rates, methodology version |
| `data/reference_fixes.json` | daily fixes of the reference rates with the market average (rows for the pre-retirement ARGUS-ETH-100M era included, closed), the prudence premium, and the striking-solve binding |
| `data/decisions.json` | the book's action record — every de-rate, revert, mandated walk, universe exit, impairment, and recovery, one row per action |
| `data/episodes.json` | the observation record across three planes (market conditions per venue, book conditions, index-fixing conditions) — derived detector output, re-derived hourly, rooted, not under the finality clock |
| `data/envelopes.json` | one fingerprinted ENVELOPE per fix — the receipt's object: positions, per-leg workings, the window's settlement rows, execution (events and admissions with final outcomes), the premises in force with their citations, the ruleset hash, the inputs' provenance |
| `data/restatements.json` | the append-only restatement ledger from the freeze (2026-09-01) onward, plus the one pre-freeze memorial row (the 2026-08-21 in-window correction) — the 761-row development-era ledger was deliberately cleared at the freeze: table and key, fingerprint before and after, reason, time |
| `verify.py` | stdlib-only consistency verifier (Python 3.8+) |

## Fingerprints

Every book fix, reference fix, decision, and envelope carries:

- `row_sha256` — its citable `h2:` fingerprint, computed by the
  database at write time over every published field;
- `h2_preimage` — the exact canonical text that was hashed
  (envelopes hash their canonical part serialization).

`verify.py` recomputes the fingerprints against the published values,
so a change to any value, the preimage, or the hash is caught without
trusting any one of them. It also checks the rulebook's arithmetic
identities (`NAV = capital + settled carry − modeled costs − net
impairment`, with impairments read from the decisions record;
`prudence premium = market average − index`; the daily return chain;
monotone cumulatives; the envelope's internal identities — folds,
partitions, settlement sums, admission/event links), the record's
structural rule (episodes are observations, decisions are actions,
and no action name ever appears in the observation record), and the
restatement ledger's **last word** from the freeze (2026-09-01)
onward: for every fix the freeze-era ledger has touched, its newest
entry's resulting fingerprint must be the fingerprint this archive
publishes — a fix cannot have moved without the ledger saying so (the
single pre-freeze memorial row documents; it does not bind).

```
python3 verify.py
```

## Completeness

`data/manifest.json` binds each release: exact file digests, row
counts, per-file roots, coverage, and the **record root** — the
digest of the four fingerprint roots (book fixes, reference
fixes, decisions, envelopes) plus the episodes' and the restatement
ledger's canonical field-line digests, in manifest order, so every
published family is under the anchor (episodes carry no per-row
fingerprint; their `peak_stress` is serialized as its exact database
text so the root recomputes identically everywhere). `verify.py`
recomputes all of them, requires the daily series to be gapless from
inception (2026-08-04), and refuses an empty fingerprinted file, so
removing rows fails verification even if the manifest is regenerated
to match. The record root is also published **outside this
repository**, from the live database, in the site's feed
([arguslabs.io/feed.xml](https://arguslabs.io/feed.xml)); anchor the
archive against the live record with:

```
python3 verify.py <record-root-from-the-feed>
```

Every released archive's root is also recorded in the feed's
**release ledger**: a durable, append-only entry binding the root to
its archive commit and export time. The live root in the feed's
subtitle moves as fixes strike and the re-derived episode plane
restates — but this archive's own entry never does, so its expected
root stays publicly retrievable no matter how far the record has
moved on. To verify an archive, find its root entry in the feed (or
match this manifest's `record_root` against the ledger) and run
`python3 verify.py <that root>`. All six data families are exported
from a single database snapshot, so the root always describes one
moment of the record.

Decision evidence carries only its action's closed public schema —
enforced in the database at write time, at export, and re-checked by
`verify.py`.

## Status of the record

The methodology froze on **2026-09-01** and the record is final as
published: a fix (and its envelope) is struck at 12:00 UTC and
becomes **final 24 hours later** — corrections only inside that
window, each with a public ledger entry, and never after it; the
database itself refuses a change to a final row. Methodology changes
are versioned forward from their date and never restate prior fixes.
Every figure before the freeze is simulated **model history**: no
live capital. Returns are never annualized under one year.

## Reproducing the computation

The record is a deterministic replay of recorded public market
measurements. Two levels of verification:

1. **This repository** — the published outputs and their internal
   consistency. No dependencies, one command.
2. **Independent reimplementation** — the rulebook states every
   parameter of the computation. The frozen input bundle (every loaded
   series and configuration for the full era, alongside the golden
   outputs) is available to parties who wish to re-derive the series:
   **contact@arguslabs.io**. Publication of the bundle itself is
   pending a review of venue data-redistribution terms.

## Cadence

Refreshed daily by the record export; the site is the live record
between refreshes.

## Notes

Dated notes on the record's conventions, newest last.

- **2026-09-02 — settlement order.** From the 2 September 2026 fixing,
  each envelope lists its settlement rows sorted by `settled_at, venue,
  asset`, and its settlements block says `order: canonical`. Earlier
  envelopes list their rows in the order the record loaded them; they
  are final and verify as published.
- **2026-09-03 — methodology v1.1.** From the first hour after the 3
  September 2026 12:00 UTC fixing, fixes, envelopes and decisions
  carry methodology_version v1.1. Two changes: every cross-venue
  condition and reference value the book reads (the breadth of
  stress, the spot reference price, the funding regime anchor, the
  basis add-on) is taken over the venues the book holds; and the
  averages the book reads are computed with exact arithmetic, so a
  replay of the record from its inputs no longer depends on the order
  in which a database happens to sum. Fixes up to and including 3
  September remain v1.0 and unchanged.

---

© Argus Labs · published for verification and research · informational
publication, not investment advice, not an administered benchmark ·
hypothetical performance is not indicative of future results
