# The Argus record — machine-readable

[Argus Labs](https://arguslabs.io) publishes a daily benchmark for
prudent crypto carry: a simulated $100M BTC/ETH portfolio run
mechanically under a published venue-risk rulebook, shown beside the
market average — the gap between the two being the price of prudence.
Named for the hundred-eyed sentinel of Greek mythology, Argus keeps an
eye on every venue's risk profile. Nothing is managed or sold; Argus
is a measurement service, the way an index provider is.

This repository is that record, machine-readable and independently
verifiable.


The published record of **ARGUS-PC-100M** (the Argus Prudent Carry
Reference Portfolio) and its family — the two reference indices
(ARGUS-BTC-100M, ARGUS-stETH-100M), the market-average comparator, the
book's decision record, every detection episode, and the restatement
ledger (every change to a published fix, with its reason) — exactly as
fixed daily at [arguslabs.io](https://arguslabs.io).

The full specification is the standard under
**[arguslabs.io/documentation#methodology](https://arguslabs.io/documentation#methodology)**; the version change log is [arguslabs.io/methodology-changelog](https://arguslabs.io/methodology-changelog).
Operational failures are published on the
[incident log](https://arguslabs.io/incidents).

## What is in here

| file | contents |
|---|---|
| `data/portfolio_fixes.json` | one row per daily fix: carry-accounting NAV, full-marks NAV, basis, cumulative carry and costs, mix, active de-rates, methodology version |
| `data/reference_fixes.json` | daily fixes of the reference indices with the market average (rows for the pre-retirement ARGUS-ETH-100M era included, closed), the prudence premium, and the striking-solve binding |
| `data/decisions.json` | the book's action record — every de-rate, revert, mandated walk, universe exit, impairment, and recovery, one row per action |
| `data/episodes.json` | the observation record across three planes (market conditions per venue, book conditions, index-fixing conditions) — re-derived with the series, deliberately unfingerprinted |
| `data/restatements.json` | the append-only restatement ledger — every change to a published fix after it was first struck (pre-freeze declared restatement waves, in-window corrections): table and key, fingerprint before and after, reason, time |
| `verify.py` | stdlib-only consistency verifier (Python 3.8+) |

## Fingerprints

Every portfolio fix, reference fix, and decision carries:

- `row_sha256` — its citable `h2:` fingerprint, computed by the
  database at write time over every published field;
- `h2_preimage` — the exact canonical text that was hashed.

`verify.py` recomputes `sha256(h2_preimage)` against the fingerprint
**and** compares the parsed preimage field-by-field to the published
values, so a change to any value, the preimage, or the hash is caught
without trusting any one of them. It also checks the rulebook's
arithmetic identities (`NAV = capital + settled carry − modeled costs
− net impairment`, with impairments read from the decisions record;
`prudence premium = market average − index`; the daily return chain;
monotone cumulatives), the record's structural rule (episodes are
observations, decisions are actions, and no action name ever appears
in the observation record), and the restatement ledger's **last
word**: for every fix the ledger has touched, its newest entry's
resulting fingerprint must be the fingerprint this archive publishes
— a fix cannot have moved without the ledger saying so.

```
python3 verify.py
```

## Completeness

`data/manifest.json` binds each release: exact file digests, row
counts, per-file roots, coverage, and the **record root** — the
digest of the three fingerprint roots plus the episodes' and the
restatement ledger's canonical field-line digests, so every published
family is under the anchor (episodes carry no per-row fingerprint;
their `peak_stress` is serialized as its exact database text so the
root recomputes identically everywhere). `verify.py` recomputes all of them, requires
the daily series to be gapless from inception (2026-08-04), and
refuses an empty fingerprinted file, so removing rows fails
verification even if the manifest is regenerated to match.
The record root is also published **outside this repository**, from
the live database, in the site's feed
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
`python3 verify.py <that root>`. All five data families are exported
from a single database snapshot, so the root always describes one
moment of the record.

Decision evidence carries only its action's closed public schema —
enforced in the database at write time, at export, and re-checked by
`verify.py`.

## Status of the record

Until **2026-09-01** every number is simulated **model history**: no
live capital, restated from inception whenever the pre-publication
methodology changes (fingerprints restate with it). On that date the
methodology freezes and the record becomes final as published — fixes
and decisions immutable 48 hours after their day closes, corrections
only inside that window and only with a public log line, methodology
changes versioned forward and never restated. Returns are never
annualized under one year.

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

Refreshed at each methodology version and around the 2026-09-01
freeze; the site is the live record between refreshes.

---

© Argus Labs · published for verification and research · informational
publication, not investment advice, not an administered benchmark ·
hypothetical performance is not indicative of future results
