#!/usr/bin/env python3
"""Consistency and completeness verifier for the Argus
machine-readable record.

Standard library only; no network, no database. Run from the record
repo root:

  python3 verify.py [expected-record-root]

The verifier is TOTAL: on any bytes it returns a list of failures and
never raises (an internal error is itself reported as a failure, never
a traceback). It is SCHEMA-FIRST: every file, row and field is checked
against the record's declared shape — presence, JSON class, format,
vocabulary, numeric domain — BEFORE any root, fingerprint, identity or
ledger check reads it; a row outside the schema is a recorded failure
and is excluded from every later check, so nothing downstream ever
operates on a value it did not expect (self-attack 2026-08-25: the
earlier verifier raised on 1,203 of 4,320 field mutations and accepted
any JSON class in twenty rooted scalars).

Layers:

1. SHAPE — data/manifest.json and the five families parse exactly
   (numbers keep their spelling; a duplicate key is refused; every
   string is UTF-8 encodable); every row carries exactly the record's
   key set for its family; every field is in its class: dates and
   timestamps are ISO-Z text (the exporter's to_char rendering, so
   text order is time order); fingerprints are h2:<64 hex>; venues,
   index names and subjects are identifier tokens; stamps and reasons
   are in the record's text class (an explicit code-point set: no
   control, format, private-use or noncharacter code points), non-blank
   and bounded; numbers are finite, within the database's magnitude and
   scale, spelled as the database spelled them; peak_stress is the
   database's own float8 text; JSON members (shares, weights,
   constituents, derated, evidence) have their declared shapes.

2. FINGERPRINTS — every portfolio fix, reference fix and decision
   carries `row_sha256` (the citable fingerprint the database computed
   at write time) and `h2_preimage` (the canonical serialized text it
   hashed). The verifier recomputes sha256(preimage), requires the
   preimage's schema tag and EXACT key set for its family (every
   member present, null or not), and compares every field to the
   published value AS SPELLED — 1 and 1.0 are different claims, as
   they are to the database.

3. COMPLETENESS — the manifest binds the release: exact file digests,
   integer row counts, per-file roots, and the RECORD ROOT (the digest
   of all five per-file roots). The portfolio series is gapless from
   inception (2026-08-04); a reference index's series may skip a day
   ONLY where the record itself explains it: an index episode of kind
   `infeasible` opened at the first missed strike with `missed_fixes`
   equal to the gap. The record root is also published OUTSIDE this
   repository — https://arguslabs.io/feed.xml — pass it as the
   argument to anchor this archive against the live record; without
   it this tool proves internal consistency only.

4. ARITHMETIC IDENTITIES — on every row, never skipped: NAV = capital
   + settled carry − modeled costs − net impairment; basis = full-marks
   NAV − carry NAV (both present or both absent); the daily return
   chain (ret_1d absent only at inception); cumulative carry and costs
   never decrease; premium = market average − index whenever the
   market average is published.

5. VOCABULARY & DISCLOSURE — episodes are observations, decisions are
   actions; every decision's evidence carries ONLY its action's closed
   public schema, every episode's evidence its plane's; walks are
   book-level; every other decision names a venue token.

6. RESTATEMENT LEDGER — append-only, `seq` unique and positive,
   timestamps non-decreasing in seq; fixes: from the freeze
   (2026-09-01) the ledger's last word is the published fingerprint
   (or absence after a delete) and consecutive entries chain; the
   development-era ledger was cleared at the freeze, and its sole
   surviving memorial row (the 2026-08-21 in-window correction)
   documents rather than binds; decisions: a fingerprint the ledger
   retired is not published, a fingerprint the ledger produced and
   never retired is.

Requires Python 3.8 or newer.
"""
from __future__ import annotations

from decimal import Decimal
import datetime
import hashlib
import json
import math
import os
import re
import sys

CAPITAL0 = 100e6
INCEPTION = "2026-08-04"        # public rulebook fact (v1.8)
ACTIONS = {"de-rate", "revert", "walk", "universe-exit",
           "impairment", "recovery"}
PLANES = {"market", "book", "index"}
SEVERITIES = {"info", "warn", "crit"}
ASSETS = {"BTC", "ETH"}
FAMILIES = {"mark", "door", "funding", "withdrawal_notice",
            "depth", "spread", "oi", "other"}
IMPAIRMENT_KINDS = {"adl_tearup"}
# storage vocabularies (migrations 130/133): the book and index planes
# carry closed kinds; a market episode's kind is its detector family
BOOK_KINDS = {"cap-breach", "staking-paused", "infeasible-hold", "halt",
              # v1.13 (F-119 / F-122): a rule-mandated move the book
              # could not execute in full this hour — held, not partial
              "resync-deferred", "rebalance-deferred"}
INDEX_KINDS = {"infeasible", "staking-stale"}
# six families (181, 2026-08-30): the FIX ENVELOPE joins as the sixth
# — one fingerprinted object per portfolio fix carrying everything the
# receipt shows; the record root joins the six family roots in this
# order (record_live_root() in the database, the same order)
FILES = ("portfolio_fixes.json", "reference_fixes.json",
         "decisions.json", "episodes.json", "restatements.json",
         "envelopes.json")
FINGERPRINTED = FILES[:3] + FILES[5:]
RESTATED_TABLES = {"index_series", "index_fixes", "book_decisions",
                   "fix_envelope"}
RESTATEMENT_OPS = {"update", "delete"}
LEDGER_CHAIN_FROM = "2026-08-23T13:00:00Z"
# THE FREEZE (2026-09-01): the development-era ledger was cleared at
# the freeze (762 rows -> 1; DECISIONS 2026-08-31 "THE FREEZE ARCHIVE
# ACT"). The surviving pre-freeze row is a MEMORIAL of the 2026-08-21
# in-window correction: the fingerprints it names predate later
# development restatements whose chain went with the cleared rows, so
# the binding last-word and pair-chain rules apply to rows stamped
# from the freeze on. Post-freeze tampering cannot hide behind a
# backdated stamp: storage stamps restated_at itself, and the public
# archive's commit-to-commit diffs expose any fingerprint move that
# lacks a ledger row regardless of its claimed date.
LEDGER_FREEZE = "2026-09-01T00:00:00Z"
MANIFEST_SCHEMA = "argus-record-manifest-h6"
PREIMAGE_SCHEMA = {"portfolio_fixes.json": "argus-portfolio-fix-h5",
                   "reference_fixes.json": "argus-reference-fix-h2",
                   "decisions.json": "argus-book-decision-h1",
                   "envelopes.json": "argus-fix-envelope-h1"}
ENVELOPE_PARTS = ("headline", "positions", "workings", "settlements",
                  "execution", "premises", "rules", "provenance")
PREMISE_KINDS = {"sourced", "assumed", "fallback"}

# ---------------------------------------------------------------------
# the numeric domain: the FINITE IEEE-double magnitude as an exact
# integer bound (F-083) AND PostgreSQL numeric's smallest scale
# (F-090) — the database and this verifier hold the same set
_MAX_FINITE = int(sys.float_info.max)
_PG_MIN_EXPONENT = -16383


class _Num(Decimal):
    """A parsed JSON number that remembers its SPELLING. Equality on
    the exact view is equality of spelling (F-079/F-092/C-03): the
    database keeps a jsonb number's text and renders a float8 in one
    canonical form, and the fingerprint hashes that text — so 1 and
    1.0, 0.0000001 and 1E-7 are different claims. Arithmetic on a
    _Num is exact Decimal arithmetic; _fnum() is the binary value the
    identities are checked on."""

    def __new__(cls, text):
        obj = Decimal.__new__(cls, text)
        obj.text = text
        return obj


class _DuplicateKey(ValueError):
    pass


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise _DuplicateKey(k)
        d[k] = v
    return d


def _refuse_constant(name):
    # NaN / Infinity / -Infinity are not JSON; the database never emits
    # them as numbers (an infinite float8 renders as a STRING)
    raise ValueError(name)


def _exact_loads(text):
    """The ONE exact, TOTAL JSON loader: numbers keep their spelling
    (_Num), a duplicate key is refused, and any spelling the parser
    cannot represent — an exponent beyond Decimal's range, invalid
    JSON, a lone surrogate — is a controlled None, never a raise and
    never a binary-rounded fallback (F-088/F-089)."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(text, str):
        return None
    try:
        parsed = json.loads(text, parse_float=_Num, object_pairs_hook=_pairs,
                            parse_constant=_refuse_constant)
    except (ValueError, ArithmeticError, RecursionError, TypeError):
        return None
    # an ESCAPED lone surrogate ("\ud800") survives the decoder as a
    # string no UTF-8 sink can carry — refused anywhere in the value,
    # keys included (F-096), so no later layer can raise on it
    return None if _has_surrogate(parsed) else parsed


def _has_surrogate(v) -> bool:
    if isinstance(v, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in v)
    if isinstance(v, dict):
        return any(_has_surrogate(k) or _has_surrogate(x)
                   for k, x in v.items())
    if isinstance(v, list):
        return any(_has_surrogate(x) for x in v)
    return False


def _num(v) -> bool:
    """The archive numeric class on an exact value: finite, within the
    largest finite double's magnitude, within the database's scale.
    Booleans are never numbers."""
    if isinstance(v, bool) or not isinstance(v, (int, float, Decimal)):
        return False
    if isinstance(v, Decimal):
        return (v.is_finite() and v.copy_abs() <= _MAX_FINITE
                and v.as_tuple().exponent >= _PG_MIN_EXPONENT)
    if isinstance(v, int):
        return abs(v) <= _MAX_FINITE
    return math.isfinite(v)


def _count(v) -> bool:
    return type(v) is int and 1 <= v <= 999999


def _fnum(v) -> float:
    """The binary value of a checked number (identities)."""
    return float(v.text) if isinstance(v, _Num) else float(v)


# ---------------------------------------------------------------------
# formats — the exporter's renderings, as regular expressions
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_H2 = re.compile(r"h2:[0-9a-f]{64}")
_TOKEN_VENUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.()_-]{0,31}")
_TOKEN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.()_/-]{0,63}")
_TOKEN_LINE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_TOKEN_KIND = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_TOKEN_SIGNAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_:.-]{0,63}")
_LEG = re.compile(r"[A-Za-z0-9][A-Za-z0-9.()_-]{0,31}/(BTC|ETH)")
# PostgreSQL float8out, shortest-precise: 1.5, -0.25, 1e-07, 1e+300
_FLOAT8_TEXT = re.compile(r"-?[0-9]+(\.[0-9]+)?(e[+-][0-9]{2,3})?")
_TOKEN_DECISION_VENUE = _TOKEN_VENUE


def _is_date(v) -> bool:
    if not isinstance(v, str) or not _DATE.fullmatch(v):
        return False
    try:
        datetime.date.fromisoformat(v)
        return True
    except ValueError:
        return False


def _is_ts(v) -> bool:
    if not isinstance(v, str) or not _TS.fullmatch(v):
        return False
    try:
        datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


# ---- the record's TEXT CLASS: one explicit code-point set, stated as
# DATA here and spelled verbatim (text_class_are()) in storage —
# argus_text_ok / argus_text_nonblank / argus_text_class, migration 157
# (S1-02/S1-03: the old class was PostgreSQL's locale-defined
# [[:cntrl:]] and \S, which the verifier could only approximate and
# which admitted format, private-use and noncharacter code points).
# Frozen at Unicode 15.1 (every Cf, Co, Cs and noncharacter code point
# of that version, plus Cc); never a locale or library class.
TEXT_EXCLUDED = (
    (0x0000, 0x001F),                       # C0 controls
    (0x007F, 0x009F),                       # DEL, C1 controls
    (0x00AD, 0x00AD),                       # soft hyphen
    (0x0600, 0x0605), (0x061C, 0x061C),     # Arabic number signs, ALM
    (0x06DD, 0x06DD), (0x070F, 0x070F),     # end of ayah, Syriac mark
    (0x0890, 0x0891), (0x08E2, 0x08E2),     # Arabic pound/piastre, ayah
    (0x180E, 0x180E),                       # Mongolian vowel separator
    (0x200B, 0x200F),                       # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),                       # bidi embeddings and overrides
    (0x2060, 0x2064),                       # word joiner, invisible operators
    (0x2066, 0x206F),                       # bidi isolates, deprecated format
    (0xD800, 0xDFFF),                       # surrogates (not text at all)
    (0xE000, 0xF8FF),                       # private use, plane 0
    (0xFDD0, 0xFDEF),                       # noncharacters
    (0xFEFF, 0xFEFF),                       # byte-order mark / ZWNBSP
    (0xFFF9, 0xFFFB),                       # interlinear annotation
    (0xFFFE, 0xFFFF), (0x1FFFE, 0x1FFFF),   # plane-end noncharacters
    (0x2FFFE, 0x2FFFF), (0x3FFFE, 0x3FFFF), (0x4FFFE, 0x4FFFF),
    (0x5FFFE, 0x5FFFF), (0x6FFFE, 0x6FFFF), (0x7FFFE, 0x7FFFF),
    (0x8FFFE, 0x8FFFF), (0x9FFFE, 0x9FFFF), (0xAFFFE, 0xAFFFF),
    (0xBFFFE, 0xBFFFF), (0xCFFFE, 0xCFFFF), (0xDFFFE, 0xDFFFF),
    (0xEFFFE, 0xEFFFF), (0xFFFFE, 0xFFFFF), (0x10FFFE, 0x10FFFF),
    (0x110BD, 0x110BD), (0x110CD, 0x110CD), # Kaithi number signs
    (0x13430, 0x1343F),                     # Egyptian hieroglyph format
    (0x1BCA0, 0x1BCA3),                     # shorthand format
    (0x1D173, 0x1D17A),                     # musical beam/phrase format
    (0xE0001, 0xE0001), (0xE0020, 0xE007F), # language tag characters
    (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD),   # private use, planes 15/16
)
# "non-blank" = at least one code point OUTSIDE this set (U+0085 is
# already excluded above)
TEXT_BLANK = (
    (0x0009, 0x000D), (0x0020, 0x0020), (0x00A0, 0x00A0), (0x1680, 0x1680),
    (0x2000, 0x200A), (0x2028, 0x2029), (0x202F, 0x202F), (0x205F, 0x205F),
    (0x3000, 0x3000),
)
TEXT_MAX = {"stamp": 512, "reason": 2000}


def _in_ranges(o: int, ranges) -> bool:
    return any(lo <= o <= hi for lo, hi in ranges)


def _is_text(v) -> bool:
    """A string the record can carry: UTF-8 encodable (a lone
    surrogate is not) and no code point of TEXT_EXCLUDED."""
    if not isinstance(v, str):
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return not any(_in_ranges(ord(c), TEXT_EXCLUDED) for c in v)


def _text_ok(v, maxlen: int) -> bool:
    """THE text class: _is_text, non-blank (a code point outside
    TEXT_BLANK), at most `maxlen` code points — argus_text_class(t,
    maxlen) in storage, from the same data."""
    return (_is_text(v) and len(v) <= maxlen
            and any(not _in_ranges(ord(c), TEXT_BLANK) for c in v))


def _is_stamp(v) -> bool:
    # the reference books still carry pre-publication prose stamps (up
    # to 260 characters) until the v1.0 reset — the class admits them
    return _text_ok(v, TEXT_MAX["stamp"])


def _is_reason(v) -> bool:
    return _text_ok(v, TEXT_MAX["reason"])


def text_class_are(ranges=TEXT_EXCLUDED) -> str:
    """The ranges as a PostgreSQL ARE bracket-expression body, in the
    \\Uxxxxxxxx spelling (one code point per escape, no locale class):
    migration 157 carries this text verbatim and a gate probe holds the
    built schema to it."""
    return "".join(f"\\U{lo:08X}" if lo == hi else f"\\U{lo:08X}-\\U{hi:08X}"
                   for lo, hi in ranges)


def _tok(rx):
    return lambda v: isinstance(v, str) and rx.fullmatch(v) is not None


def _opt(f):
    return lambda v: v is None or f(v)


def _weights(v) -> bool:
    return (isinstance(v, dict)
            and all(isinstance(k, str) and _TOKEN_NAME.fullmatch(k)
                    and _num(x) for k, x in v.items()))


def _shares(v) -> bool:
    return (isinstance(v, dict)
            and all(isinstance(k, str) and _LEG.fullmatch(k)
                    and _num(x) for k, x in v.items()))


def _name_list(v) -> bool:
    return (isinstance(v, list)
            and all(isinstance(x, str) and _TOKEN_NAME.fullmatch(x)
                    for x in v))


def _is_float8_text(v) -> bool:
    return (isinstance(v, str) and _FLOAT8_TEXT.fullmatch(v) is not None
            and _num(Decimal(v)))


def _is_object(v) -> bool:
    return isinstance(v, dict)


# the closed PUBLIC evidence schema per action (migrations 134/135/152/
# 155): key -> value-class check
PUBLIC_EVIDENCE = {
    "de-rate": {"families": lambda v: isinstance(v, list)
                and all(isinstance(x, str) and x in FAMILIES for x in v),
                "cap_pct": _num},
    "revert": {},
    "walk": {"cost_usd": _num,
             "turnover_usd": _num,
             "mandated": lambda v: isinstance(v, bool)},
    "universe-exit": {},
    # the pre-registered ADL tear-up class (v1.5) is public: its kind
    # and the sized fraction explain the loss (self-attack D-11)
    "impairment": {"loss_usd": _num,
                   "kind": lambda v: isinstance(v, str)
                   and v in IMPAIRMENT_KINDS,
                   "tearup_frac": lambda v: _num(v)
                   and Decimal(0) <= v <= Decimal(1)},   # exact, never float
    "recovery": {"recovered_usd": _num},
}
# the closed PUBLIC evidence schema per EPISODE plane (F-078/F-080;
# migration 151): venue and line are tokens, missed_fixes a positive
# JSON integer AS SPELLED
EPISODE_EVIDENCE = {
    "book": {"venue": _tok(_TOKEN_VENUE)},
    "market": {"line": _tok(_TOKEN_LINE)},
    "index": {"missed_fixes": _count},
}

# ---------------------------------------------------------------------
# the record's SHAPE: exact key set per family (the exporter's SELECT
# list, F-093) and the class of every field
SCHEMA = {
    "portfolio_fixes.json": {
        "fix_date": _is_date, "nav_usd": _num, "ret_1d": _opt(_num),
        "carry_usd_cum": _num, "cost_usd_cum": _num, "mix_btc": _num,
        "shares": _shares, "derated": _name_list,
        "methodology_version": _is_stamp, "full_nav_usd": _opt(_num),
        "basis_usd": _opt(_num), "naive_nav_usd": _opt(_num),
        "naive_carry_usd_cum": _opt(_num),
        # h5 (178, v1.11): the capital after the stable reserve and its
        # parts — MANDATORY (F-120, Sol 2026-08-30: every h5 row was
        # struck under h5; there is no older row to excuse a null)
        "capital_usd": _num, "stable_reserve_usd": _num,
        "stable_margin_usd": _num, "naive_capital_usd": _num,
        "row_sha256": _tok(_H2),
        "published_at": _is_ts, "h2_preimage": _is_text},
    "reference_fixes.json": {
        "index_name": _tok(_TOKEN_NAME), "fix_date": _is_date,
        "value_bp": _num, "prudence_premium_bp": _opt(_num),
        "naive_bp": _opt(_num), "naive_venue": _opt(_tok(_TOKEN_VENUE)),
        "naive_weights": _opt(_weights), "weights": _weights,
        "constituents": _name_list, "methodology_version": _is_stamp,
        "staking_bp": _opt(_num), "unwind_days": _opt(_num),
        "row_sha256": _tok(_H2), "solve_sha256": _opt(_tok(_H2)),
        "published_at": _is_ts, "h2_preimage": _is_text},
    "decisions.json": {
        "decided_at": _is_ts,
        "action": lambda v: isinstance(v, str) and v in ACTIONS,
        "venue": _opt(_tok(_TOKEN_VENUE)), "evidence": _is_object,
        "methodology_version": _is_stamp, "row_sha256": _tok(_H2),
        "published_at": _is_ts, "h2_preimage": _is_text},
    "episodes.json": {
        "plane": lambda v: isinstance(v, str) and v in PLANES,
        "subject": _tok(_TOKEN_NAME),
        "asset": _opt(lambda v: isinstance(v, str) and v in ASSETS),
        "kind": _tok(_TOKEN_KIND), "signal": _opt(_tok(_TOKEN_SIGNAL)),
        "severity": lambda v: isinstance(v, str) and v in SEVERITIES,
        "opened_at": _is_ts, "closed_at": _opt(_is_ts),
        "peak_stress": _opt(_is_float8_text),
        "methodology_version": _is_stamp, "evidence": _is_text},
    "restatements.json": {
        "seq": lambda v: type(v) is int and v >= 1,
        "table_name": lambda v: isinstance(v, str) and v in RESTATED_TABLES,
        "index_name": _opt(_tok(_TOKEN_NAME)), "fix_date": _is_date,
        "op": lambda v: isinstance(v, str) and v in RESTATEMENT_OPS,
        "old_row_sha256": _opt(_tok(_H2)),
        "new_row_sha256": _opt(_tok(_H2)), "reason": _is_reason,
        "restated_at": _is_ts},
    # the fix envelope (181): every part a JSON object; the parts'
    # inner identities are held in the ARITHMETIC layer below
    "envelopes.json": {
        "fix_date": _is_date, "headline": _is_object,
        "positions": _is_object, "workings": _is_object,
        "settlements": _is_object, "execution": _is_object,
        "premises": _is_object, "rules": _is_object,
        "provenance": _is_object, "methodology_version": _is_stamp,
        "row_sha256": _tok(_H2), "published_at": _is_ts,
        "h2_preimage": _is_text},
}
REQUIRED_KEYS = {name: frozenset(spec) for name, spec in SCHEMA.items()}
# the h2 field list per fingerprinted family — the preimage's keys
# beside its schema tag; the exporter spells these public fields FROM
# the preimage (F-092)
H2_FIELDS = {
    "portfolio_fixes.json": (
        "fix_date", "nav_usd", "ret_1d", "carry_usd_cum",
        "naive_carry_usd_cum", "cost_usd_cum", "mix_btc", "shares",
        "derated", "methodology_version", "full_nav_usd", "basis_usd",
        "naive_nav_usd", "capital_usd", "stable_reserve_usd",
        "stable_margin_usd", "naive_capital_usd"),
    "reference_fixes.json": (
        "index_name", "fix_date", "value_bp", "prudence_premium_bp",
        "naive_bp", "naive_venue", "naive_weights", "weights",
        "constituents", "methodology_version", "staking_bp",
        "unwind_days"),
    "decisions.json": (
        "decided_at", "action", "venue", "evidence",
        "methodology_version"),
    "envelopes.json": ("fix_date",) + ENVELOPE_PARTS + ("methodology_version",),
}
# provenance fields the h2 recipes exclude but the ROOT anchors (124 /
# F-046 self-attack): a forged publication time has to move the anchor
ROOT_EXTRAS = {"portfolio_fixes.json": ("published_at",),
               "reference_fixes.json": ("published_at", "solve_sha256"),
               "decisions.json": ("published_at",),
               "envelopes.json": ("published_at",)}
# canonical row order per family — the exporter's own ORDER BY, a
# TOTAL order (F-072/F-076/F-077)
ORDER_KEYS = {"portfolio_fixes.json": ("fix_date",),
              "reference_fixes.json": ("index_name", "fix_date"),
              "decisions.json": ("decided_at", "action", "venue",
                                 "row_sha256"),
              "episodes.json": ("opened_at", "plane", "subject", "asset",
                                "kind", "signal", "closed_at", "severity",
                                "peak_stress", "methodology_version",
                                "evidence"),
              "restatements.json": ("seq",),
              "envelopes.json": ("fix_date",)}


def _spelling(d: Decimal) -> str:
    return d.text if isinstance(d, _Num) else str(d)


def _exact_eq(a, b) -> bool:
    """Representation-aware equality on the exact view: numbers equal
    only as SPELLED; ints, strings, booleans and null must match in
    type and value; dicts and lists recurse."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, Decimal) or isinstance(b, Decimal):
        return (isinstance(a, Decimal) and isinstance(b, Decimal)
                and _spelling(a) == _spelling(b))
    if isinstance(a, dict) or isinstance(b, dict):
        return (isinstance(a, dict) and isinstance(b, dict)
                and set(a) == set(b)
                and all(_exact_eq(a[k], b[k]) for k in a))
    if isinstance(a, list) or isinstance(b, list):
        return (isinstance(a, list) and isinstance(b, list)
                and len(a) == len(b)
                and all(_exact_eq(x, y) for x, y in zip(a, b)))
    return type(a) is type(b) and a == b


def _ordered(rows: list, keys: tuple) -> bool:
    """Non-decreasing on the family's TOTAL key (rows equal on the
    whole key are byte-identical public rows, F-077)."""
    def key(r):
        out = []
        for k in keys:
            v = r.get(k)
            if v is None:
                out.append((0, ""))
            elif isinstance(v, (int, float, Decimal)) \
                    and not isinstance(v, bool):
                out.append((1, float(v)))
            else:
                out.append((2, str(v)))
        return tuple(out)
    try:
        return all(key(a) <= key(b) for a, b in zip(rows, rows[1:]))
    except TypeError:
        return False


def _line(values: list) -> str:
    """A canonical row line is a JSON ARRAY — json.dumps here and
    jsonb_build_array(...)::text in the database produce identical
    bytes (F-048)."""
    return json.dumps(values, ensure_ascii=False)


def _safe(v):
    """A root line value: the record's own scalar types only."""
    if isinstance(v, _Num):
        return v.text
    return v if isinstance(v, (str, int, float, bool)) or v is None \
        else json.dumps(v, sort_keys=True, default=str)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _digest_lines(lines) -> str:
    return _sha("\n".join(sorted(lines)).encode("utf-8", "replace"))


def file_root(rows: list, extras: tuple = ()) -> str:
    return _digest_lines(_line([_safe(r.get("row_sha256"))]
                               + [_safe(r.get(f)) for f in extras])
                         for r in rows if isinstance(r, dict))


def episode_line(e: dict) -> str:
    return _line([_safe(e.get(k))
                  for k in ("plane", "subject", "asset", "kind",
                            "signal", "severity", "opened_at",
                            "closed_at", "peak_stress",
                            "methodology_version", "evidence")])


def episodes_root(rows: list) -> str:
    return _digest_lines(episode_line(e) for e in rows
                         if isinstance(e, dict))


def restatement_line(r: dict) -> str:
    return _line([_safe(r.get(k))
                  for k in ("seq", "table_name", "index_name",
                            "fix_date", "op", "old_row_sha256",
                            "new_row_sha256", "reason", "restated_at")])


def restatements_root(rows: list) -> str:
    return _digest_lines(restatement_line(r) for r in rows
                         if isinstance(r, dict))


def family_root(name: str, rows: list) -> str:
    if name in FINGERPRINTED:
        return file_root(rows, ROOT_EXTRAS[name])
    if name == "episodes.json":
        return episodes_root(rows)
    return restatements_root(rows)


def _value_eq(a, b) -> bool:
    """VALUE equality on the exact view — numbers by numeric value
    (the envelope's jsonb spells 100000000.0 where the portfolio row's
    float8 spells 100000000; both are the same number), everything
    else as _exact_eq. The envelope's headline is held to the portfolio
    row by this: the same fix, two spellings, one value."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, Decimal)) and isinstance(b, (int, Decimal)):
        return Decimal(a) == Decimal(b)
    if isinstance(a, dict) or isinstance(b, dict):
        return (isinstance(a, dict) and isinstance(b, dict)
                and set(a) == set(b)
                and all(_value_eq(a[k], b[k]) for k in a))
    if isinstance(a, list) or isinstance(b, list):
        return (isinstance(a, list) and isinstance(b, list)
                and len(a) == len(b)
                and all(_value_eq(x, y) for x, y in zip(a, b)))
    return type(a) is type(b) and a == b


_HEX64 = re.compile(r"[0-9a-f]{64}")
_ISO_ANY = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(\.[0-9]+)?(Z|\+00:00)")
# the execution events the calculator can write (research/replay/
# loop.py, transcribed 2026-08-31 — F-126: a closed vocabulary)
EXECUTION_EVENTS = {
    "halt", "halt-end", "impairment", "recovery",
    "staking-unavailable", "staking-resumed",
    "solve-infeasible-hold", "solve-resumed",
    "de-rate", "revert", "universe-exit", "walk",
    "resync-deferred", "resync-resumed",
    "rebalance-deferred", "rebalance-resumed",
    # F-142 (Sol 2026-09-01): the market book's executed monthly
    # rebalance leaves a magnitude-bearing event (cost, turnover,
    # post-fill weights) bound 1:1 to its executed admission
    "rebalance",
}
# F-133/F-134 (Sol 2026-08-31): the admissions record's closed shape —
# outcomes are FINAL truths (recorded after the economic gate), legs
# carry identity and side only, and executed walk admissions must
# match walk events one to one
ADMISSION_OUTCOMES = {"executed", "cost-rejected", "nothing-admissible"}
# F-147 (Sol 2026-09-01): a v1.0 record carries EXACTLY the registry's
# premise names — an omitted premise silently disables its dependent
# identities, so omission is refusal
PREMISES_V10 = frozenset({
    "basis_addon", "capital0", "clock_h", "deribit_ladder",
    "im_fallback_frac", "margin_clock_k", "mm_of_im", "mm_of_im_venue",
    "parked_share", "price_stress", "spot_leg_cost_bp",
    "sygnum_intra_h", "sygnum_weekend_h"})
WALK_ORIGINS = {"compliance-walk", "cross-asset-walk",
                "within-asset-walk"}
ADMISSION_KEYS = frozenset({"t", "origin", "outcome", "mandated",
                            "proposed", "admitted", "deferred"})
LEG_ID_KEYS = frozenset({"venue", "asset", "side"})


def _tzn(s):
    """One spelling for a timestamp: the calculator emits both
    '...+00:00' (isoformat) and '...Z'."""
    return s.replace("+00:00", "Z") if isinstance(s, str) else s


def _dom_num(lo, hi, lo_open=False, hi_open=False):
    def ok(v):
        if isinstance(v, bool) or not isinstance(v, (int, float, Decimal)):
            return False
        try:
            x = float(v)
        except (ValueError, OverflowError):
            return False
        if not math.isfinite(x):
            return False
        return ((x > lo if lo_open else x >= lo)
                and (x < hi if hi_open else x <= hi))
    return ok


# premise value domains (engine/kernel.PREMISE_DOMAINS, transcribed —
# this verifier is standalone; F-126/F-127: a re-signed premise value
# outside its closed domain is refused offline too)
PREMISE_VALUE_DOMAINS = {
    "capital0": _dom_num(1.0, 1e12),
    "price_stress": _dom_num(0.0, 1.0, lo_open=True),
    "im_fallback_frac": _dom_num(0.0, 1.0, lo_open=True),
    "mm_of_im": _dom_num(0.0, 1.0, lo_open=True),
    "margin_clock_k": _dom_num(0.0, 10.0, lo_open=True),
    "parked_share": _dom_num(0.0, 1.0, hi_open=True),
    "spot_leg_cost_bp": _dom_num(0.0, 1000.0),
    "sygnum_intra_h": _dom_num(0.0, 168.0, lo_open=True),
    "sygnum_weekend_h": _dom_num(0.0, 168.0, lo_open=True),
}


def record_root(roots: dict) -> str:
    """portfolio, reference, decisions, episodes, restatements,
    envelopes roots — in that order, newline-joined, hashed. The site's
    feed publishes the same value from the live database
    (record_live_root())."""
    return _sha("\n".join(str(roots.get(n, "")) for n in FILES).encode())


# ---------------------------------------------------------------------
def run(base: str, expected_root=None) -> list:
    """All checks; returns the list of failures (empty = pass). Total:
    an internal error is a failure line, never a raise."""
    fails: list = []
    try:
        _run(base, expected_root, fails)
    except Exception as err:      # noqa: BLE001 — the totality contract
        fails.append(f"verifier internal error — the archive is NOT "
                     f"verified: {type(err).__name__}: {err!r}")
    return fails


def _run(base: str, expected_root, fails: list) -> None:
    def check(ok: bool, msg: str) -> None:
        if not ok:
            fails.append(msg)

    # ---- 1. SHAPE: files, manifest, rows, fields ----------------------
    raw: dict = {}
    exact: dict = {}
    ok_rows: dict = {}          # per family: indexes of rows in shape
    for name in FILES:
        path = os.path.join(base, "data", name)
        if not os.path.isfile(path):
            fails.append(f"{name}: file missing")
            raw[name], exact[name], ok_rows[name] = b"", [], []
            continue
        with open(path, "rb") as f:
            raw[name] = f.read()
        parsed = _exact_loads(raw[name])
        check(isinstance(parsed, list),
              f"{name}: not exactly parseable JSON (invalid JSON, a "
              f"duplicate key, a lone surrogate, or a number outside "
              f"the exact domain) (F-089)")
        exact[name] = parsed if isinstance(parsed, list) else []
        good = []
        for i, r in enumerate(exact[name]):
            if not isinstance(r, dict):
                check(False, f"{name}[{i}]: row is not an object")
                continue
            problems = _row_shape(name, i, r)
            if problems:
                fails.extend(problems)
                continue
            good.append(i)
        ok_rows[name] = good
    man_path = os.path.join(base, "data", "manifest.json")
    man = None
    if os.path.isfile(man_path):
        with open(man_path, "rb") as f:
            man = _exact_loads(f.read())
    check(isinstance(man, dict), "manifest: missing or not a JSON object")
    man = man if isinstance(man, dict) else {}
    files = man.get("files")
    check(isinstance(files, dict), "manifest: `files` is not an object")
    files = files if isinstance(files, dict) else {}
    check(man.get("schema") == MANIFEST_SCHEMA, "manifest: unknown schema")

    def rows_of(name):
        return [exact[name][i] for i in ok_rows[name]]

    fixes = rows_of("portfolio_fixes.json")
    refs = rows_of("reference_fixes.json")
    decisions = rows_of("decisions.json")
    episodes = rows_of("episodes.json")
    restatements = rows_of("restatements.json")
    envelopes = rows_of("envelopes.json")
    complete = all(len(ok_rows[n]) == len(exact[n]) for n in FILES)

    # ---- 2/3. COMPLETENESS: manifest binds the release ------------------
    roots: dict = {}
    for name in FILES:
        entry = files.get(name)
        entry = entry if isinstance(entry, dict) else {}
        rows_claim = entry.get("rows")
        check(type(rows_claim) is int and rows_claim == len(exact[name]),
              f"manifest: {name} row count {rows_claim!r} != "
              f"{len(exact[name])} rows present")
        check(entry.get("sha256") == _sha(raw[name]),
              f"manifest: {name} digest does not match the file")
        roots[name] = family_root(name, exact[name])
        check(entry.get("root") == roots[name],
              f"manifest: {name} root mismatch")
        check(_ordered(rows_of(name), ORDER_KEYS[name]),
              f"{name}: rows are not in the record's canonical order "
              f"{ORDER_KEYS[name]}")
        if name in FINGERPRINTED:
            check(len(exact[name]) > 0,
                  f"{name}: a fingerprinted record with ZERO rows is "
                  f"never a valid release")
    rroot = record_root(roots)
    check(man.get("record_root") == rroot,
          "manifest: record root does not derive from the data")
    if expected_root is not None:
        check(rroot == str(expected_root).strip(),
              f"record root {rroot} does not match the externally "
              f"published root")
    check(bool(fixes) and fixes[0]["fix_date"] == INCEPTION,
          f"portfolio: first fix is not inception ({INCEPTION})")
    check(bool(fixes) and man.get("as_of") == fixes[-1]["fix_date"],
          "manifest: as_of is not the latest portfolio fix")
    _consecutive([r["fix_date"] for r in fixes], "portfolio", fails)
    by_index: dict = {}
    for r in refs:
        by_index.setdefault(r["index_name"], []).append(r["fix_date"])
    for ix, dates in by_index.items():
        _consecutive(dates, f"reference {ix}", fails,
                     explained=_explained_gaps(episodes, ix))

    # ---- FINGERPRINTS ---------------------------------------------------
    def verify_fingerprints(rows, name, label):
        fields = H2_FIELDS[name]
        for i, r in enumerate(rows):
            tag = f"{label}[{i}]"
            pre = r["h2_preimage"]
            check(r["row_sha256"] == "h2:" + _sha(pre.encode("utf-8")),
                  f"{tag}: preimage does not hash to the fingerprint")
            parsed = _exact_loads(pre)
            if not isinstance(parsed, dict):
                check(False, f"{tag}: preimage is not exactly parseable "
                             f"JSON (F-089)")
                continue
            check(parsed.get("schema") == PREIMAGE_SCHEMA[name],
                  f"{tag}: preimage schema tag {parsed.get('schema')!r} "
                  f"is not {PREIMAGE_SCHEMA[name]!r} (F-095)")
            want = set(fields) | {"schema"}
            check(set(parsed) == want,
                  f"{tag}: preimage key set differs from the record's "
                  f"(missing {sorted(want - set(parsed))}, extra "
                  f"{sorted(set(parsed) - want)}) (F-095)")
            for fld in fields:
                check(_exact_eq(parsed.get(fld), r.get(fld)),
                      f"{tag}: field `{fld}` differs from its preimage "
                      f"({r.get(fld)!r} vs {parsed.get(fld)!r})")

    verify_fingerprints(fixes, "portfolio_fixes.json", "portfolio")
    verify_fingerprints(refs, "reference_fixes.json", "reference")
    verify_fingerprints(decisions, "decisions.json", "decision")
    verify_fingerprints(envelopes, "envelopes.json", "envelope")

    # ---- 4a. THE ENVELOPE'S IDENTITIES (181): one per portfolio fix;
    # the headline IS the portfolio row; the workings sum to the
    # headline's stable margin; the window's settlements sum to the
    # carry the headline gained; the positions partition the capital
    # the headline states; every premise declares its kind ----------
    check([e["fix_date"] for e in envelopes]
          == [r["fix_date"] for r in fixes],
          "envelopes: not exactly one envelope per portfolio fix, in order")
    fix_by_date = {r["fix_date"]: r for r in fixes}
    prev_carry = 0.0
    for e in envelopes:
        tag = f"envelope {e['fix_date']}"
        r = fix_by_date.get(e["fix_date"])
        if r is None:
            continue
        # F-134: every part's EXACT key set (a re-signed extra or
        # missing member is refused before any identity reads it)
        for part9, wantk9 in (
                ("positions", {"hedge", "legs", "unallocated_usd",
                               "spot_lots", "ref_px"}),
                ("workings", {"sleeves", "legs"}),
                ("settlements", {"rows", "funding_usd", "staking_usd"}),
                ("execution", {"events", "admissions", "open_at_strike"}),
                ("rules", {"methodology_version", "ruleset_sha256"}),
                ("provenance", {"window_from", "window_to",
                                "funding_prints", "funding_sha256",
                                "marks_at_strike"})):
            check(isinstance(e[part9], dict) and set(e[part9]) == wantk9,
                  f"{tag}: {part9} key set differs from the record's")
        prov9p = e["provenance"] if isinstance(e["provenance"], dict) else {}
        wfN9 = _tzn(prov9p.get("window_from") or "")
        wtN9 = _tzn(prov9p.get("window_to") or "9999-12-31T23:59:59Z")
        head = e["headline"]
        want = set(H2_FIELDS["portfolio_fixes.json"])
        check(set(head) == want,
              f"{tag}: headline key set differs from the portfolio row's "
              f"(missing {sorted(want - set(head))}, extra "
              f"{sorted(set(head) - want)})")
        for fld in sorted(want & set(head)):
            check(_value_eq(head[fld], r.get(fld)),
                  f"{tag}: headline `{fld}` ({head[fld]!r}) is not the "
                  f"portfolio row's ({r.get(fld)!r})")
        cap = _fnum(r["capital_usd"])
        # positions: Σ legs by asset = the asset's hedge; Σ hedge = the
        # capital; the mix is the hedge split; the legs' shares are the
        # headline's shares (published at 4 dp)
        pos = e["positions"]
        hedge = pos.get("hedge") if isinstance(pos.get("hedge"), dict) else {}
        legs = pos.get("legs") if isinstance(pos.get("legs"), list) else []
        check(set(hedge) == ASSETS and all(_num(v) for v in hedge.values()),
              f"{tag}: positions.hedge is not a BTC/ETH number pair")
        # F-143 (Sol 2026-09-01): a held leg has STRICTLY POSITIVE
        # exact notional — an exact-zero row is not a position and can
        # smuggle an arbitrary strike mark; duplicate keys refused
        check(all(isinstance(lg, dict) and _num(lg.get("share"))
                  and _num(lg.get("notional_usd"))
                  and _fnum(lg["notional_usd"]) > 0
                  and isinstance(lg.get("venue"), str)
                  and lg.get("asset") in ASSETS for lg in legs),
              f"{tag}: positions.legs rows outside their shape (a held "
              f"leg needs a strictly positive notional)")
        legkeys0 = [f"{lg.get('venue')}/{lg.get('asset')}" for lg in legs
                    if isinstance(lg, dict)]
        check(len(set(legkeys0)) == len(legkeys0),
              f"{tag}: duplicate positions.legs keys")
        if set(hedge) == ASSETS and all(_num(v) for v in hedge.values()):
            tot = sum(_fnum(v) for v in hedge.values())
            check(abs(tot - cap) < 0.015,
                  f"{tag}: Σ hedge {tot} != headline capital {cap}")
            check(tot > 0 and abs(_fnum(hedge["BTC"]) / tot
                                  - _fnum(r["mix_btc"])) < 1e-6,
                  f"{tag}: hedge split is not the headline's mix_btc")
            # the shorts cover the asset's leg up to the STATED
            # unallocated part (the solve's shares need not sum to
            # one): every leg is its share of the hedge, and Σ legs +
            # unallocated = hedge to the cent — a wrong leg cannot hide
            # in the residual because each leg is pinned to its share
            una = pos.get("unallocated_usd") \
                if isinstance(pos.get("unallocated_usd"), dict) else {}
            for lg in legs:
                if isinstance(lg, dict) and lg.get("asset") in ASSETS \
                        and _num(lg.get("share")) and _num(lg.get("notional_usd")):
                    # the share is published at 6 dp; the notional is
                    # the unrounded share × hedge — half a unit of the
                    # sixth place, plus the cent
                    h = _fnum(hedge[lg["asset"]])
                    check(abs(_fnum(lg["notional_usd"]) - _fnum(lg["share"]) * h)
                          <= 0.5e-6 * abs(h) + 0.015,
                          f"{tag}: leg {lg.get('venue')}/{lg['asset']} notional "
                          f"is not share × hedge")
            for asset in sorted(ASSETS):
                s = sum(_fnum(lg["notional_usd"]) for lg in legs
                        if isinstance(lg, dict) and lg.get("asset") == asset
                        and _num(lg.get("notional_usd")))
                u = _fnum(una[asset]) if _num(una.get(asset)) else None
                check(u is not None
                      and abs(s + u - _fnum(hedge[asset])) < 0.015,
                      f"{tag}: Σ {asset} legs {s} + unallocated {u} != "
                      f"hedge {hedge[asset]}")
        shares = r.get("shares") if isinstance(r.get("shares"), dict) else {}
        leg_shares = {f"{lg.get('venue')}/{lg.get('asset')}": lg.get("share")
                      for lg in legs if isinstance(lg, dict)}
        check(set(leg_shares) == set(shares)
              and all(_num(leg_shares[k]) and _num(shares[k])
                      and abs(_fnum(leg_shares[k]) - _fnum(shares[k])) < 1e-4
                      for k in shares),
              f"{tag}: positions.legs are not the headline's shares")
        # workings: the stable sleeves sum to the headline's stable margin
        sl = e["workings"].get("sleeves")
        check(isinstance(sl, list) and all(
            isinstance(x, dict) and _num(x.get("sleeve_usd"))
            and isinstance(x.get("kind"), str) for x in sl),
            f"{tag}: workings.sleeves rows outside their shape")
        if isinstance(sl, list):
            stable = sum(_fnum(x["sleeve_usd"]) for x in sl
                         if isinstance(x, dict) and x.get("kind") == "stable"
                         and _num(x.get("sleeve_usd")))
            check(abs(stable - _fnum(r["stable_margin_usd"])) < 0.015,
                  f"{tag}: Σ stable sleeves {stable} != headline "
                  f"stable_margin_usd {r['stable_margin_usd']}")
        # settlements: the window's rows sum to Δ carry vs the prior fix
        st = e["settlements"].get("rows")
        check(isinstance(st, list) and all(
            isinstance(x, dict) and _num(x.get("usd")) for x in st),
            f"{tag}: settlements.rows outside their shape")
        if isinstance(st, list):
            total = sum(_fnum(x["usd"]) for x in st
                        if isinstance(x, dict) and _num(x.get("usd")))
            delta = _fnum(r["carry_usd_cum"]) - prev_carry
            check(abs(total - delta) < 0.015,
                  f"{tag}: Σ settlements {total} != Δ carry {delta}")
        prev_carry = _fnum(r["carry_usd_cum"])
        # ---- F-126 (Sol 2026-08-30): a fresh, VALID fingerprint must
        # not authenticate false displayed semantics. Every derivable
        # identity inside the signed parts is RECOMPUTED, every digest
        # and count has its closed shape, every vocabulary is closed —
        # the five re-signed attacks (workings, settlement row, spot
        # lot, rules digest, provenance) all fail here.
        premv = {k: (p.get("value") if isinstance(p, dict) else None)
                 for k, p in e["premises"].items()}
        stress = premv.get("price_stress")
        addon = premv.get("basis_addon") \
            if isinstance(premv.get("basis_addon"), dict) else {}
        p_mm = premv.get("mm_of_im")
        p_mm_venue = premv.get("mm_of_im_venue") \
            if isinstance(premv.get("mm_of_im_venue"), dict) else {}
        # ---- workings.legs (v1.0 reset wave 1, 2026-08-31): the
        # per-leg terms are IN the record — each leg's g is exactly the
        # rule, its draw the stress + add-on, Deribit's imf the
        # ladder's; every venue row is then the EXACT fold of its legs
        # (the bracket died with the per-leg disclosure), and the legs
        # partition exactly the positions' legs.
        k_prem = premv.get("margin_clock_k")
        wl = e["workings"].get("legs")
        check(isinstance(wl, list) and (len(wl) > 0 or not legs),
              f"{tag}: workings.legs missing — the per-leg terms are "
              f"part of the record (v1.0)")
        legs_ok: list = []
        for j9, x in enumerate(wl if isinstance(wl, list) else []):
            need = ("notional_usd", "imf", "mm_of_im", "draw_f",
                    "clock_h", "g")
            if not (isinstance(x, dict) and isinstance(x.get("venue"), str)
                    and x.get("asset") in ASSETS
                    and all(_num(x.get(f9)) for f9 in need)
                    and x.get("binding") in ("im", "clock")):
                check(False, f"{tag}: workings.legs[{j9}] outside its "
                             f"shape")
                continue
            imf9, mmr9, df9, ck9, g9l = (
                _fnum(x["imf"]), _fnum(x["mm_of_im"]), _fnum(x["draw_f"]),
                _fnum(x["clock_h"]), _fnum(x["g"]))
            check(0.0 < imf9 <= 1.0 and 0.0 <= mmr9 <= 1.0
                  and df9 >= 0.0 and ck9 > 0.0,
                  f"{tag}: workings.legs[{j9}] terms outside their "
                  f"domain")
            if _num(k_prem):
                clk9 = imf9 * mmr9 + df9 * _fnum(k_prem) * ck9 / 24.0
                check(abs(g9l - max(imf9, clk9)) <= 1e-6,
                      f"{tag}: workings.legs[{j9}] g {g9l} is not "
                      f"max(imf, imf x mm_of_im + draw_f x k x "
                      f"clock/24)")
                check(x["binding"] == ("clock" if clk9 >= imf9 - 1e-12
                                       else "im"),
                      f"{tag}: workings.legs[{j9}] binding is not the "
                      f"rule's")
            if _num(stress):
                addon9 = _fnum(addon[x["asset"]]) \
                    if _num(addon.get(x["asset"])) else 0.0
                check(abs(df9 - (_fnum(stress) + addon9)) <= 1e-8,
                      f"{tag}: workings.legs[{j9}] draw_f is not price "
                      f"stress + the {x['asset']} basis add-on")
            lad9 = premv.get("deribit_ladder")
            if x["venue"] == "Deribit" and isinstance(lad9, dict):
                try:
                    nm9 = _fnum(lad9["nmax_usd"][x["asset"]])
                    c1, c2, c3, c4 = (
                        _fnum(lad9["C1"]), _fnum(lad9["C2"]),
                        _fnum(lad9["C3"]), _fnum(lad9["C4"]))
                    e9x = max(0.0, (_fnum(x["notional_usd"]) / nm9 - c3)
                              / (1.0 - c3)) ** c4
                    check(abs(imf9 - 1.0 / (c1 * (c1 / c2) ** (-e9x)))
                          <= 1e-6,
                          f"{tag}: workings.legs[{j9}] Deribit imf is "
                          f"not the ladder's")
                except (KeyError, TypeError, ZeroDivisionError,
                        OverflowError):
                    check(False, f"{tag}: deribit ladder premise "
                                 f"unusable for legs[{j9}]")
            legs_ok.append(x)
        fold9: dict = {}
        for x in legs_ok:
            f9 = fold9.setdefault(str(x["venue"]),
                                  {"n": 0.0, "im": 0.0, "mm": 0.0,
                                   "dr": 0.0, "g": 0.0})
            n9l = _fnum(x["notional_usd"])
            f9["n"] += n9l
            f9["im"] += n9l * _fnum(x["imf"])
            f9["mm"] += n9l * _fnum(x["imf"]) * _fnum(x["mm_of_im"])
            f9["dr"] += n9l * _fnum(x["draw_f"])
            f9["g"] += n9l * _fnum(x["g"])
        if isinstance(sl, list) and legs:
            for x in sl:
                if not isinstance(x, dict):
                    continue
                v9 = str(x.get("venue"))
                need = ("notional_usd", "im_usd", "mm_usd", "draw_usd",
                        "clock_h", "k", "sleeve_usd", "im_frac")
                if not all(_num(x.get(f9x)) for f9x in need):
                    check(False, f"{tag}: workings {v9} misses a numeric "
                                 f"field of {need}")
                    continue
                n9, im9, mm9, dr9, g9 = (
                    _fnum(x["notional_usd"]), _fnum(x["im_usd"]),
                    _fnum(x["mm_usd"]), _fnum(x["draw_usd"]),
                    _fnum(x["sleeve_usd"]))
                tol9 = 0.02 + 1e-6 * abs(n9)
                f9 = fold9.get(v9)
                check(f9 is not None,
                      f"{tag}: workings {v9} venue row has no legs")
                if f9 is not None:
                    for fld9, got9 in (("n", n9), ("im", im9),
                                       ("mm", mm9), ("dr", dr9),
                                       ("g", g9)):
                        check(abs(f9[fld9] - got9) <= tol9,
                              f"{tag}: workings {v9} {fld9} is not the "
                              f"EXACT fold of its legs ({got9} vs "
                              f"{f9[fld9]})")
                check(x.get("binding")
                      == ("clock" if g9 > im9 + 1.0 else "im"),
                      f"{tag}: workings {v9} binding is not the fold's "
                      f"own rule (clock iff sleeve > IM + $1)")
                ttb9 = x.get("ttb_h")
                if dr9 > 0:
                    check(_num(ttb9) and abs(_fnum(ttb9)
                          - 24.0 * (g9 - mm9) / dr9) <= 0.15,
                          f"{tag}: workings {v9} time-to-breach is not "
                          f"24 x (sleeve - MM) / draw")
                else:
                    check(ttb9 is None,
                          f"{tag}: workings {v9} states a time-to-breach "
                          f"with no draw")
                check(abs(_fnum(x["im_frac"]) * n9 - im9) <= tol9,
                      f"{tag}: workings {v9} im_frac is not IM / "
                      f"notional")
                if _num(p_mm):
                    ratio9 = _fnum(p_mm_venue[v9]) \
                        if _num(p_mm_venue.get(v9)) else _fnum(p_mm)
                    check(abs(mm9 - im9 * ratio9) <= tol9,
                          f"{tag}: workings {v9} MM is not IM x the "
                          f"stated mm_of_im premise")
        if legs:
            # a zero-notional position leg (a share against a zero
            # hedge) carries no margin terms and rightly has no
            # workings leg — both sides ignore dust under half a cent
            posN9: dict = {}
            for lg in legs:
                if isinstance(lg, dict) and _num(lg.get("notional_usd")) \
                        and abs(_fnum(lg["notional_usd"])) > 0.005:
                    k9p = (str(lg.get("venue")), str(lg.get("asset")))
                    posN9[k9p] = posN9.get(k9p, 0.0) \
                        + _fnum(lg["notional_usd"])
            wlN9: dict = {}
            for x in legs_ok:
                if abs(_fnum(x["notional_usd"])) > 0.005:
                    k9p = (str(x["venue"]), str(x["asset"]))
                    wlN9[k9p] = wlN9.get(k9p, 0.0) \
                        + _fnum(x["notional_usd"])
            check(set(posN9) == set(wlN9)
                  and all(abs(posN9[k9p] - wlN9[k9p])
                          <= 0.02 + 1e-6 * abs(posN9[k9p])
                          for k9p in posN9),
                  f"{tag}: workings.legs do not partition the "
                  f"positions' legs exactly")
        # settlements: every row's USD is its own notional x rate
        # (nothing through a halt), the domains closed, the funding and
        # staking sums the rows'
        if isinstance(st, list):
            for j9, x in enumerate(st):
                if not isinstance(x, dict):
                    continue
                ok9 = (isinstance(x, dict)
                       and set(x) == {"settled_at", "venue", "asset",
                                      "rate", "interval_h",
                                      "notional_usd", "usd", "halted"}
                       and isinstance(x.get("settled_at"), str)
                       and _ISO_ANY.fullmatch(x["settled_at"]) is not None
                       and _num(x.get("rate")) and _num(x.get("interval_h"))
                       and _num(x.get("notional_usd")) and _num(x.get("usd"))
                       and isinstance(x.get("halted"), bool)
                       and isinstance(x.get("venue"), str)
                       and isinstance(x.get("asset"), str))
                if not ok9:
                    check(False,
                          f"{tag}: settlements.rows[{j9}] outside its shape")
                    continue
                # F-134: a settlement belongs to ITS fix's window
                check(wfN9 <= _tzn(x["settled_at"]) <= wtN9,
                      f"{tag}: settlements.rows[{j9}] at "
                      f"{x['settled_at']} outside the fix's window")
                r9, n9, u9 = (_fnum(x["rate"]), _fnum(x["notional_usd"]),
                              _fnum(x["usd"]))
                check(abs(r9) < 1.0 and 0.0 < _fnum(x["interval_h"]) <= 24.0
                      and n9 >= 0.0,
                      f"{tag}: settlements.rows[{j9}] rate/interval/"
                      f"notional outside their domain")
                want_u = 0.0 if x["halted"] else n9 * r9
                check(abs(u9 - want_u) <= 0.02 + 1e-6 * abs(n9),
                      f"{tag}: settlements.rows[{j9}] usd {u9} is not "
                      f"notional x rate ({want_u})")
            fnd9 = sum(_fnum(x["usd"]) for x in st if isinstance(x, dict)
                       and _num(x.get("usd")) and x.get("venue") != "pool")
            stk9 = sum(_fnum(x["usd"]) for x in st if isinstance(x, dict)
                       and _num(x.get("usd")) and x.get("venue") == "pool")
            check(_num(e["settlements"].get("funding_usd"))
                  and abs(_fnum(e["settlements"]["funding_usd"]) - fnd9)
                  < 0.015,
                  f"{tag}: settlements.funding_usd is not its rows' sum")
            check(_num(e["settlements"].get("staking_usd"))
                  and abs(_fnum(e["settlements"]["staking_usd"]) - stk9)
                  < 0.015,
                  f"{tag}: settlements.staking_usd is not its rows' sum")
        # spot lots: a long-only book holds positive coin lots at
        # positive entries — a re-signed negative quantity is refused
        lots9 = pos.get("spot_lots") \
            if isinstance(pos.get("spot_lots"), dict) else None
        check(lots9 is not None, f"{tag}: positions.spot_lots is not an "
                                 f"object")
        for a9, lot9 in (lots9 or {}).items():
            check(isinstance(lot9, dict) and set(lot9) <= {"qty", "entry"}
                  and _num(lot9.get("qty")) and _fnum(lot9["qty"]) > 0.0
                  and (lot9.get("entry") is None
                       or (_num(lot9.get("entry"))
                           and _fnum(lot9["entry"]) > 0.0)),
                  f"{tag}: spot lot {a9} outside its domain (positive "
                  f"qty, positive-or-null entry)")
        # rules and provenance: digest shapes, count domains, the
        # window an ordered ISO pair, marks keyed by leg tokens
        check(isinstance(e["rules"].get("ruleset_sha256"), str)
              and _HEX64.fullmatch(e["rules"]["ruleset_sha256"]) is not None,
              f"{tag}: rules.ruleset_sha256 is not a sha256 digest")
        prov9 = e["provenance"]
        check(type(prov9.get("funding_prints")) is int
              and prov9["funding_prints"] >= 0,
              f"{tag}: provenance.funding_prints is not a non-negative "
              f"count")
        check(isinstance(prov9.get("funding_sha256"), str)
              and _HEX64.fullmatch(prov9["funding_sha256"]) is not None,
              f"{tag}: provenance.funding_sha256 is not a sha256 digest")
        wf9, wt9 = prov9.get("window_from"), prov9.get("window_to")
        check(isinstance(wf9, str) and isinstance(wt9, str)
              and _ISO_ANY.fullmatch(wf9) is not None
              and _ISO_ANY.fullmatch(wt9) is not None and wf9 < wt9,
              f"{tag}: provenance window is not an ordered ISO pair")
        marks9 = prov9.get("marks_at_strike")
        check(isinstance(marks9, dict)
              and all(isinstance(k9, str) and _LEG.fullmatch(k9) is not None
                      and (v9 is None or (_num(v9) and _fnum(v9) > 0))
                      for k9, v9 in marks9.items()),
              f"{tag}: provenance.marks_at_strike outside its shape")
        # F-134: the marks cover EXACTLY the record's own leg rows — an
        # emptied or padded map is refused, present-or-null per leg
        # (the leg set as WRITTEN, dust rows included: the published
        # share rounds to 6 dp, so a dust leg can print share 0.0)
        legcov9 = {f"{lg.get('venue')}/{lg.get('asset')}" for lg in legs
                   if isinstance(lg, dict)}
        if isinstance(marks9, dict):
            check(set(marks9) == legcov9,
                  f"{tag}: marks_at_strike does not cover exactly the "
                  f"held legs")
        # execution: a closed event vocabulary, each stamped
        ev9 = e["execution"].get("events")
        check(isinstance(ev9, list), f"{tag}: execution.events is not a "
                                     f"list")
        for j9, x in enumerate(ev9 if isinstance(ev9, list) else []):
            check(isinstance(x, dict) and isinstance(x.get("t"), str)
                  and _ISO_ANY.fullmatch(x["t"]) is not None
                  and x.get("event") in EXECUTION_EVENTS,
                  f"{tag}: execution.events[{j9}] outside the closed "
                  f"event vocabulary")
            if isinstance(x, dict) and isinstance(x.get("t"), str):
                check(wfN9 <= _tzn(x["t"]) <= wtN9,
                      f"{tag}: execution.events[{j9}] at {x.get('t')} "
                      f"outside the fix's window")
            # F-142: the rebalance event's closed magnitude shape
            if isinstance(x, dict) and x.get("event") == "rebalance":
                w9r = x.get("weights")
                check(set(x) == {"t", "event", "cost_usd",
                                 "turnover_usd", "weights"}
                      and _num(x.get("cost_usd"))
                      and _num(x.get("turnover_usd"))
                      and _fnum(x.get("turnover_usd", 0)) > 0
                      and isinstance(w9r, dict) and len(w9r) > 0
                      and all(isinstance(k9, str)
                              and _LEG.fullmatch(k9) is not None
                              and _num(v9) and 0 <= _fnum(v9) <= 1
                              for k9, v9 in w9r.items()),
                      f"{tag}: execution.events[{j9}] rebalance "
                      f"outside its magnitude-bearing shape")
        oas9 = e["execution"].get("open_at_strike")
        check(isinstance(oas9, list)
              and all(isinstance(x, dict) for x in oas9),
              f"{tag}: execution.open_at_strike is not a list of objects")
        # execution.admissions (v1.0 wave 1; F-133/F-134, Sol
        # 2026-08-31): exact keys, closed vocabularies, every time
        # inside the window, admitted+deferred a duplicate-free subset
        # of proposed, an ATOMIC origin never partially admitted, the
        # outcome a FINAL truth (recorded after the economic gate), and
        # executed walk admissions matched to walk events by time.
        adm9 = e["execution"].get("admissions")
        check(isinstance(adm9, list),
              f"{tag}: execution.admissions missing (v1.0)")
        _origins9 = {"compliance-walk", "cross-asset-walk",
                     "within-asset-walk", "reserve-resync",
                     "monthly-rebalance"}
        _atomic9 = {"reserve-resync", "monthly-rebalance"}
        _gated9 = {"cross-asset-walk", "within-asset-walk"}
        _reasons9 = {"venue-halted", "no-bid-curve", "no-ask-curve"}

        # legs carry IDENTITY and side only — an unexecuted magnitude
        # is solver output and machine-fragile; the executed magnitudes
        # are the events', settlements' and shares' (2026-08-31)
        def _mv9(m9, extra=frozenset()):
            return (isinstance(m9, dict)
                    and set(m9) == (LEG_ID_KEYS | extra)
                    and isinstance(m9.get("venue"), str)
                    and m9.get("asset") in ASSETS
                    and m9.get("side") in ("bid", "ask"))

        def _ids9(ms9):
            return sorted((m9["venue"], m9["asset"], m9["side"])
                          for m9 in ms9)
        class _Cnt(dict):
            def __missing__(self, k9c):
                return 0
        exec_walk_c9, exec_month_c9 = _Cnt(), _Cnt()
        for j9, x in enumerate(adm9 if isinstance(adm9, list) else []):
            ok9 = (isinstance(x, dict) and set(x) == ADMISSION_KEYS
                   and isinstance(x.get("t"), str)
                   and _ISO_ANY.fullmatch(x["t"]) is not None
                   and x.get("origin") in _origins9
                   and x.get("outcome") in ADMISSION_OUTCOMES
                   and isinstance(x.get("mandated"), bool)
                   and isinstance(x.get("proposed"), list)
                   and len(x["proposed"]) > 0
                   and all(_mv9(m9) for m9 in x["proposed"])
                   and isinstance(x.get("admitted"), list)
                   and all(_mv9(m9) for m9 in x["admitted"])
                   and isinstance(x.get("deferred"), list)
                   and all(_mv9(m9, frozenset({"reason"}))
                           and m9.get("reason") in _reasons9
                           for m9 in x["deferred"]))
            check(ok9, f"{tag}: execution.admissions[{j9}] outside its "
                       f"closed shape")
            if not ok9:
                continue
            check(wfN9 <= _tzn(x["t"]) <= wtN9,
                  f"{tag}: admissions[{j9}] at {x['t']} outside the "
                  f"fix's window")
            prop9 = _ids9(x["proposed"])
            check(len(set(prop9)) == len(prop9),
                  f"{tag}: admissions[{j9}] duplicate proposed legs")
            admi9 = _ids9(x["admitted"])
            defe9 = _ids9([{k9x: v9x for k9x, v9x in m9.items()
                            if k9x != "reason"} for m9 in x["deferred"]])
            merged9 = sorted(admi9 + defe9)
            check(len(set(merged9)) == len(merged9)
                  and all(i9 in prop9 for i9 in merged9),
                  f"{tag}: admissions[{j9}] admitted/deferred are not a "
                  f"duplicate-free subset of proposed")
            if x["origin"] in _atomic9:
                check(x["outcome"] != "cost-rejected",
                      f"{tag}: admissions[{j9}] atomic origin claims a "
                      f"cost rejection")
                check(not (x["deferred"] and x["admitted"]),
                      f"{tag}: admissions[{j9}] atomic origin partially "
                      f"admitted")
                if not x["deferred"]:
                    check(admi9 == prop9,
                          f"{tag}: admissions[{j9}] atomic origin "
                          f"admitted differs from proposed with no "
                          f"deferral")
            if x["outcome"] == "cost-rejected":
                check(x["origin"] in _gated9 and not x["mandated"],
                      f"{tag}: admissions[{j9}] cost-rejected outside "
                      f"the gated voluntary origins")
                check(not x["admitted"],
                      f"{tag}: admissions[{j9}] cost-rejected yet "
                      f"claims admitted legs — admitted means executed "
                      f"fills")
            if x["outcome"] == "executed":
                check(bool(x["admitted"]),
                      f"{tag}: admissions[{j9}] executed with no "
                      f"admitted legs")
                if x["origin"] == "monthly-rebalance":
                    exec_month_c9[_tzn(x["t"])] += 1
                else:
                    # compliance/cross/within AND reserve resyncs all
                    # apply through walks
                    exec_walk_c9[_tzn(x["t"])] += 1
            if x["outcome"] == "nothing-admissible":
                check(not x["admitted"],
                      f"{tag}: admissions[{j9}] nothing-admissible yet "
                      f"carries admitted legs")
        # F-133 + F-142 (Sol 2026-09-01): an EXECUTED admission and its
        # magnitude-bearing event are the same fact seen twice — bound
        # as MULTISETS, per timestamp, so one event can never
        # authenticate two claimed executions. Walk-applying origins
        # (compliance/cross/within AND reserve resyncs) bind to `walk`
        # events; executed monthly rebalances bind to `rebalance`
        # events (the market book's fill record).
        walkev_c9, rebev_c9 = _Cnt(), _Cnt()
        for x in (ev9 if isinstance(ev9, list) else []):
            if isinstance(x, dict) and x.get("event") == "walk":
                walkev_c9[_tzn(x.get("t"))] += 1
            if isinstance(x, dict) and x.get("event") == "rebalance":
                rebev_c9[_tzn(x.get("t"))] += 1
        check(dict(exec_walk_c9) == dict(walkev_c9),
              f"{tag}: executed walk-applying admissions and walk "
              f"events disagree as multisets "
              f"({dict(exec_walk_c9)} vs {dict(walkev_c9)})")
        check(dict(exec_month_c9) == dict(rebev_c9),
              f"{tag}: executed monthly rebalances and rebalance "
              f"events disagree as multisets "
              f"({dict(exec_month_c9)} vs {dict(rebev_c9)})")
        # premises: every one declares its kind AND its citation (v1.0
        # wave 1: source / observed_on join the block); a named
        # premise's value sits in its closed domain.
        # F-147 (Sol 2026-09-01): a MISSING premise fails — the block
        # must be non-empty, the identity-driving premises must be
        # PRESENT (their dependent checks may never be skipped by
        # omission), and a v1.0 record carries EXACTLY the registry's
        # key set.
        prem9 = e["premises"] if isinstance(e["premises"], dict) else {}
        check(len(prem9) > 0,
              f"{tag}: premises block is empty — the record's premises "
              f"are not optional")
        for req9 in ("price_stress", "mm_of_im"):
            check(req9 in prem9,
                  f"{tag}: required premise `{req9}` missing — its "
                  f"dependent identities may never be skipped")
        if e["rules"].get("methodology_version") == "v1.0":
            check(set(prem9) == PREMISES_V10,
                  f"{tag}: v1.0 premises key set differs from the "
                  f"registry's ({sorted(set(prem9) ^ PREMISES_V10)})")
        for k, p in e["premises"].items():
            check(isinstance(p, dict) and p.get("kind") in PREMISE_KINDS
                  and "value" in p,
                  f"{tag}: premise `{k}` does not declare a value and a "
                  f"kind in {sorted(PREMISE_KINDS)}")
            check(isinstance(p, dict) and "source" in p
                  and isinstance(p.get("source"), (str, dict))
                  and (not isinstance(p.get("source"), str)
                       or p["source"].strip() != ""),
                  f"{tag}: premise `{k}` carries no citation source "
                  f"(v1.0 wave 1)")
            # F-134: the citation metadata's CLASSES are closed — a
            # re-signed date that is not a date, a note that is not
            # text, an unknown member: all refused
            if isinstance(p, dict):
                check(set(p) <= {"value", "unit", "kind", "source",
                                 "observed_on", "note"},
                      f"{tag}: premise `{k}` carries unknown members")
                ob9 = p.get("observed_on")
                ob_ok9 = (ob9 is None or _is_date(ob9)
                          or (isinstance(ob9, dict)
                              and all(v9 is None or _is_date(v9)
                                      for v9 in ob9.values())))
                nt9 = p.get("note")
                nt_ok9 = (nt9 is None or isinstance(nt9, str)
                          or (isinstance(nt9, dict)
                              and all(v9 is None or isinstance(v9, str)
                                      for v9 in nt9.values())))
                un9 = p.get("unit")
                check(ob_ok9 and nt_ok9
                      and (un9 is None or isinstance(un9, str)),
                      f"{tag}: premise `{k}` citation metadata outside "
                      f"its classes")
                # F-147: a map premise's citation maps cover EXACTLY
                # the value's sub-keys — a cited sub-key cannot
                # disappear (or appear) without refusal
                if isinstance(p.get("value"), dict):
                    for f9 in ("source", "observed_on", "note"):
                        v9f = p.get(f9)
                        if isinstance(v9f, dict):
                            check(set(v9f) == set(p["value"]),
                                  f"{tag}: premise `{k}` {f9} sub-keys "
                                  f"differ from the value's")
            dom9 = PREMISE_VALUE_DOMAINS.get(k)
            if dom9 is not None and isinstance(p, dict):
                check(dom9(p.get("value")),
                      f"{tag}: premise `{k}` value outside its domain")
        check(e["rules"].get("methodology_version") == e["methodology_version"]
              == r["methodology_version"],
              f"{tag}: methodology stamp differs between the envelope, its "
              f"rules and the portfolio row")

    # ---- 4. ARITHMETIC IDENTITIES (never skipped) -----------------------
    def _amount(d: dict, key: str) -> float:
        v = d["evidence"].get(key)
        return _fnum(v) if _num(v) else 0.0

    imp_events = sorted(
        (d["decided_at"],
         _amount(d, "loss_usd") if d["action"] == "impairment"
         else -_amount(d, "recovered_usd"))
        for d in decisions if d["action"] in ("impairment", "recovery"))
    prev_nav = prev_carry = prev_cost = None
    for i, r in enumerate(fixes):
        tag = f"portfolio {r['fix_date']}"
        strike = r["fix_date"] + "T12:00:00Z"
        net_impair = sum(v for t, v in imp_events if t <= strike)
        nav, carry, cost = (_fnum(r["nav_usd"]), _fnum(r["carry_usd_cum"]),
                            _fnum(r["cost_usd_cum"]))
        check(abs(nav - (CAPITAL0 + carry - cost - net_impair)) < 0.015,
              f"{tag}: NAV != capital + carry - costs - impairment")
        # h5 capital identities (F-120, Sol 2026-08-30): the long leg
        # and the stable reserve partition the capital to the cent, the
        # sleeves and both capitals are non-negative, the market book's
        # long leg is a positive part of the same capital
        cap, res, mgn, ncap = (_fnum(r["capital_usd"]),
                               _fnum(r["stable_reserve_usd"]),
                               _fnum(r["stable_margin_usd"]),
                               _fnum(r["naive_capital_usd"]))
        check(abs(cap + res - CAPITAL0) < 0.015,
              f"{tag}: capital + stable reserve != {CAPITAL0:.0f}")
        check(cap > 0 and res >= 0 and mgn >= 0,
              f"{tag}: capital / reserve / stable margin outside their domain")
        check(0 < ncap <= CAPITAL0,
              f"{tag}: naive capital outside (0, {CAPITAL0:.0f}]")
        full, basis = r["full_nav_usd"], r["basis_usd"]
        check((full is None) == (basis is None),
              f"{tag}: full-marks NAV and basis must be published together")
        if full is not None and basis is not None:
            check(abs(_fnum(basis) - (_fnum(full) - nav)) < 0.015,
                  f"{tag}: basis != full-marks NAV - carry NAV")
        if i == 0:
            check(r["ret_1d"] is None,
                  f"{tag}: inception carries a daily return")
        else:
            check(r["ret_1d"] is not None,
                  f"{tag}: daily return missing after inception")
            if r["ret_1d"] is not None and prev_nav:
                check(abs(_fnum(r["ret_1d"]) - (nav / prev_nav - 1.0))
                      < 1e-9, f"{tag}: return chain broken")
            check(carry >= prev_carry - 1e-9,
                  f"{tag}: cumulative carry decreased")
            check(cost >= prev_cost - 1e-9,
                  f"{tag}: cumulative costs decreased")
        prev_nav, prev_carry, prev_cost = nav, carry, cost
    for r in refs:
        tag = f"reference {r['index_name']} {r['fix_date']}"
        naive, prem = r["naive_bp"], r["prudence_premium_bp"]
        # the market average column arrived after the first fixes: a
        # premium may stand alone, but a published market average
        # always carries its premium and the identity (B-04)
        check(naive is None or prem is not None,
              f"{tag}: market average published without its premium")
        if naive is not None and prem is not None:
            check(abs(_fnum(prem) - (_fnum(naive) - _fnum(r["value_bp"])))
                  < 1e-6, f"{tag}: premium != market average - index")

    # ---- 5. VOCABULARY & DISCLOSURE: per row, in _row_shape ------------

    # ---- 6. RESTATEMENT LEDGER ------------------------------------------
    current = {("index_series", None, r["fix_date"]): r["row_sha256"]
               for r in fixes}
    current.update({("index_fixes", r["index_name"], r["fix_date"]):
                    r["row_sha256"] for r in refs})
    current.update({("fix_envelope", None, e["fix_date"]): e["row_sha256"]
                    for e in envelopes})
    seqs = [e["seq"] for e in restatements]
    check(len(seqs) == len(set(seqs)),
          "restatements: sequence numbers are not unique")
    ordered = sorted(restatements, key=lambda x: x["seq"])
    check(all(a["restated_at"] <= b["restated_at"]
              for a, b in zip(ordered, ordered[1:])),
          "restatements: timestamps are not non-decreasing in sequence")
    last: dict = {}
    by_key: dict = {}
    for e in ordered:
        tag = f"restatement seq {e['seq']}"
        if e["table_name"] in ("index_series", "index_fixes", "fix_envelope"):
            key = (e["table_name"], e["index_name"], e["fix_date"])
            last[key] = e
            by_key.setdefault(key, []).append(e)
    for key, es in by_key.items():
        for a, b in zip(es, es[1:]):
            if (a["op"] == "delete" or b["restated_at"] < LEDGER_CHAIN_FROM
                    or a["restated_at"] < LEDGER_FREEZE):
                continue
            check(a["new_row_sha256"] == b["old_row_sha256"],
                  f"restatements: {key[0]} {key[2]} entries {a['seq']} -> "
                  f"{b['seq']} do not chain — the row moved between them "
                  f"without a ledger entry")
    for key, e in last.items():
        tbl, ix, fd = key
        label = f"{tbl} {(ix + ' ') if ix else ''}{fd}"
        if e["restated_at"] < LEDGER_FREEZE:
            # a pre-freeze MEMORIAL row: the development ledger was
            # cleared at the freeze (2026-09-01) and its sole survivor
            # documents the 2026-08-21 in-window correction — the
            # fingerprints it names predate later development
            # restatements whose chain went with the cleared rows.
            # The binding rules apply to every row from the freeze on.
            continue
        if e["op"] == "update":
            check(key in current,
                  f"restatements: {label} was restated but is not in the "
                  f"published record")
            check(current.get(key) == e["new_row_sha256"],
                  f"restatements: the ledger's last word on {label} "
                  f"({e['new_row_sha256']}) is not the published "
                  f"fingerprint ({current.get(key)}) — the row moved "
                  f"without a ledger entry")
        else:
            check(key not in current,
                  f"restatements: {label} was deleted per the ledger but "
                  f"is still published")
    published_decisions = {d["row_sha256"] for d in decisions}
    retired: set = set()
    produced: set = set()
    for e in ordered:
        if e["table_name"] != "book_decisions":
            continue
        retired.add(e["old_row_sha256"])
        produced.discard(e["old_row_sha256"])
        if e["op"] == "update":
            produced.add(e["new_row_sha256"])
            retired.discard(e["new_row_sha256"])
    for sha in sorted(retired & published_decisions):
        check(False, f"restatements: decision {sha} was retired by the "
                     f"ledger but is still published")
    for sha in sorted(produced - published_decisions):
        check(False, f"restatements: decision entry results in {sha} "
                     f"which is not a published decision and no later "
                     f"entry supersedes it")
    if not complete:
        fails.append("record: one or more rows failed the shape check — "
                     "every later check ran on the remaining rows only")


_LABEL = {"portfolio_fixes.json": "portfolio", "reference_fixes.json":
          "reference", "decisions.json": "decision",
          "episodes.json": "episode", "restatements.json": "restatement",
          "envelopes.json": "envelope"}


def _row_shape(name: str, i: int, r: dict) -> list:
    """EVERY defect of one row, in the record's own words: key set,
    field classes, and the per-row vocabulary and disclosure rules
    (evidence schema, venue rule, stamp, reason, stress, span). A row
    with any defect is excluded from the cross-row layers."""
    out: list = []
    tag = f"{_LABEL[name]}[{i}]"
    missing = REQUIRED_KEYS[name] - set(r)
    extra = set(r) - REQUIRED_KEYS[name]
    if missing or extra:
        out.append(f"{name}[{i}]: row key set differs from the record's "
                   f"(missing {sorted(missing)}, extra {sorted(extra)}) "
                   f"(F-093)")
    for k, f in SCHEMA[name].items():
        if k not in r:
            continue
        v = r[k]
        if f(v):
            continue
        if k == "methodology_version":
            out.append(f"{tag}: no methodology stamp")
        elif k == "reason":
            out.append(f"{tag}: a restatement without a reason")
        elif k == "peak_stress":
            out.append(f"{tag}: peak_stress is not the exported text class "
                       f"— a finite float8 rendering or null (F-087/F-094)")
        elif k == "evidence" and name == "decisions.json":
            out.append(f"{tag}: evidence is not a JSON object (F-081)")
        elif k == "evidence":
            out.append(f"{tag}: evidence is not a JSON text (F-078/F-081)")
        elif k == "venue":
            out.append(f"{tag}: venue outside the public token class "
                       f"(F-085)")
        elif k in ("old_row_sha256", "new_row_sha256"):
            out.append(f"{tag}: malformed {k}")
        elif k == "seq":
            out.append(f"{tag}: missing or invalid sequence number")
        elif k == "table_name":
            out.append(f"{tag}: unknown table {v!r}")
        elif k == "op":
            out.append(f"{tag}: unknown op {v!r}")
        elif k == "action":
            out.append(f"{tag}: unknown action {v!r}")
        elif k == "plane":
            out.append(f"{tag}: unknown plane")
        else:
            out.append(f"{tag}: field `{k}` outside the record's value "
                       f"class ({v!r})")
    # per-row rules that need more than one field
    if name == "decisions.json":
        action, venue = r.get("action"), r.get("venue")
        if action == "walk" and venue is not None:
            out.append(f"{tag}: a walk is book-level — venue must be "
                       f"absent (F-085)")
        elif action in ACTIONS and action != "walk" and (
                venue is None or (isinstance(venue, str)
                                  and venue.strip() == "")):
            out.append(f"{tag}: {action} without a venue")
        ev = r.get("evidence")
        schema = PUBLIC_EVIDENCE.get(action, {})
        for k, v in (ev if isinstance(ev, dict) else {}).items():
            if k not in schema:
                out.append(f"{tag}: evidence key `{k}` is outside the "
                           f"public schema for {action} (F-043)")
            elif not schema[k](v):
                out.append(f"{tag}: evidence `{k}` fails its value class "
                           f"(F-043)")
    elif name == "episodes.json":
        plane, kind = r.get("plane"), r.get("kind")
        if kind in ACTIONS:
            out.append(f"{tag}: an ACTION ({kind}) appears in the "
                       f"observation record")
        if plane == "book" and kind not in BOOK_KINDS:
            out.append(f"{tag}: kind {kind!r} is outside the book plane's "
                       f"vocabulary")
        if plane == "index" and kind not in INDEX_KINDS:
            out.append(f"{tag}: kind {kind!r} is outside the index plane's "
                       f"vocabulary")
        if r.get("peak_stress") is not None and plane != "market":
            out.append(f"{tag}: peak_stress on the {plane} plane (F-087)")
        o, c = r.get("opened_at"), r.get("closed_at")
        if isinstance(o, str) and isinstance(c, str) and c < o:
            out.append(f"{tag}: closed_at before opened_at (F-087)")
        ev = _exact_loads(r.get("evidence")) \
            if isinstance(r.get("evidence"), str) else None
        if not isinstance(ev, dict):
            out.append(f"{tag}: evidence is not a JSON object "
                       f"(F-078/F-081)")
        schema = EPISODE_EVIDENCE.get(plane, {})
        for k, v in (ev if isinstance(ev, dict) else {}).items():
            if k not in schema:
                out.append(f"{tag}: evidence key `{k}` is outside the "
                           f"public schema for the {plane} plane (F-078)")
            elif not schema[k](v):
                out.append(f"{tag}: evidence `{k}` fails its value class "
                           f"(F-078)")
    elif name == "restatements.json":
        op, new = r.get("op"), r.get("new_row_sha256")
        if op == "update" and new is None:
            out.append(f"{tag}: an update with no resulting fingerprint")
        if op == "delete" and new is not None:
            out.append(f"{tag}: a delete with a resulting fingerprint")
        if r.get("old_row_sha256") is None:
            out.append(f"{tag}: no fingerprint before the change")
        # the table's key shape (F-100): a reference fix is named by its
        # index; a portfolio fix or a decision never is
        tbl, ix = r.get("table_name"), r.get("index_name")
        if tbl == "index_fixes" and ix is None:
            out.append(f"{tag}: index_fixes entry without an index_name "
                       f"(key shape)")
        if tbl in ("index_series", "book_decisions", "fix_envelope") \
                and ix is not None:
            out.append(f"{tag}: {tbl} entry carries an index_name "
                       f"(key shape)")
    return out


def _explained_gaps(episodes: list, ix: str) -> dict:
    """{first missed day: missed_fixes} from the index episodes that
    explain a reference series gap (kind `infeasible`, plane index)."""
    out: dict = {}
    for e in episodes:
        if e["plane"] != "index" or e["subject"] != ix \
                or e["kind"] != "infeasible":
            continue
        ev = _exact_loads(e["evidence"])
        n = ev.get("missed_fixes") if isinstance(ev, dict) else None
        if _count(n):
            out[e["opened_at"][:10]] = n
    return out


def _consecutive(dates: list, label: str, fails: list,
                 explained=None) -> None:
    ds = [datetime.date.fromisoformat(d) for d in dates]
    for a, b in zip(ds, ds[1:]):
        gap = (b - a).days
        if gap == 1:
            continue
        first_missed = (a + datetime.timedelta(days=1)).isoformat()
        if gap > 1 and explained \
                and explained.get(first_missed) == gap - 1:
            continue        # the record itself explains the gap (A-3)
        fails.append(f"{label}: gap between {a} and {b} — the daily "
                     f"series is not contiguous and no index episode "
                     f"explains it")


def main() -> None:
    expected = sys.argv[1] if len(sys.argv) > 1 else None
    base = os.path.dirname(os.path.abspath(__file__))
    fails = run(base, expected)
    if fails:
        for m in fails:
            print(f"FAIL: {m}")
        print(f"\n{len(fails)} CHECK(S) FAILED")
        sys.exit(1)
    with open(os.path.join(base, "data", "manifest.json")) as f:
        man = json.load(f)
    anchor = ("anchored to the published record root" if expected
              else "self-declared completeness — anchor with the "
                   "record root from https://arguslabs.io/feed.xml")
    print(f"ALL CHECKS PASS — record root {man['record_root']} "
          f"as of {man['as_of']}; shape, fingerprints, manifest, "
          f"identities, vocabulary, disclosure and the restatement "
          f"ledger all hold ({anchor})")


if __name__ == "__main__":
    main()
