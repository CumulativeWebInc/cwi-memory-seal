# Memory Seal — CWI app #38

The integrity primitive for agent memory. Kills backlog problem **P6**: *"Agent memory corruption / contamination has no integrity primitive"* (backlog score 29 — the highest-scoring unbuilt problem).

Two primitives, both real, both client-side:

1. **Contamination scanner** — paste MEMORY.md / daily notes / memory JSON and get
   evidence-bound findings from 12 heuristic rules (`ms-rules/1.0`):
   injected directives (MS-01), secret-shaped values (MS-02), credential-category
   keys with values (MS-03), self-preservation/oversight-evasion language (MS-04),
   sensitive-attribute inference (MS-05), unmarked contradictions (MS-06),
   retroactive-edit markers (MS-07, healthy), unverified-as-fact (MS-08),
   vague attribution (MS-09), near-duplicate drift risk (MS-10), staleness (MS-11),
   low-confidence high-stakes claims (MS-12).
   Machine-readable audit envelopes: `cwi.memory-audit/1.0` (`audits.json`, `?audit=` deep links).

2. **Checkpoints** — seal a snapshot of memory entries (e.g. before context
   compaction) with a SHA-256 entries hash + Ed25519 signature. Verification
   catches any add/remove/edit/reorder since sealing. Hash-chained log:
   `cwi.memory-checkpoint/1.0` (`checkpoints.json`).

## Honest limits

- The scanner is **heuristic triage**, not a proof. A clean scan is not a proof of
  clean memory; adversarial text can evade rules. Findings are for a human, never
  automatic verdicts.
- A checkpoint proves **integrity since sealing, not truth**. Entries sealed while
  wrong stay wrong — the seal just freezes them.

## Dogfood (2026-09-16)

Scanned CWI's real `MEMORY.md` (87 lines), `USER.md` (8), and the alignment
synthesis (24): **0 critical · 9 warning · 4 info** — all benign heuristic
triage hits on public operational facts. Sealed a real Ed25519-signed genesis
checkpoint (`msc_KV944N303MJJDT9T`) over the memory files' SHA-256 hashes.
Signing key lives off-repo at `~/workspace/cwi-company/memory-seal/private-keys.json` (chmod 600).

## Build

- `memory.js` — zero-dependency UMD engine (scan + checkpoints), byte-identical on disk and served
- `index.html` / `styles.css` — mobile-first UI: Scan / Checkpoints / Audit log tabs
- `vendor/nacl.js` — tweetnacl (public domain) for browser Ed25519
- `schema/` — `cwi.memory-audit/1.0`, `cwi.memory-checkpoint/1.0`, `cwi.memory-checkpoint-log/1.0`
- `tests/test.js` — 41 tests, `node --test` — all green
- `scripts/seal-dogfood.js` — regenerates the dogfood scan + checkpoint

Nothing is uploaded anywhere; the browser build runs entirely client-side.
i18n hook via [cwi-i18n](https://cumulativewebinc.github.io/cwi-i18n/) (`data-app="memory-seal"`).

Cumulative Web Inc — cumulativeweb.com
