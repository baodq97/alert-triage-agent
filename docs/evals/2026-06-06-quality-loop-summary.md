# Quality Loop Report — 2026-06-06

Five live audit → improve → eval rounds over the 35-case golden suite,
following the improvement wave (US-0006/0007/0008, PR #12).

| Round | Lens | Judge mean |
|---|---|---|
| 0 | baseline (post PR #12 re-record) | 73.8 (stdev 6.7) |
| 1 | Reasoner coverage gate | 75.4 |
| 2 | Verdict limitation ledger + confidence cap | 77.5 |
| 3 | Pivot playbook + non-corroboration findings | 76.9 |
| 4 | Aspect completeness | 76.4 |
| 5 | Judge scoring anchors + environment fairness | **84.1 (stdev 2.6, min 78)** |

Behavioral evidence independent of the judge: verify-hook coverage-gap
telemetry dropped **10 → 3 cases**. Tier-1 stayed 35/35 throughout; the
verify hook reports 0 false flags after recalibration (RFC-0003 §Phase-1
measurement). Shipped in PR #13.

Full per-case input→output detail: [2026-06-06-quality-loop-report.html](./2026-06-06-quality-loop-report.html)
(regenerate with `uv run python _workspace/build_report.py`).
