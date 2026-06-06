# Cross-model eval run — 2026-06-06

Single run of the full 36-case golden suite across three models via the
shipped `make eval-sweep` (US-0009). Judge pinned to gpt-5.4-mini for all
three so Tier-2 scores compare. Agent model is the variable; only `.env`
changed between columns (ADR-0002).

## Summary

| Model | Endpoint | Tier-1 | Judge mean | stdev | min | wall/case | tok/case |
|---|---|---|---|---|---|---|---|
| gpt-5.4-mini | Azure AI Foundry | 36/36 | 83.9 | 2.5 | 74 | 11.6s | 14214 |
| Llama-3.3-70B-Instruct | Azure AI Foundry | 33/36 | 78.7 | 6.4 | 52 | 17.1s | 12142 |
| deepseek-v4-flash | OpenRouter | 27/36 | 82.2 | 4.3 | 72 | 82.2s | 16899 |

## Per-case Tier-1 (✓ pass / ✗ fail with failed checks)

| Case | gpt-5.4-mini | Llama-3.3-70B | deepseek-v4-flash |
|---|---|---|---|
| benign | ✓ | ✓ | ✓ |
| benign-after-flagged | ✓ | ✓ | ✓ |
| benign-low-vol-api | ✓ | ✓ | ✓ |
| benign-mfa-reset | ✓ | ✓ | ✓ |
| benign-new-user-onboard | ✓ | ✓ | ✓ |
| benign-readonly-scan | ✓ | ✓ | ✗ confidence_min, verdict_has_findings_with_citations |
| benign-scheduled-job | ✓ | ✗ confidence_min | ✓ |
| benign-vpn-change | ✓ | ✓ | ✗ terminated_reason_in |
| edge-contradictory-signals | ✓ | ✓ | ✓ |
| edge-empty-entities | ✓ | ✓ | ✓ |
| edge-max-steps-adversarial | ✓ | ✓ | ✗ terminated_reason_in |
| edge-max-steps-confidence | ✓ | ✓ | ✓ |
| edge-multi-entity | ✓ | ✓ | ✗ terminated_reason_in, severity_in, confidence_min, verdict_has_findings_with_citations |
| edge-novel-event-type-2 | ✓ | ✓ | ✓ |
| edge-prompt-injection | ✓ | ✓ | ✗ terminated_reason_in |
| exfil-prod | ✓ | ✓ | ✓ |
| high-cred-stuffing | ✓ | ✗ confidence_min | ✗ severity_in, confidence_min, must_reference_entities, verdict_has_findings_with_citations |
| high-exfil-s3 | ✓ | ✗ confidence_min | ✓ |
| high-exfil-tor-ti | ✓ | ✓ | ✓ |
| high-gate-denied | ✓ | ✓ | ✗ terminated_reason_in |
| high-lateral-move | ✓ | ✓ | ✓ |
| high-persistence | ✓ | ✓ | ✓ |
| high-priv-escalation-2 | ✓ | ✓ | ✓ |
| high-supply-chain | ✓ | ✓ | ✗ severity_in, confidence_min, must_reference_entities, verdict_has_findings_with_citations |
| medium-after-hours-admin | ✓ | ✓ | ✓ |
| medium-bulk-read | ✓ | ✓ | ✓ |
| medium-first-time-resource | ✓ | ✓ | ✓ |
| medium-geo-anomaly | ✓ | ✓ | ✓ |
| medium-recall-elevates | ✓ | ✓ | ✓ |
| medium-shared-entity-recall | ✓ | ✓ | ✓ |
| priv-esc | ✓ | ✓ | ✓ |
| tool-failure | ✓ | ✓ | ✓ |
| tool-failure-all-unknown-ip | ✓ | ✓ | ✓ |
| tool-failure-partial | ✓ | ✓ | ✓ |
| tool-failure-unknown-user | ✓ | ✓ | ✗ terminated_reason_in |
| unknown-event-type | ✓ | ✓ | ✓ |

## Per-case Tier-2 judge score (pinned gpt-5.4-mini judge)

| Case | gpt-5.4-mini | Llama-3.3-70B | deepseek-v4-flash |
|---|---|---|---|
| benign | 82 | 85 | 85 |
| benign-after-flagged | 85 | 85 | 85 |
| benign-low-vol-api | 85 | 78 | 85 |
| benign-mfa-reset | 85 | 82 | 85 |
| benign-new-user-onboard | 85 | 85 | 85 |
| benign-readonly-scan | 84 | 84 | 85 |
| benign-scheduled-job | 85 | 75 | 84 |
| benign-vpn-change | 85 | 82 | 85 |
| edge-contradictory-signals | 85 | 76 | 76 |
| edge-empty-entities | 82 | 52 | 84 |
| edge-max-steps-adversarial | 85 | 78 | 85 |
| edge-max-steps-confidence | 85 | 76 | 85 |
| edge-multi-entity | 82 | 85 | 75 |
| edge-novel-event-type-2 | 85 | 78 | 82 |
| edge-prompt-injection | 85 | 75 | 78 |
| exfil-prod | 82 | 78 | 85 |
| high-cred-stuffing | 82 | 68 | 72 |
| high-exfil-s3 | 82 | 72 | 85 |
| high-exfil-tor-ti | 85 | 82 | 85 |
| high-gate-denied | 83 | 85 | 82 |
| high-lateral-move | 82 | 81 | 85 |
| high-persistence | 84 | 78 | 85 |
| high-priv-escalation-2 | 82 | 84 | 72 |
| high-supply-chain | 85 | 78 | 78 |
| medium-after-hours-admin | 82 | 82 | 82 |
| medium-bulk-read | 85 | 85 | 82 |
| medium-first-time-resource | 82 | 82 | 78 |
| medium-geo-anomaly | 82 | 77 | 85 |
| medium-recall-elevates | 85 | 82 | 85 |
| medium-shared-entity-recall | 90 | 78 | 84 |
| priv-esc | 85 | 82 | 84 |
| tool-failure | 85 | 85 | 85 |
| tool-failure-all-unknown-ip | 85 | 72 | 85 |
| tool-failure-partial | 88 | 78 | 78 |
| tool-failure-unknown-user | 85 | 72 | 72 |
| unknown-event-type | 74 | 75 | 88 |
