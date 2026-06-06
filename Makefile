.PHONY: run watch test lint typecheck check eval eval-replay eval-sweep

ALERT ?= alerts/ALT-2026-04-7821-data-exfiltration.json

run:
	uv run python run.py --alert $(ALERT)

watch:
	uv run python run.py --watch alerts/incoming/

test:
	uv run pytest

lint:
	uv run ruff check . && uv run ruff format --check .

typecheck:
	uv run ty check

check: lint typecheck test

eval:
	uv run --env-file .env python -m triage.evals.runner

eval-replay:
	uv run python -m triage.evals.runner --replay

# Multi-model sweep (US-0009): run the suite on any model from an isolated env
# file, judge pinned to the baseline for comparable Tier-2 scores. Examples:
#   make eval-sweep ENV=.env.deepseek            # judge pinned to .env
#   make eval-sweep ENV=.env.llama OUT=_workspace/evalrun-llama
# Rate-limited model (e.g. 20 RPM): add WORKERS=1 SECS=60 on the command line.
ENV ?= .env
JUDGE_ENV ?= .env
OUT ?= _workspace/evalrun-sweep
WORKERS ?= 4
SECS ?= 0
eval-sweep:
	uv run python -m triage.evals.sweep \
		--env-file $(ENV) --judge-env-file $(JUDGE_ENV) \
		--out $(OUT) --scratch-caches --workers $(WORKERS) --min-case-seconds $(SECS)
