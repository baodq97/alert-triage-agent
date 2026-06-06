.PHONY: run watch test lint typecheck check eval eval-replay

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
