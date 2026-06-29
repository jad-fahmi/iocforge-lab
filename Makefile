.PHONY: install dev test api lint typecheck check

install:
	pip install -e .

dev:
	pip install -e ".[dev,api]"

test:
	pytest -q

api:
	uvicorn ioc_enricher.api.app:app --reload

lint:
	ruff check .
	python -m compileall -q ioc_enricher

typecheck:
	mypy

check: lint typecheck test
