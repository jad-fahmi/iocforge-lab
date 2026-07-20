.PHONY: install dev test api lint

install:
	pip install -e .

dev:
	pip install -e ".[dev,api]"

test:
	pytest -q

api:
	uvicorn ioc_enricher.api.app:app --reload

lint:
	python -m compileall ioc_enricher
