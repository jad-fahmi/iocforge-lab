# Contributing to IOCForge

## Development setup

Use Python 3.10 or later, then install the development and API dependencies:

```shell
python -m pip install -e ".[dev,api]"
pre-commit install
```

Before opening a pull request, run the same checks used in CI. With GNU Make
installed, run:

```shell
make check
```

This runs Ruff, Python compilation, mypy, and pytest. Otherwise, run:

```shell
python -m ruff check .
python -m compileall -q ioc_enricher
python -m mypy
python -m pytest
```

## Connector contributions

Connectors must subclass `Connector`, declare a stable `name`, their supported
`IocType` values, and whether an API key is required. Return a `SourceResult`
for every outcome: data, no data, or a normalized error. Do not leak API keys
or full sensitive upstream responses into logs or reports. Add mocked tests for
successful, not-found, missing-credential, and error paths where applicable.

Keep pull requests focused. Include tests and documentation with behavioral
changes, and use a short imperative commit subject.
