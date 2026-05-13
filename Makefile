#!/usr/bin/env make

.PHONY: activate lint type-check install install-dev uninstall run

activate:
	poetry env activate

lint:
	poetry run pre-commit run --all-files

type-check:
	poetry run mypy .

install:
	POETRY_VIRTUALENVS_IN_PROJECT=1 poetry install --no-root

install-dev:
	POETRY_VIRTUALENVS_IN_PROJECT=1 poetry install --no-root --with dev
	poetry run pre-commit install

uninstall:
	poetry env remove python

run:
	poetry run scripts/run.sh
