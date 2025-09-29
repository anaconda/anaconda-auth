# Conda-related paths
conda_env_dir ?= ./env

# Command aliases
CONDA_EXE ?= conda
CONDA_RUN := $(CONDA_EXE) run --prefix $(conda_env_dir) --no-capture-output

.PHONY: help setup install-hooks pre-commit type-check test tox clean clean-all

help:  ## Display help on all Makefile targets
	@@grep -h '^[a-zA-Z]' $(MAKEFILE_LIST) | awk -F ':.*?## ' 'NF==2 {printf "   %-20s%s\n", $$1, $$2}' | sort

setup:  ## Setup local dev conda environment
	$(CONDA_EXE) env $(shell [ -d $(conda_env_dir) ] && echo update || echo create) -p $(conda_env_dir) --file environment-dev.yml

install-hooks:  ## Install pre-commit hooks
	pre-commit install-hooks

pre-commit:  ## Run pre-commit against all files
	@if ! which pre-commit >/dev/null; then \
		echo "Install pre-commit via brew/conda"; \
		echo "  e.g. 'brew install pre-commit'"; \
		exit 1; \
	fi
	pre-commit run --verbose --show-diff-on-failure --color=always --all-files

type-check:  ## Run static type checks
	$(CONDA_RUN) mypy

test:  ## Run all the unit tests
	$(CONDA_RUN) pytest $(ARGS)

test-integration:  ## Run all the unit tests
	$(CONDA_RUN) pytest --integration

tox:  ## Run tox to test in isolated environments
	$(CONDA_RUN) tox

tox-integration:  ## Run tox to test in isolated environments
	$(CONDA_RUN) tox -- --integration

clean:  ## Clean up cache and temporary files
	find . -name \*.py[cod] -delete
	rm -rf .pytest_cache .mypy_cache .tox build dist

clean-all: clean  ## Clean up, including build files and conda environment
	find . -name \*.egg-info -delete
	rm -rf $(conda_env_dir)
