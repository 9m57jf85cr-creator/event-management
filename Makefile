VENV_PY := .venv/bin/python
PYTHON ?= $(if $(wildcard $(VENV_PY)),$(VENV_PY),python3)

.PHONY: run test smoke lint

run:
	$(PYTHON) app.py

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

smoke:
	$(PYTHON) -m unittest tests.test_smoke -v

lint:
	$(PYTHON) -m ruff check .
