VENV_PY := .venv/bin/python
PYTHON ?= $(if $(wildcard $(VENV_PY)),$(VENV_PY),python3)
GUNICORN_PID ?= .gunicorn.pid
GUNICORN_LOG ?= .gunicorn.log

.PHONY: run run-prod run-prod-daemon stop-prod status-prod logs-prod test smoke lint migrate backup restore compose-up compose-down compose-logs compose-migrate compose-smoke

run:
	$(PYTHON) app.py

run-prod:
	$(PYTHON) -m gunicorn -w 2 -b 0.0.0.0:8000 app:app

run-prod-daemon:
	@if [ -f "$(GUNICORN_PID)" ] && kill -0 "$$(cat "$(GUNICORN_PID)")" 2>/dev/null; then \
		echo "Gunicorn already running with PID $$(cat "$(GUNICORN_PID)")"; \
		exit 1; \
	fi
	@rm -f "$(GUNICORN_PID)"
	$(PYTHON) -m gunicorn -w 2 -b 0.0.0.0:8000 app:app --daemon --pid "$(GUNICORN_PID)" --log-file "$(GUNICORN_LOG)"
	@for i in $$(seq 1 20); do \
		if [ -s "$(GUNICORN_PID)" ]; then break; fi; \
		sleep 0.1; \
	done
	@if [ ! -s "$(GUNICORN_PID)" ]; then \
		echo "Gunicorn failed to start: PID file not created"; \
		if [ -f "$(GUNICORN_LOG)" ]; then tail -n 40 "$(GUNICORN_LOG)"; fi; \
		exit 1; \
	fi
	@if ! kill -0 "$$(cat "$(GUNICORN_PID)")" 2>/dev/null; then \
		echo "Gunicorn failed to stay running"; \
		if [ -f "$(GUNICORN_LOG)" ]; then tail -n 40 "$(GUNICORN_LOG)"; fi; \
		exit 1; \
	fi
	@echo "Gunicorn started in background (PID $$(cat "$(GUNICORN_PID)"))"

stop-prod:
	@if [ ! -f "$(GUNICORN_PID)" ]; then \
		echo "Gunicorn is not running (missing $(GUNICORN_PID))"; \
		exit 0; \
	fi
	@if ! kill -0 "$$(cat "$(GUNICORN_PID)")" 2>/dev/null; then \
		echo "Stale PID file found; removing $(GUNICORN_PID)"; \
		rm -f "$(GUNICORN_PID)"; \
		exit 0; \
	fi
	@kill "$$(cat "$(GUNICORN_PID)")"
	@rm -f "$(GUNICORN_PID)"
	@echo "Gunicorn stopped"

status-prod:
	@if [ -f "$(GUNICORN_PID)" ] && kill -0 "$$(cat "$(GUNICORN_PID)")" 2>/dev/null; then \
		echo "Gunicorn running with PID $$(cat "$(GUNICORN_PID)")"; \
	else \
		echo "Gunicorn is not running"; \
	fi

logs-prod:
	@if [ ! -f "$(GUNICORN_LOG)" ]; then \
		echo "Log file not found: $(GUNICORN_LOG)"; \
		exit 1; \
	fi
	@tail -f "$(GUNICORN_LOG)"

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

smoke:
	$(PYTHON) -m unittest tests.test_smoke -v

lint:
	$(PYTHON) -m ruff check .

migrate:
	$(PYTHON) -m flask --app app db-upgrade

backup:
	./scripts/backup_db.sh

restore:
	@if [ -z "$(BACKUP_FILE)" ]; then echo "Usage: make restore BACKUP_FILE=backups/events_YYYYMMDD_HHMMSS.db"; exit 1; fi
	./scripts/restore_db.sh "$(BACKUP_FILE)"

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f web

compose-migrate:
	docker compose run --rm web python -m flask --app app db-upgrade

compose-smoke:
	@for i in $$(seq 1 30); do \
		if $(PYTHON) -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/', timeout=2).status == 200 else 1)" >/dev/null 2>&1; then \
			echo "Smoke check passed"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "Smoke check failed: app not reachable on http://127.0.0.1:8000/" >&2; \
	exit 1
