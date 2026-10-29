VENV_PY := .venv/bin/python
ALT_VENV_PY := venv/bin/python
PYTHON ?= $(if $(wildcard $(VENV_PY)),$(VENV_PY),$(if $(wildcard $(ALT_VENV_PY)),$(ALT_VENV_PY),python3))
GUNICORN_PID ?= .gunicorn.pid
GUNICORN_LOG ?= .gunicorn.log
DEMO_PID ?= .demo.pid
DEMO_LOG ?= .demo.log
DEMO_PORT ?= 5001

.PHONY: run demo demo-8000 demo-bg demo-stop demo-status run-prod run-prod-daemon stop-prod status-prod logs-prod test smoke lint migrate backup restore compose-up compose-down compose-logs compose-migrate compose-smoke

run:
	$(PYTHON) app.py

demo:
	@echo "Starting demo server on http://127.0.0.1:$(DEMO_PORT)"
	@echo "Keep this terminal open. Press Ctrl+C to stop."
	@FLASK_HOST=127.0.0.1 FLASK_PORT=$(DEMO_PORT) $(PYTHON) app.py

demo-8000:
	@echo "Starting demo server on http://127.0.0.1:8000"
	@echo "Keep this terminal open. Press Ctrl+C to stop."
	@FLASK_HOST=127.0.0.1 FLASK_PORT=8000 $(PYTHON) app.py

demo-bg:
	@set -e; \
	existing_pid="$$(lsof -nP -iTCP:$(DEMO_PORT) -sTCP:LISTEN -t 2>/dev/null | head -n 1)"; \
	if [ -n "$$existing_pid" ]; then \
		echo "$$existing_pid" >"$(DEMO_PID)"; \
		echo "Demo server already running at http://127.0.0.1:$(DEMO_PORT)"; \
		echo "PID: $$existing_pid"; \
		echo "Logs: $(DEMO_LOG)"; \
		exit 0; \
	fi; \
	rm -f "$(DEMO_PID)"; \
	nohup env FLASK_HOST=127.0.0.1 FLASK_PORT=$(DEMO_PORT) $(PYTHON) app.py >"$(DEMO_LOG)" 2>&1 & echo $$! >"$(DEMO_PID)"; \
	for i in $$(seq 1 30); do \
		if $(PYTHON) -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:$(DEMO_PORT)/', timeout=2).status == 200 else 1)" >/dev/null 2>&1; then \
			pid="$$(cat "$(DEMO_PID)" 2>/dev/null)"; \
			echo "Demo server is running at http://127.0.0.1:$(DEMO_PORT)"; \
			echo "PID: $$pid"; \
			echo "Logs: $(DEMO_LOG)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "Demo server failed to start. Recent logs:"; \
	tail -n 40 "$(DEMO_LOG)"; \
	rm -f "$(DEMO_PID)"; \
	exit 1

demo-stop:
	@set -e; \
	pid=""; \
	port_pid="$$(lsof -nP -iTCP:$(DEMO_PORT) -sTCP:LISTEN -t 2>/dev/null | head -n 1)"; \
	if [ -n "$$port_pid" ]; then \
		pid="$$port_pid"; \
	elif [ ! -f "$(DEMO_PID)" ]; then \
		echo "Demo server is not running (missing $(DEMO_PID))"; \
		exit 0; \
	fi; \
	if [ -z "$$pid" ]; then \
		pid="$$(cat "$(DEMO_PID)" 2>/dev/null)"; \
	fi; \
	if [ -z "$$pid" ]; then \
		echo "Empty PID file found; removing $(DEMO_PID)"; \
		rm -f "$(DEMO_PID)"; \
		exit 0; \
	fi; \
	if ! kill -0 "$$pid" 2>/dev/null; then \
		echo "Stale PID file found; removing $(DEMO_PID)"; \
		rm -f "$(DEMO_PID)"; \
		exit 0; \
	fi; \
	kill "$$pid"; \
	rm -f "$(DEMO_PID)"; \
	echo "Demo server stopped"

demo-status:
	@pid="$$(lsof -nP -iTCP:$(DEMO_PORT) -sTCP:LISTEN -t 2>/dev/null | head -n 1)"; \
	if [ -n "$$pid" ]; then \
		echo "$$pid" >"$(DEMO_PID)"; \
		echo "Demo server running with PID $$pid at http://127.0.0.1:$(DEMO_PORT)"; \
	else \
		echo "Demo server is not running"; \
	fi

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
