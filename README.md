# Event Management (Flask)

Simple event management app with event creation, capacity management, booking, and cancellation flows.
Each booking now gets a unique reference code for self-service lookup and cancellation.
Admin users can review cancellation history from the booking audit page.

## Project Layout

- Repo root: `/Users/sonamchosket/Desktop/event-management`
- Entry file: `app.py` (compatibility wrapper)
- App package: `event_management/`
- Frontend templates: `templates/`
- Frontend static assets: `static/css/`, `static/js/`, `static/manifest.json`, `static/service-worker.js`
- Blueprints:
  - `event_management/blueprints/auth.py`
  - `event_management/blueprints/events.py`
  - `event_management/blueprints/bookings.py`
  - `event_management/blueprints/api.py`
- DB migration SQL files: `migrations/versions/`

## Architecture

Request path:
- `templates/*` -> browser form/API call
- `event_management/blueprints/*` -> route/controller layer
- `event_management/services/*` -> business workflows (booking create/cancel/resend)
- `event_management/repositories/*` -> SQL query layer
- `event_management/db.py`, `event_management/schema.py` -> DB connection and schema setup

Security and middleware:
- `event_management/security_hooks.py` -> CSRF, rate-limit hook, API-key enforcement, security headers
- `event_management/security_auth.py` -> auth helpers and decorator
- `event_management/security_rate_limit.py` -> rate-limit storage logic

App startup:
- `event_management/webapp.py` -> `create_app()` factory, route/security registration, CLI command wiring
- `app.py` -> compatibility entry point used by tests and local run commands

Frontend rendering:
- `templates/base.html` loads global assets (`static/css/main.css`, `static/js/main.js`)
- page-specific CSS is attached via `{% block extra_head %}` in each template
- page-specific JS is attached via `{% block extra_scripts %}` in each template (for example `static/js/login.js`)

Data lifecycle:
- Versioned migrations are applied via `flask --app app db-upgrade`
- Legacy compatibility/backfill logic remains in `event_management/legacy_migrations.py`

## Run Locally

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
flask --app app run --debug
```

Open: `http://127.0.0.1:5000`

## Configure Admin Credentials (.env)

Create a `.env` file in the repo root:

```bash
cd /Users/sonamchosket/Desktop/event-management
cat > .env << 'EOF'
ADMIN_USERNAME=sonam
ADMIN_PASSWORD=MyStrongPass123!
SECRET_KEY=change-this-to-a-random-long-value
EOF
```

Restart the app after changing `.env`.

You can also set an optional database path:

```env
DATABASE=events.db
```

If `DATABASE` is a relative path, it is resolved from the repo root.

## Production Security Notes

Set production environment variables before starting:

```bash
export FLASK_ENV=production
export SECRET_KEY='set-a-strong-random-secret'
export ADMIN_USERNAME='your-admin-user'
export ADMIN_PASSWORD='your-admin-password'
export API_KEY='replace-with-your-api-key'
```

In production mode, the app:
- rejects the default development `SECRET_KEY`
- rejects default `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `API_KEY`
- enables secure session cookies (`SESSION_COOKIE_SECURE=True`)
- keeps `HttpOnly` and `SameSite=Lax` session cookie protections
- applies baseline security headers (CSP, frame, content-type, referrer)
- enforces rate limits for login and booking POST requests

Optional rate limit tuning:

```bash
export RATE_LIMIT_WINDOW_SECONDS=60
export RATE_LIMIT_LOGIN_MAX_REQUESTS=10
export RATE_LIMIT_BOOKING_MAX_REQUESTS=30
```

Optional email notifications for booking create/cancel:

```bash
export SMTP_ENABLED=true
export SMTP_HOST='smtp.your-provider.com'
export SMTP_PORT=587
export SMTP_USERNAME='smtp-user'
export SMTP_PASSWORD='smtp-pass'
export SMTP_USE_TLS=true
export SMTP_FROM_EMAIL='no-reply@your-domain.com'
```

## Deployment (Docker + Gunicorn)

Build image:

```bash
cd /Users/sonamchosket/Desktop/event-management
docker build -t event-management:latest .
```

Run container:

```bash
docker run --rm -p 8000:8000 \
  -e FLASK_ENV=production \
  -e SECRET_KEY='set-a-strong-random-secret' \
  -e ADMIN_USERNAME='your-admin-user' \
  -e ADMIN_PASSWORD='your-admin-password' \
  -e API_KEY='replace-with-your-api-key' \
  -e DATABASE='/app/events.db' \
  event-management:latest
```

The container starts with Gunicorn:
- `gunicorn -w 2 -b 0.0.0.0:8000 app:app`

## Deployment (Docker Compose)

1. Copy compose env file:

```bash
cd /Users/sonamchosket/Desktop/event-management
cp .env.docker.example .env.docker
```

2. Edit `.env.docker` with production values for:
- `SECRET_KEY`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `API_KEY`

3. Start services:

```bash
make compose-up
```

4. Watch logs:

```bash
make compose-logs
```

5. Run smoke check:

```bash
make compose-smoke
```

6. Stop services:

```bash
make compose-down
```

Notes:
- Compose stores SQLite at `/data/events.db` inside a named volume (`event_mgmt_data`) for persistence.
- On container start, migrations run automatically before Gunicorn starts.
- Compose includes a container healthcheck that verifies `http://127.0.0.1:8000/`.

## Events API

Set an API key:

```bash
export API_KEY='replace-with-your-api-key'
```

All `/api/*` endpoints require header:

```text
X-API-Key: <your-api-key>
```

Endpoints:

```text
GET /api/v1/events
GET /api/v1/health
```

Backward-compatible alias:

```text
GET /api/events
```

Query params:
- `q` (optional): search by event name/location
- `date_from` (optional, `YYYY-MM-DD`)
- `date_to` (optional, `YYYY-MM-DD`)
- `page` (optional, default `1`)
- `per_page` (optional, default `20`, max `100`)

Response includes:
- event fields (`id`, `name`, `date`, `location`, `capacity`)
- booking stats (`total_tickets`, `remaining_tickets`, `is_sold_out`)
- pagination metadata (`page`, `per_page`, `total_items`, `total_pages`)

## Alternative Run Command

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
python app.py
```

## Database Migrations

The project now supports versioned SQL migrations.

Apply pending migrations:

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
flask --app app db-upgrade
```

Or via Make:

```bash
make migrate
```

Current baseline migration file:
- `migrations/versions/20260228_0001_initial_schema.sql`

## Backup and Restore

Create timestamped SQLite backup:

```bash
cd /Users/sonamchosket/Desktop/event-management
./scripts/backup_db.sh
```

Restore from a backup file:

```bash
cd /Users/sonamchosket/Desktop/event-management
./scripts/restore_db.sh backups/events_YYYYMMDD_HHMMSS.db
```

## Run Tests

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
python -m unittest discover -s tests -p 'test_*.py' -v
```

## Next Steps

1. Create/update `.env` with `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `SECRET_KEY`, and `API_KEY`.
2. Run `python -m unittest discover -s tests -p 'test_*.py' -v` to verify all flows.
3. Start the app with `python app.py` and test end-to-end: admin login, add event, book, self-cancel, and bookings export.

Quick smoke test:

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
python -m unittest tests.test_smoke -v
```

## Make Targets

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
make lint
make smoke
make test
make run
make migrate
make backup
make restore BACKUP_FILE=backups/events_YYYYMMDD_HHMMSS.db
make compose-up
make compose-logs
make compose-smoke
make compose-down
make compose-migrate
```

## Dependency Snapshot

When needed, generate `requirements.txt` from your active venv:

```bash
cd /Users/sonamchosket/Desktop/event-management
.venv/bin/pip freeze > requirements.txt
```

## Troubleshooting

### `zsh: command not found: flask`

Cause: virtual environment is not active or command was run outside the venv context.

Fix:

```bash
source /Users/sonamchosket/Desktop/event-management/.venv/bin/activate
which flask
```

Expected output:

```text
/Users/sonamchosket/Desktop/event-management/.venv/bin/flask
```

### Template mismatch or runtime errors after edits

Ensure you are running from the app folder:

```bash
cd /Users/sonamchosket/Desktop/event-management
```

### Database reset (development only)

If you want a clean local state, remove `events.db` in the repo root and rerun the app.
