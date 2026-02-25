# Event Management (Flask)

Simple event management app with event creation, capacity management, booking, and cancellation flows.
Each booking now gets a unique reference code for self-service lookup and cancellation.
Admin users can review cancellation history from the booking audit page.

## Project Layout

- Repo root: `/Users/sonamchosket/Desktop/event-management`
- Main file: `app.py`

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
```

In production mode, the app:
- rejects the default development `SECRET_KEY`
- enables secure session cookies (`SESSION_COOKIE_SECURE=True`)
- keeps `HttpOnly` and `SameSite=Lax` session cookie protections
- applies baseline security headers (CSP, frame, content-type, referrer)

## Alternative Run Command

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
python app.py
```

## Run Tests

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
python -m unittest discover -s tests -p 'test_*.py' -v
```

## Make Targets

```bash
cd /Users/sonamchosket/Desktop/event-management
source .venv/bin/activate
make lint
make test
make run
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
