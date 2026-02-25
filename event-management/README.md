# Event Management (Flask)

Simple event management app with event creation, deletion, and booking.

## Project Layout

- Repo root: `/Users/sonamchosket/Desktop/event-management`
- App folder: `/Users/sonamchosket/Desktop/event-management/event-management`
- Main file: `app.py`

## Run Locally

```bash
cd /Users/sonamchosket/Desktop/event-management/event-management
source ../.venv/bin/activate
flask --app app run --debug
```

Open: `http://127.0.0.1:5000`

## Alternative Run Command

```bash
cd /Users/sonamchosket/Desktop/event-management/event-management
source ../.venv/bin/activate
python app.py
```

## Run Tests

```bash
cd /Users/sonamchosket/Desktop/event-management/event-management
source ../.venv/bin/activate
python -m unittest discover -s tests -p 'test_*.py' -v
```

## Make Targets

```bash
cd /Users/sonamchosket/Desktop/event-management/event-management
source ../.venv/bin/activate
make lint
make test
make run
```

## Dependency Snapshot

When needed, generate `requirements.txt` from your active venv:

```bash
cd /Users/sonamchosket/Desktop/event-management/event-management
../.venv/bin/pip freeze > requirements.txt
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
cd /Users/sonamchosket/Desktop/event-management/event-management
```

### Database reset (development only)

If you want a clean local state, remove `events.db` in the app folder and rerun the app.
