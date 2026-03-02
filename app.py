import smtplib

try:
    from event_management import app, create_app, init_db, load_runtime_config, main, reset_rate_limit_state
except ModuleNotFoundError as exc:
    missing_module = exc.name or str(exc)
    raise SystemExit(
        "Missing dependency "
        f"'{missing_module}'. Install requirements with "
        "`python3 -m pip install -r requirements.txt` "
        "or run via your project virtual environment."
    ) from exc

__all__ = ["app", "create_app", "init_db", "load_runtime_config", "reset_rate_limit_state", "main", "smtplib"]


if __name__ == "__main__":
    main()
