import importlib
import smtplib as stdlib_smtplib
from email.message import EmailMessage


def _get_smtp_client():
    # Keep compatibility with tests that patch `app.smtplib.SMTP`.
    try:
        app_module = importlib.import_module("app")
        smtp_module = getattr(app_module, "smtplib", stdlib_smtplib)
    except Exception:
        smtp_module = stdlib_smtplib
    return smtp_module.SMTP


def send_notification_email(app, to_email, subject, body_lines):
    if not app.config.get("SMTP_ENABLED"):
        return "skipped", "SMTP is disabled."

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = app.config["SMTP_FROM_EMAIL"]
    message["To"] = to_email
    message.set_content("\n".join(body_lines))

    try:
        with _get_smtp_client()(
            app.config["SMTP_HOST"],
            app.config["SMTP_PORT"],
            timeout=10,
        ) as smtp_client:
            if app.config["SMTP_USE_TLS"]:
                smtp_client.starttls()

            if app.config["SMTP_USERNAME"] or app.config["SMTP_PASSWORD"]:
                smtp_client.login(
                    app.config["SMTP_USERNAME"],
                    app.config["SMTP_PASSWORD"],
                )

            smtp_client.send_message(message)
            return "sent", ""
    except Exception as exc:
        app.logger.exception("Failed to send notification email.")
        return "failed", str(exc)[:300]


def send_booking_confirmation_email(
    app,
    to_email,
    user_name,
    event_name,
    event_date,
    event_location,
    tickets,
    reference_code,
):
    return send_notification_email(
        app=app,
        to_email=to_email,
        subject=f"Booking Confirmed: {event_name}",
        body_lines=[
            f"Hi {user_name},",
            "",
            "Your booking is confirmed.",
            f"Event: {event_name}",
            f"Date: {event_date}",
            f"Location: {event_location}",
            f"Tickets: {tickets}",
            f"Reference Code: {reference_code}",
            "",
            "Thank you.",
        ],
    )


def send_booking_cancellation_email(app, to_email, user_name, event_name, reference_code):
    return send_notification_email(
        app=app,
        to_email=to_email,
        subject=f"Booking Cancelled: {event_name}",
        body_lines=[
            f"Hi {user_name},",
            "",
            "Your booking has been cancelled.",
            f"Event: {event_name}",
            f"Reference Code: {reference_code}",
        ],
    )
