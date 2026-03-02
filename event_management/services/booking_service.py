from ..db import (
    generate_booking_reference,
    get_db_connection,
    log_booking_audit,
    update_booking_confirmation_email_status,
)
from ..notifications import send_booking_cancellation_email, send_booking_confirmation_email
from ..repositories.bookings_repo import (
    fetch_booking_for_admin_cancel,
    fetch_booking_for_resend,
    fetch_booking_for_self_cancel,
)
from ..repositories.events_repo import fetch_capacity_totals_for_update


def create_booking(app, event_id, name, email, phone, tickets, event_details):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute("BEGIN IMMEDIATE")

    capacity_row = fetch_capacity_totals_for_update(cursor, event_id)
    if capacity_row is None:
        conn.rollback()
        conn.close()
        return {"status": "event_not_found"}

    remaining_tickets = max(capacity_row[0] - capacity_row[1], 0)
    if remaining_tickets <= 0:
        conn.rollback()
        conn.close()
        return {"status": "sold_out"}

    if tickets > remaining_tickets:
        conn.rollback()
        conn.close()
        return {"status": "insufficient_tickets", "remaining_tickets": remaining_tickets}

    cursor.execute(
        """
        INSERT INTO bookings (
            event_id,
            user_name,
            user_email,
            user_phone,
            confirmation_email_status,
            confirmation_email_error,
            tickets,
            reference_code
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            name,
            email,
            phone,
            "pending",
            "",
            tickets,
            generate_booking_reference(cursor),
        ),
    )
    booking_id = cursor.lastrowid
    cursor.execute("SELECT reference_code FROM bookings WHERE id = ?", (booking_id,))
    booking_reference = cursor.fetchone()[0]
    log_booking_audit(
        cursor=cursor,
        booking_id=booking_id,
        reference_code=booking_reference,
        action="create",
        actor="self_service",
    )
    conn.commit()
    conn.close()

    email_status, email_error = send_booking_confirmation_email(
        app=app,
        to_email=email,
        user_name=name,
        event_name=event_details["name"],
        event_date=event_details["date"],
        event_location=event_details["location"],
        tickets=tickets,
        reference_code=booking_reference,
    )
    update_booking_confirmation_email_status(app, booking_id, email_status, email_error)

    return {"status": "success", "reference_code": booking_reference}


def cancel_booking_self_service(app, reference_code):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    row = fetch_booking_for_self_cancel(cursor, reference_code)
    if row is None:
        conn.close()
        return {"status": "not_found"}

    cursor.execute("DELETE FROM bookings WHERE id = ?", (row[0],))
    log_booking_audit(
        cursor=cursor,
        booking_id=row[0],
        reference_code=row[1],
        action="cancel",
        actor="self_service",
    )
    conn.commit()
    conn.close()

    send_booking_cancellation_email(
        app=app,
        to_email=row[3],
        user_name=row[2],
        event_name=row[4],
        reference_code=row[1],
    )
    return {"status": "success"}


def cancel_booking_admin(app, booking_id):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    row = fetch_booking_for_admin_cancel(cursor, booking_id)
    if row is None:
        conn.close()
        return {"status": "not_found"}

    cursor.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    log_booking_audit(
        cursor=cursor,
        booking_id=row[0],
        reference_code=row[1],
        action="cancel",
        actor="admin",
    )
    conn.commit()
    conn.close()

    send_booking_cancellation_email(
        app=app,
        to_email=row[3],
        user_name=row[2],
        event_name=row[4],
        reference_code=row[1],
    )
    return {"status": "success"}


def resend_confirmation_email(app, booking_id):
    row = fetch_booking_for_resend(app, booking_id)
    if row is None:
        return {"status": "not_found"}

    status, error_message = send_booking_confirmation_email(
        app=app,
        to_email=row[2],
        user_name=row[1],
        event_name=row[5],
        event_date=row[6],
        event_location=row[7],
        tickets=row[4],
        reference_code=row[3],
    )
    update_booking_confirmation_email_status(
        app,
        booking_id=row[0],
        status=status,
        error_message=error_message,
    )
    return {"status": status}
