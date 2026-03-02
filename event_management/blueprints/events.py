from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ..constants import MAX_TICKETS
from ..parsers import parse_event_form, parse_home_event_filters
from ..repositories.events_repo import (
    create_event,
    delete_event as delete_event_record,
    fetch_event_for_edit,
    fetch_event_with_totals,
    update_event as update_event_record,
)
from ..security import admin_required
from ..services.booking_service import create_booking
from ..services.event_service import list_event_summaries
from ..validators import (
    is_valid_booking_email,
    is_valid_booking_name,
    is_valid_booking_phone,
    validate_event_fields,
)

bp = Blueprint("events", __name__)


@bp.route("/")
def home():
    filters = parse_home_event_filters()
    listing = list_event_summaries(
        current_app,
        filters,
        page=filters["page"],
        per_page=filters["per_page"],
    )
    return render_template(
        "index.html",
        event_data=listing["items"],
        filters=filters,
        page=listing["page"],
        total_pages=listing["total_pages"],
        per_page=listing["per_page"],
    )


@bp.route("/add_event", methods=["POST"])
@admin_required
def add_event():
    name, date, location, capacity_raw = parse_event_form()
    valid, capacity = validate_event_fields(name, date, location, capacity_raw)
    if not valid:
        return redirect(url_for("events.home"))

    create_event(current_app, name, date, location, capacity)

    flash("Event added successfully.", "success")
    return redirect(url_for("events.home"))


@bp.route("/delete/<int:id>", methods=["POST"])
@admin_required
def delete_event(id):
    if not delete_event_record(current_app, id):
        flash("Event not found.", "error")
        return redirect(url_for("events.home"))
    flash("Event deleted.", "success")
    return redirect(url_for("events.home"))


@bp.route("/edit_event/<int:event_id>", methods=["GET", "POST"])
@admin_required
def edit_event(event_id):
    event = fetch_event_for_edit(current_app, event_id)
    if event is None:
        flash("Event not found.", "error")
        return redirect(url_for("events.home"))

    if request.method == "POST":
        name, date, location, capacity_raw = parse_event_form(default_capacity=event["capacity"])
        valid, capacity = validate_event_fields(name, date, location, capacity_raw)
        if not valid:
            event = {
                "id": event_id,
                "name": name,
                "date": date,
                "location": location,
                "capacity": capacity_raw,
            }
            return render_template("edit_event.html", event=event)

        update_event_record(current_app, event_id, name, date, location, capacity)
        flash("Event updated successfully.", "success")
        return redirect(url_for("events.home"))
    return render_template("edit_event.html", event=event)


@bp.route("/book/<int:event_id>", methods=["GET", "POST"])
def book_event(event_id):
    event = fetch_event_with_totals(current_app, event_id)
    if event is None:
        flash("Event not found.", "error")
        return redirect(url_for("events.home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        tickets_raw = request.form.get("tickets", "").strip()
        event_name = event[1]

        if not is_valid_booking_name(name):
            return redirect(url_for("events.book_event", event_id=event_id))

        if not is_valid_booking_email(email):
            return redirect(url_for("events.book_event", event_id=event_id))

        if not is_valid_booking_phone(phone):
            return redirect(url_for("events.book_event", event_id=event_id))

        try:
            tickets = int(tickets_raw)
            if tickets <= 0:
                raise ValueError
        except ValueError:
            flash("Tickets must be a positive integer.", "error")
            return redirect(url_for("events.book_event", event_id=event_id))

        if tickets > MAX_TICKETS:
            flash(f"Tickets cannot exceed {MAX_TICKETS}.", "error")
            return redirect(url_for("events.book_event", event_id=event_id))

        booking_result = create_booking(
            app=current_app,
            event_id=event_id,
            name=name,
            email=email,
            phone=phone,
            tickets=tickets,
            event_details={"name": event_name, "date": event[2], "location": event[3]},
        )

        if booking_result["status"] == "event_not_found":
            flash("Event not found.", "error")
            return redirect(url_for("events.home"))
        if booking_result["status"] == "sold_out":
            flash("This event is sold out.", "error")
            return redirect(url_for("events.book_event", event_id=event_id))
        if booking_result["status"] == "insufficient_tickets":
            flash(
                f"Only {booking_result['remaining_tickets']} tickets left for this event.",
                "error",
            )
            return redirect(url_for("events.book_event", event_id=event_id))

        flash(
            f"Booking successful. Your reference code: {booking_result['reference_code']}",
            "success",
        )
        return redirect(url_for("events.home"))

    remaining_tickets = max(event[4] - event[5], 0)
    return render_template(
        "book.html",
        event={
            "id": event[0],
            "name": event[1],
            "capacity": event[4],
            "total_tickets": event[5],
            "remaining_tickets": remaining_tickets,
        },
    )
