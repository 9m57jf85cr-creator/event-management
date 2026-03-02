import re

from flask import Blueprint, current_app, jsonify, request

from ..constants import MAX_BOOKING_EMAIL_LENGTH, MAX_BOOKING_NAME_LENGTH, MAX_BOOKING_PHONE_LENGTH, MAX_TICKETS
from ..parsers import parse_events_api_filters
from ..repositories.events_repo import fetch_event_with_totals
from ..services.booking_service import create_booking
from ..services.event_service import list_event_summaries

bp = Blueprint("api", __name__)


def _events_api_response():
    filters = parse_events_api_filters()
    listing = list_event_summaries(
        current_app,
        filters,
        page=filters["page"],
        per_page=filters["per_page"],
    )

    return jsonify(
        {
            "items": listing["items"],
            "page": listing["page"],
            "per_page": listing["per_page"],
            "total_items": listing["total_items"],
            "total_pages": listing["total_pages"],
        }
    )


@bp.route("/api/events")
@bp.route("/api/v1/events")
def api_events():
    return _events_api_response()


@bp.route("/api/v1/health")
def api_health_v1():
    return jsonify({"status": "ok", "version": "v1"})


def _validate_booking_payload(payload):
    if not isinstance(payload, dict):
        return None, "Request body must be a JSON object."

    name = str(payload.get("name", "")).strip()
    email = str(payload.get("email", "")).strip()
    phone = str(payload.get("phone", "")).strip()

    try:
        event_id = int(payload.get("event_id"))
    except (TypeError, ValueError):
        return None, "event_id must be a positive integer."

    try:
        tickets = int(payload.get("tickets"))
    except (TypeError, ValueError):
        return None, "tickets must be a positive integer."

    if event_id <= 0:
        return None, "event_id must be a positive integer."
    if tickets <= 0:
        return None, "tickets must be a positive integer."
    if tickets > MAX_TICKETS:
        return None, f"tickets cannot exceed {MAX_TICKETS}."

    if not name:
        return None, "name is required."
    if len(name) > MAX_BOOKING_NAME_LENGTH:
        return None, f"name cannot exceed {MAX_BOOKING_NAME_LENGTH} characters."
    if any(ord(ch) < 32 for ch in name):
        return None, "name contains invalid characters."

    if not email:
        return None, "email is required."
    if len(email) > MAX_BOOKING_EMAIL_LENGTH:
        return None, f"email cannot exceed {MAX_BOOKING_EMAIL_LENGTH} characters."
    if any(ord(ch) < 32 for ch in email):
        return None, "email contains invalid characters."
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return None, "email must be a valid email address."

    if not phone:
        return None, "phone is required."
    if len(phone) > MAX_BOOKING_PHONE_LENGTH:
        return None, f"phone cannot exceed {MAX_BOOKING_PHONE_LENGTH} characters."
    if any(ord(ch) < 32 for ch in phone):
        return None, "phone contains invalid characters."
    if not re.fullmatch(r"[0-9+\-\s()]+", phone):
        return None, "phone must be a valid phone number."
    if sum(ch.isdigit() for ch in phone) < 7:
        return None, "phone must be a valid phone number."

    return {
        "event_id": event_id,
        "name": name,
        "email": email,
        "phone": phone,
        "tickets": tickets,
    }, None


@bp.route("/api/v1/bookings", methods=["POST"])
def api_create_booking():
    payload = request.get_json(silent=True)
    data, validation_error = _validate_booking_payload(payload)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    event = fetch_event_with_totals(current_app, data["event_id"])
    if event is None:
        return jsonify({"error": "Event not found."}), 404

    booking_result = create_booking(
        app=current_app,
        event_id=data["event_id"],
        name=data["name"],
        email=data["email"],
        phone=data["phone"],
        tickets=data["tickets"],
        event_details={"name": event[1], "date": event[2], "location": event[3]},
    )

    if booking_result["status"] == "event_not_found":
        return jsonify({"error": "Event not found."}), 404
    if booking_result["status"] == "sold_out":
        return jsonify({"error": "This event is sold out."}), 409
    if booking_result["status"] == "insufficient_tickets":
        return (
            jsonify(
                {
                    "error": f"Only {booking_result['remaining_tickets']} tickets left for this event.",
                    "remaining_tickets": booking_result["remaining_tickets"],
                }
            ),
            409,
        )

    return jsonify({"status": "success", "reference_code": booking_result["reference_code"]}), 201
