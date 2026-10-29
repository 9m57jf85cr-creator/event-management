import re
import string
from datetime import date as date_cls
from datetime import datetime

from flask import flash

from .constants import (
    ADD_ON_SERVICE_LABELS,
    BOOKING_REFERENCE_LENGTH,
    INDIA_LOCATION_KEYWORDS,
    MAX_BOOKING_EMAIL_LENGTH,
    MAX_BOOKING_NAME_LENGTH,
    MAX_BOOKING_PHONE_LENGTH,
    MAX_EVENT_CAPACITY,
    MAX_EVENT_NAME_LENGTH,
    MAX_LOCATION_LENGTH,
    MAX_PAYMENT_REFERENCE_LENGTH,
    UNLIMITED_CAPACITY,
)

PHONE_NUMBER_ERROR_MESSAGE = "Enter a valid phone number."


def _is_india_location(location):
    normalized = location.strip().lower()
    return any(keyword in normalized for keyword in INDIA_LOCATION_KEYWORDS)


def validate_event_fields(name, date, location, capacity_raw):
    if not name or not date or not location:
        flash("Event name, date, and location are required.", "error")
        return False, None

    if len(name) > MAX_EVENT_NAME_LENGTH:
        flash(f"Event name cannot exceed {MAX_EVENT_NAME_LENGTH} characters.", "error")
        return False, None

    if len(location) > MAX_LOCATION_LENGTH:
        flash(f"Location cannot exceed {MAX_LOCATION_LENGTH} characters.", "error")
        return False, None

    if any(ord(ch) < 32 for ch in name + location):
        flash("Event fields contain invalid characters.", "error")
        return False, None

    if name.strip().isdigit():
        flash("Event name cannot be only numbers.", "error")
        return False, None

    if not _is_india_location(location):
        flash("Location must be within India.", "error")
        return False, None

    if not capacity_raw:
        capacity = UNLIMITED_CAPACITY
    else:
        try:
            capacity = int(capacity_raw)
        except ValueError:
            flash("Capacity must be a positive integer, or leave blank for unlimited.", "error")
            return False, None

        if capacity <= 0:
            flash("Capacity must be a positive integer, or leave blank for unlimited.", "error")
            return False, None

    if capacity > MAX_EVENT_CAPACITY:
        flash(f"Capacity cannot exceed {MAX_EVENT_CAPACITY}.", "error")
        return False, None

    try:
        parsed_date = datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError:
        flash("Date must be in YYYY-MM-DD format.", "error")
        return False, None

    if parsed_date < date_cls.today():
        flash("Date must be today or a future date.", "error")
        return False, None

    return True, capacity


def is_valid_booking_name(name):
    if not name:
        flash("Your name is required.", "error")
        return False

    if len(name) > MAX_BOOKING_NAME_LENGTH:
        flash(f"Name cannot exceed {MAX_BOOKING_NAME_LENGTH} characters.", "error")
        return False

    if any(ord(ch) < 32 for ch in name):
        flash("Name contains invalid characters.", "error")
        return False

    return True


def is_valid_booking_email(email):
    if not email:
        flash("Email is required.", "error")
        return False

    if len(email) > MAX_BOOKING_EMAIL_LENGTH:
        flash(f"Email cannot exceed {MAX_BOOKING_EMAIL_LENGTH} characters.", "error")
        return False

    if any(ord(ch) < 32 for ch in email):
        flash("Email contains invalid characters.", "error")
        return False

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("Enter a valid email address.", "error")
        return False

    return True


def is_valid_booking_phone(phone):
    _, error_message = validate_booking_phone_value(phone)
    if error_message:
        flash(error_message, "error")
        return False
    return True


def validate_booking_phone_value(phone):
    cleaned = phone.strip()

    if not cleaned:
        return None, "Phone number is required."

    if len(cleaned) > MAX_BOOKING_PHONE_LENGTH:
        return None, f"Phone number cannot exceed {MAX_BOOKING_PHONE_LENGTH} characters."

    if any(ord(ch) < 32 for ch in cleaned):
        return None, "Phone number contains invalid characters."

    if not re.fullmatch(r"[0-9+\-\s()]+", cleaned):
        return None, PHONE_NUMBER_ERROR_MESSAGE

    if cleaned.count("+") > 1 or ("+" in cleaned and not cleaned.startswith("+")):
        return None, PHONE_NUMBER_ERROR_MESSAGE

    digit_count = sum(ch.isdigit() for ch in cleaned)
    if digit_count < 7 or digit_count > 15:
        return None, PHONE_NUMBER_ERROR_MESSAGE

    normalized = re.sub(r"\s+", " ", cleaned)
    return normalized, None


def validate_payment_details(payment_method, payment_reference):
    method = payment_method.strip().lower()
    reference = payment_reference.strip()

    if method not in {"offline", "online"}:
        flash("Select a valid payment method.", "error")
        return False, None, None

    if method == "online":
        if not reference:
            flash("Transaction reference is required for online payment.", "error")
            return False, None, None
        if len(reference) > MAX_PAYMENT_REFERENCE_LENGTH:
            flash(
                f"Transaction reference cannot exceed {MAX_PAYMENT_REFERENCE_LENGTH} characters.",
                "error",
            )
            return False, None, None
        if not re.fullmatch(r"[A-Za-z0-9._\-\/]+", reference):
            flash("Transaction reference contains invalid characters.", "error")
            return False, None, None
        return True, "online", reference

    return True, "offline", ""


def validate_add_on_service_selection(selected_ids):
    normalized_ids = []

    for raw_id in selected_ids:
        service_id = raw_id.strip()
        if not service_id:
            continue
        if service_id not in ADD_ON_SERVICE_LABELS:
            flash("Select only valid add-on services.", "error")
            return None
        if service_id not in normalized_ids:
            normalized_ids.append(service_id)

    return normalized_ids


def is_valid_reference_code(reference_code):
    if not reference_code:
        flash("Booking reference code is required.", "error")
        return False

    cleaned = reference_code.strip().upper()
    if len(cleaned) != BOOKING_REFERENCE_LENGTH:
        flash("Invalid booking reference code.", "error")
        return False

    if not all(ch in (string.ascii_uppercase + string.digits) for ch in cleaned):
        flash("Invalid booking reference code.", "error")
        return False

    return True
