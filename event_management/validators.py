import re
import string
from datetime import datetime

from flask import flash

from .constants import (
    BOOKING_REFERENCE_LENGTH,
    MAX_BOOKING_EMAIL_LENGTH,
    MAX_BOOKING_NAME_LENGTH,
    MAX_BOOKING_PHONE_LENGTH,
    MAX_EVENT_CAPACITY,
    MAX_EVENT_NAME_LENGTH,
    MAX_LOCATION_LENGTH,
)


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

    try:
        capacity = int(capacity_raw)
    except ValueError:
        flash("Capacity must be a positive integer.", "error")
        return False, None

    if capacity <= 0:
        flash("Capacity must be a positive integer.", "error")
        return False, None

    if capacity > MAX_EVENT_CAPACITY:
        flash(f"Capacity cannot exceed {MAX_EVENT_CAPACITY}.", "error")
        return False, None

    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        flash("Date must be in YYYY-MM-DD format.", "error")
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
    if not phone:
        flash("Phone number is required.", "error")
        return False

    if len(phone) > MAX_BOOKING_PHONE_LENGTH:
        flash(f"Phone number cannot exceed {MAX_BOOKING_PHONE_LENGTH} characters.", "error")
        return False

    if any(ord(ch) < 32 for ch in phone):
        flash("Phone number contains invalid characters.", "error")
        return False

    if not re.fullmatch(r"[0-9+\-\s()]+", phone):
        flash("Enter a valid phone number.", "error")
        return False

    digit_count = sum(ch.isdigit() for ch in phone)
    if digit_count < 7:
        flash("Enter a valid phone number.", "error")
        return False

    return True


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
