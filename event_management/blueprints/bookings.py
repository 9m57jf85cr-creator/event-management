import csv
import io
import json

from flask import Blueprint, current_app, flash, make_response, redirect, render_template, request, url_for

from ..constants import ADD_ON_SERVICE_LABELS
from ..parsers import parse_booking_audit_filters, parse_booking_sort, parse_booking_status_filter
from ..repositories.bookings_repo import (
    fetch_admin_bookings_page,
    fetch_audit_rows,
    fetch_bookings_for_csv,
    fetch_my_bookings_by_reference,
)
from ..security import admin_required
from ..services.booking_service import cancel_booking_admin, cancel_booking_self_service, resend_confirmation_email
from ..validators import is_valid_reference_code

bp = Blueprint("bookings", __name__)


def _selected_add_on_labels(raw_selected_add_ons):
    if not raw_selected_add_ons:
        return []

    try:
        selected_ids = json.loads(raw_selected_add_ons)
    except json.JSONDecodeError:
        return []

    if not isinstance(selected_ids, list):
        return []

    return [ADD_ON_SERVICE_LABELS[service_id] for service_id in selected_ids if service_id in ADD_ON_SERVICE_LABELS]


def _selected_add_on_export_value(raw_selected_add_ons):
    labels = _selected_add_on_labels(raw_selected_add_ons)
    return ", ".join(labels)


def serialize_booking_row(row, include_email_status=False):
    """Convert booking query rows into a dictionary the templates can render directly."""
    if include_email_status:
        return {
            "id": row[0],
            "event_name": row[1],
            "user_name": row[2],
            "user_email": row[3],
            "user_phone": row[4],
            "payment_method": row[5],
            "payment_status": row[6],
            "payment_reference": row[7],
            "selected_add_ons": _selected_add_on_labels(row[10]),
            "confirmation_email_status": row[8],
            "confirmation_email_error": row[9],
            "tickets": row[11],
            "created_at": row[12],
            "reference_code": row[13],
        }
    return {
        "id": row[0],
        "event_name": row[1],
        "user_name": row[2],
        "user_email": row[3],
        "user_phone": row[4],
        "payment_method": row[5],
        "payment_status": row[6],
        "payment_reference": row[7],
        "selected_add_ons": _selected_add_on_labels(row[8]),
        "tickets": row[9],
        "created_at": row[10],
        "reference_code": row[11],
    }


@bp.route("/my_bookings")
def my_bookings():
    reference_code = request.args.get("ref", "").strip().upper()
    booking_data = []
    has_search = bool(reference_code)

    if has_search:
        if is_valid_reference_code(reference_code):
            rows = fetch_my_bookings_by_reference(current_app, reference_code)
            booking_data = [serialize_booking_row(row) for row in rows]
        else:
            has_search = False
            reference_code = ""

    return render_template(
        "my_bookings.html",
        booking_data=booking_data,
        reference_code=reference_code,
        has_search=has_search,
    )


@bp.route("/my_bookings/cancel/<reference_code>", methods=["POST"])
def cancel_my_booking(reference_code):
    reference_code = reference_code.strip().upper()
    if not is_valid_reference_code(reference_code):
        return redirect(url_for("bookings.my_bookings"))

    result = cancel_booking_self_service(current_app, reference_code)
    if result["status"] == "not_found":
        flash("Booking not found for this reference code.", "error")
        return redirect(url_for("bookings.my_bookings", ref=reference_code))

    flash("Your booking was cancelled.", "success")
    return redirect(url_for("bookings.my_bookings", ref=reference_code))


@bp.route("/bookings")
@admin_required
def bookings():
    query = request.args.get("q", "").strip()
    status_filter = parse_booking_status_filter()
    sort_by, sort_dir, order_by_sql = parse_booking_sort()
    page = request.args.get("page", default=1, type=int)
    per_page = 10
    if page < 1:
        page = 1

    booking_rows, page, total_pages = fetch_admin_bookings_page(
        current_app, query, status_filter, order_by_sql, page, per_page
    )
    booking_data = [serialize_booking_row(row, include_email_status=True) for row in booking_rows]
    return render_template(
        "bookings.html",
        booking_data=booking_data,
        q=query,
        status_filter=status_filter,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )


@bp.route("/cancel_booking/<int:booking_id>", methods=["POST"])
@admin_required
def cancel_booking(booking_id):
    result = cancel_booking_admin(current_app, booking_id)
    if result["status"] == "not_found":
        flash("Booking not found.", "error")
        return redirect(url_for("bookings.bookings"))
    flash("Booking cancelled.", "success")
    return redirect(url_for("bookings.bookings"))


@bp.route("/bookings/resend_confirmation/<int:booking_id>", methods=["POST"])
@admin_required
def resend_booking_confirmation(booking_id):
    result = resend_confirmation_email(current_app, booking_id)
    if result["status"] == "not_found":
        flash("Booking not found.", "error")
        return redirect(url_for("bookings.bookings"))
    if result["status"] == "sent":
        flash("Confirmation email sent.", "success")
    elif result["status"] == "failed":
        flash("Confirmation email failed to send.", "error")
    else:
        flash("Confirmation email skipped because SMTP is disabled.", "error")
    return redirect(url_for("bookings.bookings"))


@bp.route("/bookings/export.csv")
@admin_required
def export_bookings_csv():
    query = request.args.get("q", "").strip()
    status_filter = parse_booking_status_filter()
    _, _, order_by_sql = parse_booking_sort()
    rows = fetch_bookings_for_csv(current_app, query, status_filter, order_by_sql)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "booking_id",
            "event_name",
            "user_name",
            "user_email",
            "user_phone",
            "payment_method",
            "payment_status",
            "payment_reference",
            "selected_add_ons",
            "tickets",
            "created_at",
            "reference_code",
        ]
    )
    writer.writerows(
        [
            [
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
                row[5],
                row[6],
                row[7],
                _selected_add_on_export_value(row[8]),
                row[9],
                row[10],
                row[11],
            ]
            for row in rows
        ]
    )

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=bookings_report.csv"
    return response


@bp.route("/booking_audit")
@admin_required
def booking_audit():
    filters = parse_booking_audit_filters()
    rows = fetch_audit_rows(current_app, filters, include_id=True)

    audit_data = [
        {
            "id": row[0],
            "booking_id": row[1],
            "reference_code": row[2],
            "action": row[3],
            "actor": row[4],
            "created_at": row[5],
        }
        for row in rows
    ]

    return render_template("booking_audit.html", audit_data=audit_data, filters=filters)


@bp.route("/booking_audit/export.csv")
@admin_required
def export_booking_audit_csv():
    filters = parse_booking_audit_filters()
    rows = fetch_audit_rows(current_app, filters, include_id=False)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["booking_id", "reference_code", "action", "actor", "created_at"])
    writer.writerows(rows)

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=booking_audit_report.csv"
    return response
