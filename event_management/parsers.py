from datetime import datetime

from flask import abort, flash, request

from .constants import MAX_TICKETS


def parse_event_form(default_capacity=None):
    name = request.form.get("name", "").strip()
    date = request.form.get("date", "").strip()
    location = request.form.get("location", "").strip()
    capacity_raw = request.form.get("capacity")
    if capacity_raw is None:
        if default_capacity is not None:
            capacity_raw = str(default_capacity)
        else:
            capacity_raw = str(MAX_TICKETS)
    capacity = capacity_raw.strip()
    return name, date, location, capacity


def parse_booking_sort():
    allowed_sort_fields = {
        "created_at": "b.created_at",
        "event_name": "e.name",
        "user_name": "b.user_name",
        "tickets": "b.tickets",
    }
    sort_by = request.args.get("sort_by", "created_at").strip()
    if sort_by not in allowed_sort_fields:
        sort_by = "created_at"

    sort_dir = request.args.get("sort_dir", "desc").strip().lower()
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"

    order_by_sql = f"{allowed_sort_fields[sort_by]} {sort_dir.upper()}, b.id DESC"
    return sort_by, sort_dir, order_by_sql


def parse_booking_status_filter():
    status = request.args.get("status", "").strip().lower()
    if status not in {"", "sent", "failed", "skipped", "pending"}:
        return ""
    return status


def parse_booking_audit_filters():
    action = request.args.get("action", "").strip().lower()
    if action not in {"", "cancel", "create"}:
        action = ""

    actor = request.args.get("actor", "").strip().lower()
    if actor not in {"", "admin", "self_service"}:
        actor = ""

    reference_code = request.args.get("ref", "").strip().upper()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    where_parts = []
    params = []

    if action:
        where_parts.append("action = ?")
        params.append(action)

    if actor:
        where_parts.append("actor = ?")
        params.append(actor)

    if reference_code:
        where_parts.append("reference_code = ?")
        params.append(reference_code)

    if date_from:
        where_parts.append("DATE(created_at) >= DATE(?)")
        params.append(date_from)

    if date_to:
        where_parts.append("DATE(created_at) <= DATE(?)")
        params.append(date_to)

    where_clause = ""
    if where_parts:
        where_clause = "WHERE " + " AND ".join(where_parts)

    return {
        "action": action,
        "actor": actor,
        "reference_code": reference_code,
        "date_from": date_from,
        "date_to": date_to,
        "where_clause": where_clause,
        "params": params,
    }


def parse_events_api_filters():
    query = request.args.get("q", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    for value in (date_from, date_to):
        if value:
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError:
                abort(400, description="date_from/date_to must be in YYYY-MM-DD format.")

    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=20, type=int)
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    per_page = min(per_page, 100)

    where_parts = []
    params = []
    if query:
        where_parts.append("(e.name LIKE ? OR e.location LIKE ?)")
        pattern = f"%{query}%"
        params.extend([pattern, pattern])

    if date_from:
        where_parts.append("e.date >= ?")
        params.append(date_from)

    if date_to:
        where_parts.append("e.date <= ?")
        params.append(date_to)

    where_clause = ""
    if where_parts:
        where_clause = "WHERE " + " AND ".join(where_parts)

    return {
        "query": query,
        "date_from": date_from,
        "date_to": date_to,
        "page": page,
        "per_page": per_page,
        "where_clause": where_clause,
        "params": params,
    }


def parse_home_event_filters():
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=10, type=int)
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    per_page = min(per_page, 50)

    for value in (date_from, date_to):
        if value:
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError:
                flash("Date filters must be in YYYY-MM-DD format.", "error")
                return {
                    "date_from": "",
                    "date_to": "",
                    "page": page,
                    "per_page": per_page,
                    "where_clause": "",
                    "params": [],
                }

    where_parts = []
    params = []
    if date_from:
        where_parts.append("e.date >= ?")
        params.append(date_from)
    if date_to:
        where_parts.append("e.date <= ?")
        params.append(date_to)

    where_clause = ""
    if where_parts:
        where_clause = "WHERE " + " AND ".join(where_parts)

    return {
        "date_from": date_from,
        "date_to": date_to,
        "page": page,
        "per_page": per_page,
        "where_clause": where_clause,
        "params": params,
    }
