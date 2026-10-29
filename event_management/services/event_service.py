"""Business logic for shaping event data before it reaches templates."""

from ..constants import UNLIMITED_CAPACITY
from ..repositories.events_repo import fetch_paginated_events


def build_event_summary(row):
    """Convert a repository row into a template-friendly event summary."""
    if row[4] == UNLIMITED_CAPACITY:
        remaining_tickets = None
        capacity_display = "Unlimited"
        remaining_tickets_display = "Unlimited"
        is_sold_out = False
    else:
        remaining_tickets = max(row[4] - row[5], 0)
        capacity_display = row[4]
        remaining_tickets_display = remaining_tickets
        is_sold_out = remaining_tickets == 0

    return {
        "id": row[0],
        "name": row[1],
        "date": row[2],
        "location": row[3],
        "capacity": row[4],
        "capacity_display": capacity_display,
        "total_tickets": row[5],
        "remaining_tickets": remaining_tickets,
        "remaining_tickets_display": remaining_tickets_display,
        "is_sold_out": is_sold_out,
    }


def list_event_summaries(app, filters, page, per_page):
    """Fetch paginated events and format them for the home page."""
    rows, page, total_items, total_pages = fetch_paginated_events(app, filters, page, per_page)

    return {
        "items": [build_event_summary(row) for row in rows],
        "page": page,
        "per_page": per_page,
        "total_items": total_items,
        "total_pages": total_pages,
    }
