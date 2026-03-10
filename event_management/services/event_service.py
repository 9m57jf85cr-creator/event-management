from ..constants import UNLIMITED_CAPACITY
from ..repositories.events_repo import fetch_paginated_events


def list_event_summaries(app, filters, page, per_page):
    rows, page, total_items, total_pages = fetch_paginated_events(app, filters, page, per_page)

    items = []
    for row in rows:
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

        items.append(
            {
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
        )

    return {
        "items": items,
        "page": page,
        "per_page": per_page,
        "total_items": total_items,
        "total_pages": total_pages,
    }
