from ..repositories.events_repo import fetch_paginated_events


def list_event_summaries(app, filters, page, per_page):
    rows, page, total_items, total_pages = fetch_paginated_events(app, filters, page, per_page)

    items = []
    for row in rows:
        remaining_tickets = max(row[4] - row[5], 0)
        items.append(
            {
                "id": row[0],
                "name": row[1],
                "date": row[2],
                "location": row[3],
                "capacity": row[4],
                "total_tickets": row[5],
                "remaining_tickets": remaining_tickets,
                "is_sold_out": remaining_tickets == 0,
            }
        )

    return {
        "items": items,
        "page": page,
        "per_page": per_page,
        "total_items": total_items,
        "total_pages": total_pages,
    }
