from ..db import get_db_connection


def fetch_paginated_events(app, filters, page, per_page):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM events e
        {filters['where_clause']}
        """,
        filters["params"],
    )
    total_items = cursor.fetchone()[0]
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    cursor.execute(
        f"""
        SELECT e.id, e.name, e.date, e.location, e.capacity, COALESCE(SUM(b.tickets), 0) AS total_tickets
        FROM events e
        LEFT JOIN bookings b ON e.id = b.event_id
        {filters['where_clause']}
        GROUP BY e.id, e.name, e.date, e.location, e.capacity
        ORDER BY e.date, e.id
        LIMIT ? OFFSET ?
        """,
        filters["params"] + [per_page, offset],
    )
    rows = cursor.fetchall()
    conn.close()
    return rows, page, total_items, total_pages


def create_event(app, name, date, location, capacity):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO events (name, date, location, capacity) VALUES (?, ?, ?, ?)",
        (name, date, location, capacity),
    )
    conn.commit()
    conn.close()


def delete_event(app, event_id):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM events WHERE id = ?", (event_id,))
    exists = cursor.fetchone() is not None
    if not exists:
        conn.close()
        return False

    cursor.execute("DELETE FROM events WHERE id = ?", (event_id,))
    conn.commit()
    conn.close()
    return True


def fetch_event_for_edit(app, event_id):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, date, location, capacity FROM events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return None
    return {"id": row[0], "name": row[1], "date": row[2], "location": row[3], "capacity": row[4]}


def update_event(app, event_id, name, date, location, capacity):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE events SET name = ?, date = ?, location = ?, capacity = ? WHERE id = ?",
        (name, date, location, capacity, event_id),
    )
    conn.commit()
    conn.close()


def fetch_event_with_totals(app, event_id):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT e.id, e.name, e.date, e.location, e.capacity, COALESCE(SUM(b.tickets), 0) AS total_tickets
        FROM events e
        LEFT JOIN bookings b ON e.id = b.event_id
        WHERE e.id = ?
        GROUP BY e.id, e.name, e.date, e.location, e.capacity
        """,
        (event_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def fetch_capacity_totals_for_update(cursor, event_id):
    cursor.execute(
        """
        SELECT e.capacity, COALESCE(SUM(b.tickets), 0) AS total_tickets
        FROM events e
        LEFT JOIN bookings b ON e.id = b.event_id
        WHERE e.id = ?
        GROUP BY e.id, e.capacity
        """,
        (event_id,),
    )
    return cursor.fetchone()
