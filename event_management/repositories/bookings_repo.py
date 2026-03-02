from ..db import get_db_connection


def _booking_where(query, status_filter):
    where_parts = []
    params = []
    if query:
        where_parts.append(
            "(e.name LIKE ? OR b.user_name LIKE ? OR b.user_email LIKE ? OR b.user_phone LIKE ?)"
        )
        pattern = f"%{query}%"
        params.extend([pattern, pattern, pattern, pattern])
    if status_filter:
        where_parts.append("b.confirmation_email_status = ?")
        params.append(status_filter)

    where_clause = ""
    if where_parts:
        where_clause = "WHERE " + " AND ".join(where_parts)
    return where_clause, params


def fetch_my_bookings_by_reference(app, reference_code):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT b.id, e.name, b.user_name, b.user_email, b.user_phone, b.tickets, b.created_at, b.reference_code
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        WHERE b.reference_code = ?
        ORDER BY b.created_at DESC, b.id DESC
        """,
        (reference_code,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def fetch_booking_for_self_cancel(cursor, reference_code):
    cursor.execute(
        """
        SELECT b.id, b.reference_code, b.user_name, b.user_email, e.name
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        WHERE b.reference_code = ?
        """,
        (reference_code,),
    )
    return cursor.fetchone()


def fetch_admin_bookings_page(app, query, status_filter, order_by_sql, page, per_page):
    where_clause, params = _booking_where(query, status_filter)

    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        {where_clause}
        """,
        params,
    )
    total_items = cursor.fetchone()[0]
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    cursor.execute(
        f"""
        SELECT
            b.id,
            e.name,
            b.user_name,
            b.user_email,
            b.user_phone,
            b.confirmation_email_status,
            b.confirmation_email_error,
            b.tickets,
            b.created_at,
            b.reference_code
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        {where_clause}
        ORDER BY {order_by_sql}
        LIMIT ? OFFSET ?
        """,
        params + [per_page, offset],
    )
    rows = cursor.fetchall()
    conn.close()
    return rows, page, total_pages


def fetch_booking_for_admin_cancel(cursor, booking_id):
    cursor.execute(
        """
        SELECT b.id, b.reference_code, b.user_name, b.user_email, e.name
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        WHERE b.id = ?
        """,
        (booking_id,),
    )
    return cursor.fetchone()


def fetch_booking_for_resend(app, booking_id):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            b.id,
            b.user_name,
            b.user_email,
            b.reference_code,
            b.tickets,
            e.name,
            e.date,
            e.location
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        WHERE b.id = ?
        """,
        (booking_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def fetch_bookings_for_csv(app, query, status_filter, order_by_sql):
    where_clause, params = _booking_where(query, status_filter)

    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT b.id, e.name, b.user_name, b.user_email, b.user_phone, b.tickets, b.created_at, b.reference_code
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        {where_clause}
        ORDER BY {order_by_sql}
        """,
        params,
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def fetch_audit_rows(app, filters, include_id):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    select_cols = "id, booking_id, reference_code, action, actor, created_at" if include_id else "booking_id, reference_code, action, actor, created_at"
    cursor.execute(
        f"""
        SELECT {select_cols}
        FROM booking_audit
        {filters['where_clause']}
        ORDER BY created_at DESC, id DESC
        """,
        filters["params"],
    )
    rows = cursor.fetchall()
    conn.close()
    return rows
