# Presentation Guide

## One-line demo start

```bash
make demo-8000
```

Open `http://127.0.0.1:8000`

## Easy way to explain the project

This is a Flask-based college event management system.

The app has 4 simple layers:

1. `templates/` and `static/`
   These files handle what users see in the browser.

2. `event_management/blueprints/`
   These files handle incoming requests such as login, event management, bookings, and API calls.

3. `event_management/services/`
   These files contain the main business logic, like creating bookings, checking capacity, and sending confirmation emails.

4. `event_management/repositories/`
   These files talk directly to the database and run SQL queries.

## Easy file-by-file explanation

- [`app.py`](/Users/sonamchosket/Desktop/event-management/app.py)
  Simple entry file that starts the app.

- [`event_management/webapp.py`](/Users/sonamchosket/Desktop/event-management/event_management/webapp.py)
  Builds the Flask app, loads config, registers routes, and initializes the database.

- [`event_management/blueprints/auth.py`](/Users/sonamchosket/Desktop/event-management/event_management/blueprints/auth.py)
  Admin login and logout.

- [`event_management/blueprints/events.py`](/Users/sonamchosket/Desktop/event-management/event_management/blueprints/events.py)
  Home page, add/edit/delete events, and event booking.

- [`event_management/blueprints/bookings.py`](/Users/sonamchosket/Desktop/event-management/event_management/blueprints/bookings.py)
  My bookings, admin booking management, cancellation, and CSV export.

- [`event_management/services/booking_service.py`](/Users/sonamchosket/Desktop/event-management/event_management/services/booking_service.py)
  Handles booking creation, cancellation, and email resend logic.

- [`event_management/services/event_service.py`](/Users/sonamchosket/Desktop/event-management/event_management/services/event_service.py)
  Prepares event data for display, including ticket availability.

## Short presentation script

You can explain the flow like this:

1. The user opens the home page and sees available events.
2. Flask routes in the blueprints receive the request.
3. Service files apply business rules like capacity checks.
4. Repository files save and fetch data from SQLite.
5. The result is sent back to the template and shown in the browser.

## Best 30-second summary

"This project is a Flask web application for managing college events. I separated it into routes, services, and repositories so the code is easier to maintain and explain. Routes handle requests, services contain the business logic, and repositories handle the database operations."
