from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = PROJECT_ROOT / "project_presentation_notes.pdf"


SLIDES = [
    {
        "title": "Slide 1: Title",
        "body": [
            "<b><u>College Event Management System</u></b>",
            "Presented by: Your Name",
            "Course / Semester / College Name",
        ],
        "notes": (
            "This project is a web-based application developed to manage college events in an organized "
            "and secure way. It allows the admin to create and manage events, and it allows users to book "
            "tickets, check booking details, and cancel bookings using a reference code."
        ),
    },
    {
        "title": "Slide 2: Introduction",
        "bullets": [
            "<b><u>Admin can create, edit, and delete events.</u></b>",
            "<b><u>Users can book tickets online.</u></b>",
            "<b><u>Users can search and cancel bookings using a unique reference code.</u></b>",
        ],
        "notes": (
            "The aim of this project is to reduce manual work and make event handling faster, safer, "
            "and easier. The whole flow from event publishing to booking and cancellation is available "
            "in one system."
        ),
    },
    {
        "title": "Slide 3: Problem Statement",
        "bullets": [
            "Manual event handling is slow.",
            "Booking records can be lost or duplicated.",
            "Students do not have a self-service booking system.",
            "<b><u>There is no clear audit history in manual systems.</u></b>",
        ],
        "notes": (
            "In many colleges, event information is handled through notebooks, spreadsheets, or messages. "
            "This causes confusion, incorrect counts, and difficulty in tracking bookings. This project "
            "solves those issues through a centralized application."
        ),
    },
    {
        "title": "Slide 4: Objectives",
        "bullets": [
            "Create a simple event management website.",
            "Allow booking with validation.",
            "<b><u>Generate unique booking reference codes.</u></b>",
            "Support self-cancellation and admin cancellation.",
            "Add security and testing.",
        ],
        "notes": (
            "The project was built not only to manage events, but also to show practical software "
            "engineering features like validation, security hooks, audit tracking, and automated tests."
        ),
    },
    {
        "title": "Slide 5: Proposed Solution",
        "body": [
            "The proposed solution is a <b><u>Flask-based web application</u></b> with event management, "
            "booking, cancellation, security, and audit features."
        ],
        "notes": (
            "The project uses Flask for the backend, SQLite for the database, and HTML, CSS, and "
            "JavaScript for the frontend. This makes the system lightweight, practical, and easy to run locally."
        ),
    },
    {
        "title": "Slide 6: Technologies Used",
        "bullets": [
            "<b><u>Frontend:</u></b> HTML, CSS, JavaScript",
            "<b><u>Backend:</u></b> Python, Flask",
            "<b><u>Database:</u></b> SQLite",
            "<b><u>Testing:</u></b> Python unittest",
        ],
        "notes": (
            "These technologies were chosen because they are simple, effective, and suitable for an academic "
            "project. Python and Flask are easy to understand, while SQLite is perfect for lightweight storage."
        ),
    },
    {
        "title": "Slide 7: System Modules",
        "bullets": [
            "<b><u>Admin Module</u></b>: login, add event, edit event, delete event, view bookings.",
            "<b><u>User Module</u></b>: view events, book tickets, search booking, cancel booking.",
            "<b><u>Security Module</u></b>: CSRF, API key, rate limit, headers.",
            "<b><u>Audit Module</u></b>: track booking create and cancel actions.",
        ],
        "notes": (
            "The project is divided into clear modules so each part of the application has a separate "
            "responsibility. This improves maintainability and makes the code easier to explain during viva."
        ),
    },
    {
        "title": "Slide 8: Architecture",
        "body": ["<b><u>Templates -> Routes -> Services -> Repositories -> Database</u></b>"],
        "notes": (
            "The frontend sends a request to Flask routes. The service layer handles business logic, "
            "the repository layer performs SQL queries, and the database stores the final data. "
            "This layered design keeps the application organized."
        ),
    },
    {
        "title": "Slide 9: Main Features",
        "bullets": [
            "Admin login",
            "Event creation and management",
            "Capacity management",
            "<b><u>Booking with reference code</u></b>",
            "Self-service cancellation",
            "Email confirmation status",
            "Audit and CSV export",
        ],
        "notes": (
            "This project is more than a basic CRUD app. It includes reference-based search, email tracking, "
            "admin reports, and audit records, which make it more complete and realistic."
        ),
    },
    {
        "title": "Slide 10: Database Tables",
        "bullets": [
            "<b><u>events</u></b>: stores event details.",
            "<b><u>bookings</u></b>: stores booking details and reference code.",
            "<b><u>booking_audit</u></b>: stores booking actions.",
            "<b><u>request_rate_limit</u></b>: stores rate limit data.",
        ],
        "notes": (
            "The database structure is simple but effective. It supports event records, booking records, "
            "action history, and request protection."
        ),
    },
    {
        "title": "Slide 11: Home Page",
        "body": [
            "The home page displays all available events with their date, location, capacity, and remaining tickets."
        ],
        "notes": (
            "This page acts as the main dashboard. Users can see event information clearly, and admin can "
            "also add events from the same interface."
        ),
    },
    {
        "title": "Slide 12: Admin Login",
        "bullets": [
            "Secure login form",
            "<b><u>Invalid credential protection</u></b>",
            "<b><u>Rate limiting for repeated login attempts</u></b>",
        ],
        "notes": (
            "The admin module is protected so only authorized users can manage the system. Session handling "
            "is used to maintain secure admin access after successful login."
        ),
    },
    {
        "title": "Slide 13: Add Event",
        "bullets": [
            "Admin enters event name, date, location, and capacity.",
            "Empty fields are rejected.",
            "Past dates are rejected.",
            "<b><u>Location validation is applied.</u></b>",
        ],
        "notes": (
            "This validation ensures that wrong or low-quality event data is not stored in the system. "
            "It improves data quality and reduces future booking issues."
        ),
    },
    {
        "title": "Slide 14: Book Event",
        "bullets": [
            "User enters name, email, phone, tickets, and payment method.",
            "<b><u>Booking is accepted only if capacity is available.</u></b>",
            "A unique reference code is generated after success.",
        ],
        "notes": (
            "The booking flow verifies user input, checks event capacity, stores the booking, creates an audit "
            "entry, and records the email notification status."
        ),
    },
    {
        "title": "Slide 15: Phone Number Validation",
        "bullets": [
            "<b><u>Wrong phone numbers are rejected and only valid numbers are accepted.</u></b>",
            "Letters are rejected.",
            "Very short and very long numbers are rejected.",
            "Wrong plus sign format is rejected.",
            "Both web form and API use the same validation logic.",
        ],
        "notes": (
            "This was an important improvement in the project. The system now checks structure and digit count "
            "so only proper phone numbers are stored."
        ),
    },
    {
        "title": "Slide 16: Booking Reference Code",
        "body": ["<b><u>Each booking gets a unique 10-character reference code.</u></b>"],
        "notes": (
            "This code is used for searching a booking later and for self-service cancellation. It removes "
            "the need for users to contact admin for basic booking actions."
        ),
    },
    {
        "title": "Slide 17: My Bookings Module",
        "body": ["Users can search their booking using the reference code and see full details."],
        "notes": (
            "This module is useful because users can independently verify their booking, payment method, "
            "number of tickets, and reference code."
        ),
    },
    {
        "title": "Slide 18: Cancellation Flow",
        "bullets": [
            "<b><u>Self-service cancel</u></b> by user using reference code.",
            "<b><u>Admin cancel</u></b> from booking panel.",
            "Cancellation creates an audit record.",
        ],
        "notes": (
            "The cancellation feature handles the complete booking lifecycle. When a booking is cancelled, "
            "the action is also recorded for admin monitoring."
        ),
    },
    {
        "title": "Slide 19: Email Notification",
        "bullets": [
            "Booking confirmation email can be sent.",
            "Email status can be <b><u>sent</u></b>, <b><u>failed</u></b>, or <b><u>skipped</u></b>.",
            "The system clearly reports this status.",
        ],
        "notes": (
            "The project tracks whether the confirmation email was sent successfully. Real email delivery "
            "requires SMTP settings in the environment file."
        ),
    },
    {
        "title": "Slide 20: Booking Audit",
        "body": ["<b><u>Audit history stores booking creation and cancellation actions.</u></b>"],
        "notes": (
            "This feature improves transparency. Admin can review what happened, when it happened, and who "
            "performed the action."
        ),
    },
    {
        "title": "Slide 21: Security Features",
        "bullets": [
            "<b><u>CSRF protection</u></b>",
            "<b><u>Rate limiting</u></b>",
            "<b><u>API key validation</u></b>",
            "<b><u>Security headers</u></b>",
        ],
        "notes": (
            "Security is a strong part of this project. The app uses CSRF tokens for forms, request limiting "
            "for login and booking attempts, API key checks for API endpoints, and secure browser headers."
        ),
    },
    {
        "title": "Slide 22: API Support",
        "body": [
            "The application includes API endpoints for event listing, health check, and booking creation."
        ],
        "notes": (
            "This makes the system future-ready. If needed, the same backend can later be connected to a "
            "mobile app or another frontend."
        ),
    },
    {
        "title": "Slide 23: Testing",
        "bullets": [
            "<b><u>Automated tests were added and all tests are passing.</u></b>",
            "Booking flow tests",
            "Validation tests",
            "Email status tests",
            "Repository and smoke tests",
        ],
        "notes": (
            "Testing is important because it proves the project works correctly. The application was checked "
            "using unit tests and smoke tests, and the complete suite passed successfully."
        ),
    },
    {
        "title": "Slide 24: Challenges and Fixes",
        "bullets": [
            "Phone validation issue fixed.",
            "Email status feedback improved.",
            "<b><u>Outdated test dates were corrected.</u></b>",
        ],
        "notes": (
            "During development, some issues appeared in booking validation and test stability. These were "
            "solved by creating shared validation logic, clearer booking messages, and better date handling."
        ),
    },
    {
        "title": "Slide 25: Outcome",
        "body": [
            "The project is now in a strong working condition with booking, cancellation, audit, security, and testing support."
        ],
        "notes": (
            "This system is practical for college event operations because it combines usability, security, "
            "and manageability in one application."
        ),
    },
    {
        "title": "Slide 26: Future Scope",
        "bullets": [
            "Payment gateway integration",
            "SMS notifications",
            "QR code tickets",
            "Attendance tracking",
            "<b><u>Cloud deployment</u></b>",
        ],
        "notes": (
            "The current system already covers the main workflow, but future improvements can make it even "
            "more powerful and real-world ready."
        ),
    },
    {
        "title": "Slide 27: Conclusion",
        "body": [
            "<b><u>The College Event Management System makes event handling simple, secure, and organized.</u></b>"
        ],
        "notes": (
            "In conclusion, this project successfully solves the problem of manual event management. "
            "It helps the admin manage events more efficiently and gives users a better booking experience."
        ),
    },
    {
        "title": "Slide 28: Thank You",
        "body": ["Thank You", "Questions and Answers"],
        "notes": (
            "You can close your presentation by thanking the audience and inviting questions. If asked about "
            "the strongest part of the project, mention security, booking reference code, and self-service cancellation."
        ),
    },
]


def build_pdf():
    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=A4,
        rightMargin=1.6 * cm,
        leftMargin=1.6 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f766e"),
        alignment=TA_CENTER,
        spaceAfter=10,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["BodyText"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#475569"),
        fontSize=10.5,
        leading=14,
        spaceAfter=18,
    )
    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0f766e"),
        spaceAfter=8,
        spaceBefore=8,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        spaceAfter=8,
    )
    notes_label_style = ParagraphStyle(
        "NotesLabel",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13,
        textColor=colors.HexColor("#115e59"),
        backColor=colors.HexColor("#e6fffb"),
        borderPadding=6,
        borderWidth=0.7,
        borderColor=colors.HexColor("#99f6e4"),
        borderRadius=4,
        spaceBefore=8,
        spaceAfter=6,
    )
    notes_style = ParagraphStyle(
        "Notes",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10.3,
        leading=14,
        leftIndent=10,
        borderPadding=8,
        borderColor=colors.HexColor("#99f6e4"),
        borderLeftWidth=3,
        spaceAfter=10,
    )

    story = [
        Paragraph("College Event Management System", title_style),
        Paragraph(
            "Detailed PPT content with <b>important points in bold</b> and <u>underlined emphasis</u>.",
            subtitle_style,
        ),
    ]

    for index, slide in enumerate(SLIDES):
        story.append(Paragraph(slide["title"], heading_style))

        for line in slide.get("body", []):
            story.append(Paragraph(line, body_style))

        bullets = slide.get("bullets", [])
        if bullets:
            flowable = ListFlowable(
                [
                    ListItem(Paragraph(item, body_style), leftIndent=8)
                    for item in bullets
                ],
                bulletType="bullet",
                start="circle",
                leftIndent=18,
            )
            story.append(flowable)
            story.append(Spacer(1, 6))

        story.append(Paragraph("Detailed Notes", notes_label_style))
        story.append(Paragraph(slide["notes"], notes_style))

        if index != len(SLIDES) - 1:
            story.append(Spacer(1, 6))

    doc.build(story)


if __name__ == "__main__":
    build_pdf()
    print(f"Created {OUTPUT_PATH}")
