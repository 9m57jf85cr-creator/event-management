from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_styles():
    styles = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "TitleCustom",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f766e"),
            alignment=TA_CENTER,
            spaceAfter=10,
        ),
        "subtitle": ParagraphStyle(
            "SubtitleCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=10.5,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#475569"),
            spaceAfter=16,
        ),
        "heading": ParagraphStyle(
            "HeadingCustom",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14.5,
            leading=18,
            textColor=colors.HexColor("#0f766e"),
            spaceBefore=6,
            spaceAfter=8,
        ),
        "body": ParagraphStyle(
            "BodyCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            spaceAfter=8,
        ),
        "label": ParagraphStyle(
            "LabelCustom",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=10.2,
            leading=13,
            textColor=colors.HexColor("#115e59"),
            backColor=colors.HexColor("#e6fffb"),
            borderPadding=6,
            borderWidth=0.7,
            borderColor=colors.HexColor("#99f6e4"),
            borderRadius=4,
            spaceBefore=8,
            spaceAfter=6,
        ),
        "note": ParagraphStyle(
            "NoteCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=10.3,
            leading=14,
            leftIndent=10,
            borderPadding=8,
            borderColor=colors.HexColor("#99f6e4"),
            borderLeftWidth=3,
            spaceAfter=10,
        ),
    }


def add_bullets(story, bullets, body_style):
    if not bullets:
        return
    story.append(
        ListFlowable(
            [ListItem(Paragraph(item, body_style), leftIndent=8) for item in bullets],
            bulletType="bullet",
            leftIndent=18,
        )
    )
    story.append(Spacer(1, 6))


def build_pdf(output_path: Path, title: str, subtitle: str, sections: list[dict]):
    styles = build_styles()
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=1.6 * cm,
        leftMargin=1.6 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )
    story = [
        Paragraph(title, styles["title"]),
        Paragraph(subtitle, styles["subtitle"]),
    ]
    for index, section in enumerate(sections):
        story.append(Paragraph(section["title"], styles["heading"]))
        for paragraph in section.get("body", []):
            story.append(Paragraph(paragraph, styles["body"]))
        add_bullets(story, section.get("bullets", []), styles["body"])
        note = section.get("notes")
        if note:
            story.append(Paragraph("Detailed Notes", styles["label"]))
            story.append(Paragraph(note, styles["note"]))
        if section.get("page_break") and index != len(sections) - 1:
            story.append(PageBreak())
    doc.build(story)


SHORT_PPT = [
    {
        "title": "Slide 1: Title and Overview",
        "body": [
            "<b><u>College Event Management System</u></b>",
            "A web application for event creation, booking, cancellation, and admin management.",
        ],
        "notes": "This slide introduces the project. Mention that the system is designed for colleges to manage events more efficiently through a web-based platform.",
    },
    {
        "title": "Slide 2: Problem Statement",
        "bullets": [
            "Manual event handling is slow and confusing.",
            "Booking records may be lost.",
            "<b><u>No easy way to track booking activity.</u></b>",
        ],
        "notes": "Explain that traditional event handling methods create errors and waste time. This project replaces that with a digital process.",
    },
    {
        "title": "Slide 3: Objectives",
        "bullets": [
            "Manage events digitally.",
            "Allow online booking.",
            "<b><u>Generate reference codes for every booking.</u></b>",
            "Support cancellation and audit tracking.",
        ],
        "notes": "Tell the audience that the project focuses on usability, data accuracy, and better control for both users and admin.",
    },
    {
        "title": "Slide 4: Technologies Used",
        "bullets": [
            "<b><u>Frontend:</u></b> HTML, CSS, JavaScript",
            "<b><u>Backend:</u></b> Python and Flask",
            "<b><u>Database:</u></b> SQLite",
        ],
        "notes": "These tools were selected because they are practical, lightweight, and suitable for a college project.",
    },
    {
        "title": "Slide 5: Main Features",
        "bullets": [
            "Admin login and event management",
            "User booking system",
            "<b><u>Self-service booking cancellation</u></b>",
            "Email status tracking",
            "Booking audit and CSV export",
        ],
        "notes": "This is the main feature summary slide. Keep it simple and explain that the project covers the full event and booking lifecycle.",
    },
    {
        "title": "Slide 6: Booking and Validation",
        "bullets": [
            "Name, email, and phone are validated.",
            "<b><u>Invalid phone numbers are rejected.</u></b>",
            "Capacity is checked before booking is saved.",
        ],
        "notes": "Mention the recent phone validation improvement and explain that it prevents incorrect data from entering the system.",
    },
    {
        "title": "Slide 7: Security Features",
        "bullets": [
            "<b><u>CSRF protection</u></b>",
            "<b><u>Rate limiting</u></b>",
            "<b><u>API key protection</u></b>",
            "Security response headers",
        ],
        "notes": "This is a strong slide for viva. Explain that the project includes practical security features, not just basic form pages.",
    },
    {
        "title": "Slide 8: Testing and Results",
        "bullets": [
            "Booking flow tested",
            "Validation tested",
            "Email status tested",
            "<b><u>All automated tests are passing.</u></b>",
        ],
        "notes": "This proves that the application was verified properly and is not just built without checking.",
    },
    {
        "title": "Slide 9: Future Scope",
        "bullets": [
            "Payment gateway integration",
            "SMS notifications",
            "QR code tickets",
            "<b><u>Cloud deployment</u></b>",
        ],
        "notes": "Explain that the system already works well, but it can be expanded into a more advanced production-ready solution.",
    },
    {
        "title": "Slide 10: Conclusion",
        "body": [
            "<b><u>The project makes event management simple, secure, and organized.</u></b>"
        ],
        "notes": "Close by saying the system reduces manual effort, improves booking management, and creates a better user and admin experience.",
    },
]


VIVA_QA = [
    {
        "title": "Viva Question 1",
        "body": ["<b><u>What is the main aim of this project?</u></b>"],
        "notes": "The main aim of this project is to digitize college event management. It helps admin manage events and allows users to book and cancel tickets in an organized and secure way.",
    },
    {
        "title": "Viva Question 2",
        "body": ["<b><u>Which technologies are used in this project?</u></b>"],
        "notes": "The project uses HTML, CSS, and JavaScript for the frontend, Python with Flask for the backend, and SQLite as the database.",
    },
    {
        "title": "Viva Question 3",
        "body": ["<b><u>Why did you use Flask?</u></b>"],
        "notes": "Flask is lightweight, simple to understand, and well suited for small to medium web applications. It is a good choice for academic projects.",
    },
    {
        "title": "Viva Question 4",
        "body": ["<b><u>What is the role of SQLite in this project?</u></b>"],
        "notes": "SQLite stores event data, booking data, audit records, and rate limit records. It is easy to set up and works well for a local project.",
    },
    {
        "title": "Viva Question 5",
        "body": ["<b><u>How does booking work in your system?</u></b>"],
        "notes": "The user selects an event and enters details such as name, email, phone number, and number of tickets. The system validates the input, checks capacity, saves the booking, and generates a unique reference code.",
    },
    {
        "title": "Viva Question 6",
        "body": ["<b><u>What is the use of the booking reference code?</u></b>"],
        "notes": "The booking reference code is used to identify a booking. It helps users search their booking and cancel it without contacting the admin.",
    },
    {
        "title": "Viva Question 7",
        "body": ["<b><u>How did you validate phone numbers?</u></b>"],
        "notes": "The system checks that the phone number contains only valid characters, has the right digit length, and does not use a wrong plus sign format. Invalid numbers are rejected.",
    },
    {
        "title": "Viva Question 8",
        "body": ["<b><u>What security features did you add?</u></b>"],
        "notes": "The project includes CSRF protection, rate limiting for login and booking attempts, API key validation for API routes, and secure response headers.",
    },
    {
        "title": "Viva Question 9",
        "body": ["<b><u>What is the booking audit feature?</u></b>"],
        "notes": "The booking audit feature stores actions such as booking creation and cancellation. It helps admin track what happened and who performed the action.",
    },
    {
        "title": "Viva Question 10",
        "body": ["<b><u>How are emails handled in your project?</u></b>"],
        "notes": "The system can send booking confirmation emails if SMTP is configured. The delivery status is stored as sent, failed, or skipped.",
    },
    {
        "title": "Viva Question 11",
        "body": ["<b><u>How did you test your project?</u></b>"],
        "notes": "I used automated unit tests and smoke tests to verify booking flow, validation, repository logic, email status handling, and security-related behavior.",
    },
    {
        "title": "Viva Question 12",
        "body": ["<b><u>What are the future improvements?</u></b>"],
        "notes": "Future scope includes payment gateway integration, SMS alerts, QR code tickets, attendance tracking, and cloud deployment.",
    },
]


REPORT_SECTIONS = [
    {
        "title": "1. Introduction",
        "body": [
            "The <b><u>College Event Management System</u></b> is a web application developed to make event handling easier for colleges. It provides a digital platform where admin can create and manage events, and users can book or cancel tickets."
        ],
        "notes": "Use this section to explain the basic idea of the project in clear language. Mention that it reduces manual work and improves record keeping.",
    },
    {
        "title": "2. Need for the Project",
        "bullets": [
            "Manual systems are slow.",
            "Records can be lost.",
            "Capacity management is difficult.",
            "<b><u>Users need a simple self-service booking method.</u></b>",
        ],
        "notes": "This section explains why the project is useful. You can describe the common problems in manual event handling and how the system solves them.",
    },
    {
        "title": "3. Objectives",
        "bullets": [
            "Manage events online.",
            "Allow secure online booking.",
            "Validate user details.",
            "<b><u>Provide reference-based booking lookup.</u></b>",
            "Track booking history.",
        ],
        "notes": "These objectives show what the project was designed to achieve from the beginning.",
    },
    {
        "title": "4. Technologies Used",
        "bullets": [
            "HTML, CSS, JavaScript",
            "Python and Flask",
            "SQLite",
            "Python unittest",
        ],
        "notes": "Keep this simple in viva. Mention that the stack is lightweight and appropriate for an academic project.",
    },
    {
        "title": "5. System Architecture",
        "body": [
            "The project follows a layered structure: <b><u>Templates -> Routes -> Services -> Repositories -> Database</u></b>."
        ],
        "notes": "Explain that each layer has a separate responsibility. This improves readability and maintainability.",
    },
    {
        "title": "6. Main Modules",
        "bullets": [
            "Admin module",
            "User booking module",
            "My bookings module",
            "Audit module",
            "Security module",
        ],
        "notes": "This section summarizes the major functional parts of the application.",
    },
    {
        "title": "7. Booking Flow",
        "body": [
            "When a user books an event, the system validates name, email, phone number, and ticket count. It then checks capacity, saves the booking, generates a unique reference code, and records the email status."
        ],
        "notes": "This is one of the most important sections. Explain the flow step by step in simple words.",
    },
    {
        "title": "8. Phone Number Validation",
        "body": [
            "<b><u>The system rejects invalid phone numbers and accepts only proper valid numbers.</u></b>"
        ],
        "bullets": [
            "Short numbers are rejected.",
            "Letters are rejected.",
            "Wrong plus sign format is rejected.",
            "Extremely long numbers are rejected.",
        ],
        "notes": "This is a recent fix and a good point to highlight because it shows practical validation work.",
    },
    {
        "title": "9. Email Handling",
        "body": [
            "The system supports booking confirmation email delivery. The delivery status is stored as sent, failed, or skipped."
        ],
        "notes": "Mention that actual email sending needs SMTP settings in the environment file.",
    },
    {
        "title": "10. Security Features",
        "bullets": [
            "<b><u>CSRF protection</u></b>",
            "<b><u>Login and booking rate limiting</u></b>",
            "<b><u>API key protection</u></b>",
            "Security headers",
        ],
        "notes": "This section makes your project stand out because it shows secure coding practices.",
    },
    {
        "title": "11. Testing",
        "body": [
            "The project was tested using automated tests. Booking flow, validation, repository logic, and smoke tests were executed successfully."
        ],
        "notes": "Mention that the full test suite passes, which proves the project is stable.",
    },
    {
        "title": "12. Conclusion",
        "body": [
            "<b><u>The project successfully provides a simple, secure, and useful event management system for college use.</u></b>"
        ],
        "notes": "Close the report by saying the project solves manual event management problems in a practical way.",
    },
]


if __name__ == "__main__":
    build_pdf(
        PROJECT_ROOT / "project_short_ppt.pdf",
        "College Event Management System",
        "Short 10-slide presentation version with key points and speaker notes.",
        SHORT_PPT,
    )
    build_pdf(
        PROJECT_ROOT / "project_viva_questions_answers.pdf",
        "College Event Management System Viva Questions and Answers",
        "Simple answers in easy language for viva preparation.",
        VIVA_QA,
    )
    build_pdf(
        PROJECT_ROOT / "project_report_simple.pdf",
        "College Event Management System Project Report",
        "Simple detailed report with important points highlighted.",
        REPORT_SECTIONS,
    )
    print("Created project_short_ppt.pdf")
    print("Created project_viva_questions_answers.pdf")
    print("Created project_report_simple.pdf")
