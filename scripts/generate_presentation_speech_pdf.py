from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = PROJECT_ROOT / "project_presentation_speech_clean.pdf"

SECTIONS = [
    (
        "Slide 1: Introduction",
        "Good morning everyone. My project title is <b><u>College Event Management System</u></b>. "
        "This project is a web-based application that helps manage college events in a simple, secure, and organized way.",
    ),
    (
        "Slide 2: Problem Statement",
        "In many colleges, event management is done manually. This creates problems like lost records, confusion in booking, "
        "and difficulty in tracking event details. So, I developed this system to make the whole process digital.",
    ),
    (
        "Slide 3: Objective",
        "The main objective of my project is to help admin manage events easily and allow users to book and cancel tickets online. "
        "Another objective is to improve security, validation, and proper record keeping.",
    ),
    (
        "Slide 4: Technologies Used",
        "In this project, I used <b><u>HTML, CSS, and JavaScript</u></b> for frontend, "
        "<b><u>Python Flask</u></b> for backend, and <b><u>SQLite</u></b> for database. "
        "These technologies are simple and suitable for web application development.",
    ),
    (
        "Slide 5: Main Features",
        "The main features of my project are admin login, add, edit, and delete event, user booking system, "
        "booking reference code, self-service cancellation, booking audit, and email confirmation status.",
    ),
    (
        "Slide 6: Booking Flow",
        "In the booking process, the user selects an event and enters name, email, phone number, and ticket count. "
        "The system validates the input, checks available capacity, saves the booking, and generates a unique reference code.",
    ),
    (
        "Slide 7: Phone Validation",
        "One important improvement in my project is <b><u>phone number validation</u></b>. "
        "Now the system rejects invalid phone numbers and accepts only valid phone numbers. "
        "This improves data accuracy and prevents wrong booking entries.",
    ),
    (
        "Slide 8: Security Features",
        "I added security features like <b><u>CSRF protection</u></b>, <b><u>rate limiting</u></b>, "
        "<b><u>API key protection</u></b>, and <b><u>security headers</u></b>. "
        "These features help protect the application from misuse.",
    ),
    (
        "Slide 9: Audit and Email Status",
        "The project also stores booking audit history. This means admin can see when a booking was created or cancelled. "
        "The project also tracks whether booking confirmation email was sent, failed, or skipped.",
    ),
    (
        "Slide 10: Testing",
        "I tested the project using automated tests. The booking flow, validation, and other features were checked, "
        "and all tests are passing successfully.",
    ),
    (
        "Slide 11: Future Scope",
        "In future, this project can be improved by adding payment gateway, SMS notifications, QR code tickets, "
        "attendance system, and cloud deployment.",
    ),
    (
        "Slide 12: Conclusion",
        "In conclusion, my project provides a simple and secure solution for college event management. "
        "It reduces manual work, improves booking handling, and gives better control to both admin and users.",
    ),
    (
        "Slide 13: Thank You",
        "Thank you. I am ready for questions.",
    ),
]


def build_pdf():
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleCustom",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f766e"),
        alignment=TA_CENTER,
        spaceAfter=8,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleCustom",
        parent=styles["BodyText"],
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#475569"),
        alignment=TA_CENTER,
        spaceAfter=16,
    )
    heading_style = ParagraphStyle(
        "HeadingCustom",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0f766e"),
        spaceBefore=8,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyCustom",
        parent=styles["BodyText"],
        fontSize=11,
        leading=15,
        spaceAfter=8,
    )

    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=A4,
        rightMargin=1.6 * cm,
        leftMargin=1.6 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    story = [
        Paragraph("College Event Management System", title_style),
        Paragraph("Viva and PPT Speaking Script", subtitle_style),
    ]

    for title, text in SECTIONS:
        story.append(Paragraph(title, heading_style))
        story.append(Paragraph(text, body_style))
        story.append(Spacer(1, 4))

    doc.build(story)


if __name__ == "__main__":
    build_pdf()
    print(f"Created {OUTPUT_PATH}")
