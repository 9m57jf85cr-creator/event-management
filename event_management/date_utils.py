from datetime import datetime


_INPUT_DATE_FORMATS = (
    "%Y-%m-%d",
    "%d %B %Y",
    "%d %b %Y",
)
_OUTPUT_DATE_FORMAT = "%d %b %Y"


def format_event_date(value):
    if value is None:
        return ""

    text = str(value).strip()
    if not text:
        return ""

    for fmt in _INPUT_DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).strftime(_OUTPUT_DATE_FORMAT)
        except ValueError:
            continue

    return text
