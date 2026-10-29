DEFAULT_SECRET_KEY = "dev-secret-key-change-me"
MAX_EVENT_NAME_LENGTH = 120
MAX_LOCATION_LENGTH = 120
MAX_BOOKING_NAME_LENGTH = 80
MAX_BOOKING_EMAIL_LENGTH = 254
MAX_BOOKING_PHONE_LENGTH = 20
MAX_PAYMENT_REFERENCE_LENGTH = 64
MAX_TICKETS = 100
MAX_EVENT_CAPACITY = 5000
UNLIMITED_CAPACITY = 0
BOOKING_REFERENCE_LENGTH = 10
ADD_ON_SERVICE_GROUPS = (
    {
        "slug": "catering-lunch-service",
        "title": "Catering / Lunch Service",
        "options": (
            {"id": "meal_veg_non_veg", "label": "Veg / Non-Veg meal options"},
            {"id": "snacks_refreshments", "label": "Snacks & refreshments"},
        ),
    },
    {
        "slug": "audio-visual-equipment",
        "title": "Audio / Visual Equipment",
        "options": (
            {"id": "microphone_speakers", "label": "Microphone & speaker system"},
            {"id": "projector_led_screen", "label": "Projector / LED screen"},
            {"id": "lighting_setup", "label": "Lighting setup"},
        ),
    },
    {
        "slug": "photography-videography",
        "title": "Photography & Videography",
        "options": (
            {"id": "event_photographer", "label": "Event photographer"},
            {"id": "videographer", "label": "Videographer"},
        ),
    },
    {
        "slug": "furniture-setup",
        "title": "Furniture & Setup",
        "options": (
            {"id": "chair_table_arrangement", "label": "Chair & table arrangement"},
            {"id": "stage_podium_setup", "label": "Stage/podium setup"},
        ),
    },
)
ADD_ON_SERVICE_LABELS = {
    option["id"]: option["label"]
    for group in ADD_ON_SERVICE_GROUPS
    for option in group["options"]
}

INDIA_LOCATION_KEYWORDS = (
    "india",
    "andhra pradesh",
    "arunachal pradesh",
    "assam",
    "bihar",
    "chhattisgarh",
    "goa",
    "gujarat",
    "haryana",
    "himachal pradesh",
    "jharkhand",
    "karnataka",
    "kerala",
    "madhya pradesh",
    "maharashtra",
    "manipur",
    "meghalaya",
    "mizoram",
    "nagaland",
    "odisha",
    "punjab",
    "rajasthan",
    "sikkim",
    "tamil nadu",
    "telangana",
    "tripura",
    "uttar pradesh",
    "uttarakhand",
    "west bengal",
    "andaman and nicobar",
    "chandigarh",
    "dadra and nagar haveli",
    "daman and diu",
    "delhi",
    "jammu and kashmir",
    "ladakh",
    "lakshadweep",
    "puducherry",
    "amritsar",
    "ludhiana",
    "jalandhar",
    "jalandher",
    "patiala",
    "mohali",
    "bathinda",
    "pathankot",
    "hoshiarpur",
    "kapurthala",
    "phagwara",
    "barnala",
    "moga",
    "abohar",
    "khanna",
    "sangrur",
    "gurdaspur",
    "faridkot",
    "malerkotla",
    "firozpur",
    "rupnagar",
)
