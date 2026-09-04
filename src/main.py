import re
import json
from pathlib import path

EMAIL_PATTERN = (
    r"\b[A-Za-z0-9_%+-]+(?:\.[A-Za-z0-9_%+-]+)*"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"
)

URL_PATTERN = (
    r"https?://[A-Za-z0-9.-]+"
    r"(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?"
)

PHONE_PATTERN = (
    r"(?<!\d)(?:\+255[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{3}"
    r"|0\d{3}[-\s]?\d{3}[-\s]?\d{3})(?!\d)"
)

CARD_PATTERN = (
    r"(?<!\d)(?:\d{4}[-\s]?){3}\d{4}(?!\d)"
)

ALU_DOMAINS = (
    "@alueducation.com",
    "@alumni.alueducation.com",
    "@si.alueducation.com"
)

def extract_data(pattern, text):
    """Return unique matches found using a regular expression."""
    matches = re.findall(pattern, text, re.IGNORECASE)
    return list(dict.fromkeys(matches))

def validate_alu_email(email):
    """Check whether an email belongs to an approved ALU domain."""
    return email.lower().endswith(ALU_DOMAINS)

def mask_card(card):
    """Hide all credit-card digits except the final four."""
    digits = re.sub(r"\D", "", card)
    return "**** **** **** " + digits[-4:]

SUSPICIOUS_PATTERNS = [
    r"<script\b",
    r"</script>",
    r"ignore\s+all\s+previous\s+instructions",
    r"drop\s+table",
    r"union\s+select",
]

def contains_suspicious_content(text):
    """Detect common injection-like or unsafe content."""
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def main():
    input_file = Path("input/raw-text.txt")
    output_file = Path("output/sample-output.json")

    text = input_file.read_text(encoding="utf-8")

    suspicious = contains_suspicious_content(text)

    emails = extract_data(EMAIL_PATTERN, text)
    urls = extract_data(URL_PATTERN, text)
    phones = extract_data(PHONE_PATTERN, text)
    cards = extract_data(CARD_PATTERN, text)

    alu_emails = [
        email for email in emails
        if validate_alu_email(email)
    ]

    masked_cards = [mask_card(card) for card in cards]

    results = {
        "security": {
            "suspicious_content_detected": suspicious,
            "input_trusted": not suspicious
        },
        "emails": emails,
        "alu_emails": alu_emails,
        "urls": urls,
        "phone_numbers": phones,
        "credit_cards": masked_cards
    }

    output_file.parent.mkdir(exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print("Data extraction completed.")
    print(f"Emails found: {len(emails)}")
    print(f"ALU emails found: {len(alu_emails)}")
    print(f"URLs found: {len(urls)}")
    print(f"Phone numbers found: {len(phones)}")
    print(f"Credit cards found: {len(cards)}")
    print(f"Suspicious content detected: {suspicious}")

if __name__ == "__main__":
    main()
