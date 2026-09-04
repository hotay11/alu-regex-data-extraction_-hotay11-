import re
import json
from pathlib import Path

EMAIL_PATTERN = (
    r"\b[A-Za-z0-9_%+-]+(?:\.[A-Za-z0-9_%+-]+)*"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"
)

PHONE_PATTERN = (
    r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?"      
    r"(?:\(?\d{2,4}\)?[-.\s]?)?"           
    r"\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}" 
    r"(?!\d)"
)

URL_PATTERN = (
    r"https?://[A-Za-z0-9.-]+"
    r"(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?"
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
    """Returns unique matches found using a regular expression."""
    matches = re.findall(pattern, text, re.IGNORECASE)
    return list(dict.fromkeys(matches))

def validate_alu_email(email):
    """Checks whether an email belongs to an approved ALU domain."""
    return email.lower().endswith(ALU_DOMAINS)

def mask_card(card):
    """Hides all credit-card digits except the final four."""
    digits = re.sub(r"\D", "", card)
    return "**** **** **** " + digits[-4:]

def mask_email(email):
    """Hides the important part of the email that conatins personal info"""
    local, _, domain = email.partition("@")
    if len(local) <= 1:
        return f"{local}***@{domain}"
    return f"{local[0]}***@{domain}"

def is_well_formed_email(email, full_text):
    if ".." in email or email.startswith(".") or email.startswith("@"):
        return False
    idx = full_text.find(email)
    if idx > 0 and full_text[idx - 1] in ".@":
        return False
    return True

def is_plausible_phone(number):
    digit_count = sum(c.isdigit() for c in number)
    return 7 <= digit_count <= 15
    

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

def filter_suspicious_lines(text):
    clean_lines = []
    suspicious_found = False
    for line in text.splitlines():
        if contains_suspicious_content(line):
            suspicious_found = True
            continue
        clean_lines.append(line)
    return "\n".join(clean_lines), suspicious_found

def main():
    input_file = Path("input/raw-text.txt")
    output_file = Path("output/sample-output.json")

    text = input_file.read_text(encoding="utf-8")

    clean_text, suspicious = filter_suspicious_lines(text)
    
    emails = [e for e in extract_data(EMAIL_PATTERN, clean_text)
              if is_well_formed_email(e, clean_text)]
    urls = extract_data(URL_PATTERN, clean_text)
    phones = [p for p in extract_data(PHONE_PATTERN, clean_text)
              if is_plausible_phone(p)]
    cards = extract_data(CARD_PATTERN, clean_text)

    alu_emails = [
        email for email in emails
        if validate_alu_email(email)
    ]

    masked_cards = [mask_card(card) for card in cards]
    masked_emails = [mask_email(e) for e in emails]
    masked_alu_emails = [mask_email(e) for e in alu_emails]

    results = {
        "security": {
            "suspicious_content_detected": suspicious,
            "input_trusted": not suspicious
        },
        "emails": masked_emails,
        "alu_emails": masked_alu_emails,
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
