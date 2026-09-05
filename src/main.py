```python
import re
import json
from pathlib import Path


# Patterns for finding email addresses
EMAIL_PATTERN = (
    r"\b[A-Za-z0-9_%+-]+(?:\.[A-Za-z0-9_%+-]+)*"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"
)


# Patterns for finding phone numbers in different formats
PHONE_PATTERN = (
    r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?"
    r"(?:\(?\d{2,4}\)?[-.\s]?)?"
    r"\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}"
    r"(?!\d)"
)


# Patterns for finding HTTP and HTTPS URLs
URL_PATTERN = (
    r"https?://[A-Za-z0-9.-]+"
    r"(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?"
)


# Patterns for finding credit card numbers with spaces or hyphens
CARD_PATTERN = (
    r"(?<!\d)(?:\d{4}[-\s]?){3}\d{4}(?!\d)"
)


# ALU email domains that the assignment requires
ALU_DOMAINS = (
    "@alueducation.com",
    "@alumni.alueducation.com",
    "@si.alueducation.com"
)


def extract_data(pattern, text):
    """Returns unique matches found using a regular expression."""

    # Finds all matches and remove duplicates
    matches = re.findall(pattern, text, re.IGNORECASE)
    return list(dict.fromkeys(matches))


def validate_alu_email(email):
    """Checks whether an email belongs to an approved ALU domain."""

    # Checks if the email ends with one of the ALU domains
    return email.lower().endswith(ALU_DOMAINS)


def mask_card(card):
    """Hides all credit-card digits except the final four."""

    # Removes spaces and symbols, then keep only the last four digits
    digits = re.sub(r"\D", "", card)
    return "**** **** **** " + digits[-4:]


def mask_email(email):
    """Hides part of the email to protect personal information."""

    # Keeps the first letter and hide the rest of the username
    local, _, domain = email.partition("@")

    if len(local) <= 1:
        return f"{local}***@{domain}"

    return f"{local[0]}***@{domain}"


def is_well_formed_email(email, start_idx, full_text):

    #Reject some common malformed email formats
    if ".." in email or email.startswith(".") or email.startswith("@"):
        return False
    if start_idx > 0 and full_text[start_idx - 1] in ".@":
        return False
    return True

def is_plausible_phone(number):

    # Checks the number of digits and whether it starts in a valid way
    digit_count = sum(c.isdigit() for c in number)
    starts_right = number.strip().startswith(("+", "0"))

    return starts_right and 7 <= digit_count <= 15


# Patterns used to identify some suspicious or unsafe input
SUSPICIOUS_PATTERNS = [
    r"<script\b",
    r"</script>",
    r"ignore\s+all\s+previous\s+instructions",
    r"drop\s+table",
    r"union\s+select",
]


def contains_suspicious_content(text):
    """Detect common injection-like or unsafe content."""

    # Checks whether the text contains any suspicious pattern
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def filter_suspicious_lines(text):
    # Removes lines that contain suspicious content
    clean_lines = []
    suspicious_found = False

    for line in text.splitlines():
        if contains_suspicious_content(line):
            suspicious_found = True
            continue

        clean_lines.append(line)

    return "\n".join(clean_lines), suspicious_found


def main():

    # Sets the input and output file locations
    input_file = Path("input/raw-text.txt")
    output_file = Path("output/sample-output.json")

    # Reads the raw text from the input file
    text = input_file.read_text(encoding="utf-8")

    # Checks the input before extracting any information
    clean_text, suspicious = filter_suspicious_lines(text)

    # Extracts and validate email addresses
    emails = []
for match in re.finditer(EMAIL_PATTERN, clean_text, re.IGNORECASE):
    email = match.group()
    if is_well_formed_email(email, match.start(), clean_text):
        if email not in emails:      
            emails.append(email)
    
    # Extracts URLs
    urls = extract_data(URL_PATTERN, clean_text)

    # Extracts and validates phone numbers
    phones = [p for p in extract_data(PHONE_PATTERN, clean_text)
              if is_plausible_phone(p)]

    # Extracts credit card numbers
    cards = extract_data(CARD_PATTERN, clean_text)

    # Finds the emails that belong to ALU
    alu_emails = [
        email for email in emails
        if validate_alu_email(email)
    ]

    # Masks sensitive information before putting it in the output
    masked_cards = [mask_card(card) for card in cards]
    masked_emails = [mask_email(e) for e in emails]
    masked_alu_emails = [mask_email(e) for e in alu_emails]

    # Organises all the results into one JSON structure
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

    # Creates the output folder if it doesn't already exist
    output_file.parent.mkdir(exist_ok=True)

    # Saves the results as a JSON file
    with output_file.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    # Shows a simple summary in the terminal
    print("Data extraction completed.")
    print(f"Emails found: {len(emails)}")
    print(f"ALU emails found: {len(alu_emails)}")
    print(f"URLs found: {len(urls)}")
    print(f"Phone numbers found: {len(phones)}")
    print(f"Credit cards found: {len(cards)}")
    print(f"Suspicious content detected: {suspicious}")


if __name__ == "__main__":
    main()
```
