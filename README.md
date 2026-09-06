**Data Extraction & Secure Validation
Brief Description**

This project is an example of using regular expressions (regex) to get useful information out of raw text. The program detects emails, URLs, phone numbers and credit card numbers. It also scans the input for suspicious material and safeguards sensitive data prior to saving the results.

**Code Structure**

The project is divided into three sections:

Input: This contains raw-text.txt which contains raw and messy data that the program processes.
Contains main.py which processes the data.
Output: Contains sample-output.json which stores the extracted and protected results.
main.py

The main logic of the project is in the main.py file. It is divided into various sections:

Regex patterns: These are rules that are used to identify emails, urls, phone numbers and credit card numbers in raw text.
Validation: The program verifies the validity of the extracted emails and phone numbers. Also verifies emails from approved ALU domains.
Security checks: Before extracting the data, the program looks for suspicious content such as script tags and common SQL injection patterns. Suspicious lines are removed from the input.
Data masking: Credit card numbers are masked to show only the last 4 digits. The email addresses are also partially obscured to safeguard personal information.
Data extraction: The program uses the regex patterns to search the cleaned text and discards the duplicate results.
Output: Extracted information is structured in a JSON format and stored in sample-output.json. A brief summary of the number of items found is also printed.
Data Extracted

**The program extracts:**

Email addresses
URLs
Phone numbers
Credit card numbers

**It also validates ALU email addresses from:
**
@alueducation.com
@alumni.alueducation.com
@si.alueducation.com
Security

The data entered is considered untrusted. The program will scan for suspicious code like script tags and common SQL injection patterns.

The output is not unnecessarily revealing of personal or financial information, but rather sensitive information is masked.

**Project Structure**
alu-regex-data-extraction/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
└── README.md
How to Run

From the project folder, run:

python3 src/main.py

The results will be saved in:

output/sample-output.json
