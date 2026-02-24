# Python Phishing Email Detector

This is a cybersecurity project that analyses email text files and detects potential phishing attempts using a weighted, rule based scoring system.

---

## Overview

Phishing emails often contain:

- Urgent or threatening language
- Requests for verification
- Expiration warnings
- Suspicious links
- Unusual domain names

This project analyses email content and assigns a phishing score based on weighted risk factors.

Unlike basic keyword detectors, this version:

- Uses weighted scoring
- Reduces false positives
- Caps low risk business vocabulary impact
- Adds context based combination bonuses
- Prioritises suspicious links over wording alone

---

## Detection Logic Explained

Not all suspicious words are treated equally.

### 1. Weighted Keyword Categories

#### High Risk Keywords (+2 points each)

Words that create urgency or fear:

- urgent
- immediate
- expired
- expiration
- suspicious

#### Medium Risk Keywords (+1.5 points each)

Common in credential phishing:

- verify
- verification

#### Low Risk Keywords (+0.5 points each)

Normal business terms that may appear in legitimate emails:

- invoice
- payroll
- payslip
- document
- file
- request
- delivery
- package
- follow up

### 2. Context Combination Bonuses

Phishing emails often combine urgency + verification.

Extra points are added for dangerous combinations such as:

- "urgent" + "verify"
- "expired" + "verify"

This improves detection accuracy without penalising normal business emails.

### 3. URL Analysis

Links are treated as more important than vocabulary.

This script checks for:

- Domains containing numbers (+3 points)
- Unusually long domain names (+2 points)
- Too many links in the email (+2 points)

Suspicious technical indicators weigh more heavily than word choice alone.

### 4. Final Classification Logic

An email is flagged as phishing pnly if:

- The phishing score exceeds the threshold (e.g., > 6)
- AND at lease one high risk keyword or suspicious link is present

This reduces false positives.

---

## How To Run

### 1. Clone The Repository

```
git clone https://github.com/coder0name0dre/phishing_detector.git
cd phishing_detector
```

### 2. Run The Script

```
python phishing_detector.py
```

### 3. Enter The Email File Name

```
Enter the email text file name: email1.txt
```

The program outputs:

- Phishing score
- Detection result
- Reasons for scoring

---

## Example Email Files Included

- email1.txt - Clear phishing (verification scam)
- email2.txt - Payroll phishing attempt
- email3.txt - Subtle delivery phishing
- email4.txt - Legitimate payroll email
- email5.txt - Legitimate delivery confirmation

---

## Example Expected Results

| Email Type | Expected Result |
|------------|----------------|
| email1.txt | Flagged |
| email2.txt | Flagged |
| email3.txt | Flagged |
| email4.txt | Safe |
| email5.txt | Safe |

---

## License

This project is licensed under the [MIT License](https://github.com/coder0name0dre/phishing_detector/blob/main/LICENSE).