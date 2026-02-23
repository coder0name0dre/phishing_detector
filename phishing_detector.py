import re                               # we use this to search for patterns like URLs inside text
from urllib.parse import urlparse       # we use this to help extract the domain name from links

def extract_urls(email_text):
# this function searches the email text for URLs.
# regular expression (regex) is used to find anything that looks like a web link.

    # regex pattern for URLs
    url_pattern = r'https?://[^\s]+'

    # re.findall returns all matches of the pattern
    urls = re.findall(url_pattern, email_text)

    return urls


def analyse_email(email_text):
# this function checks the email for phishing indicators.
# it returns a phishing score and a list of detected issues.

    phishing_score = 0      # higher score = more suspicious
    reasons = []            # explanations will be stored here

    # convert email to lowercase so checks are case insensitive
    email_lower = email_text.lower()

    # these are high risk keywords often used in phishing emails to create urgency or fear
    high_risk_keywords = [
        "urgent",
        "immediate",
        "expired",
        "expiration",
        "suspicious"
    ]

    # these are medium risk keywords that are often used in credential phishing 
    medium_risk_keywords= [
        "verify",
        "verification"
    ]

    # these are low risk keywords that are common in legitimate emails
    low_risk_keywords = [
        "invoice",
        "payroll",
        "payslip",
        "document",
        "file",
        "request",
        "delivery",
        "package",
        "follow up"
    ]

    # high risk keywords +2 to the phishing score
    for word in high_risk_keywords:
        if word in email_lower:
            phishing_score += 2
            reasons.append(f"High risk keyword: {word}")

    # medium risk keywords +1.5 to the phishing score
    for word in medium_risk_keywords:
        if word in email_lower:
            phishing_score += 1.5
            reasons.append(f"Medium risk keyword: {word}")

    # low risk keywords +0.5 to the phishing score
    for word in low_risk_keywords:
        if word in email_lower:
            phishing_score += 0.5
            reasons.append(f"Low risk keyword: {word}")

    # combo bonus if certain keywords are found together in a email
    if "urgent" in email_lower and "verify" in email_lower:
        phishing_score += 2
        reasons.append("urgency + verification combination")

    if "expired" in email_lower and "verify" in email_lower:
        phishing_score += 2
        reasons.append("Expired account + verification combination")

    # this for loop extracts any urls found in the email text
    urls = extract_urls(email_text)

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # check if domain contains numbers. if so, +3 to phishing score
        if any(char.isdigit() for char in domain):
            phishing_score += 3
            reasons.append(f"Suspicious domain with numbers: {domain}")

        # Check if domain is unusually long. if so, +2 to phishing score
        if len(domain) > 25:
            phishing_score += 2
            reasons.append(f"Unusually long domain name: {domain}")

    # this if statement checks to see if the email contains too many links, which is often suspicious. if so, +2  to phishing score
    if len(urls) > 2:
        phishing_score += 2
        reasons.append("Email contains many links")

    return phishing_score, reasons


def main():
# main function that runs the phishing detector

    # ask user for the file name
    filename = input("Enter the email text file name: ")

    try:
        # open the file and read its contents
        with open(filename, "r", encoding="utf-8") as file:
            email_text = file.read()

        # analyse the email
        score, reasons = analyse_email(email_text)

        print("\n< < < Analysis Results > > >")
        print(f"\nPhishing Score: {score}")

        # threshold for phishing detection
        if score >= 6:
            print("\nThis email is likely a phishing attempt!")
        else:
            print("\nThis email appears to be safe, but not guaranteed.")

        # print reasons
        print("\nReasons:")

        for reason in reasons:
            print("-", reason)

    except FileNotFoundError:
        print("File not found. Please check the file name.")


# this ensures main() runs only if the script is executed directly
if __name__ == "__main__":
    main()
