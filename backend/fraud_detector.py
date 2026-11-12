import re
import ipaddress
from urllib.parse import urlparse
from difflib import SequenceMatcher


# ==================================
# FEATURE 1: SMS FRAUD DETECTION
# ==================================

def analyze_message(message):

    message = message.lower().strip()

    warning_phrases = [
        "never share",
        "do not share",
        "don't share",
        "never tell",
        "do not disclose",
        "never disclose",
        "don't disclose",
        "should not share",
        "must not share"
    ]

    is_warning = any(
        phrase in message for phrase in warning_phrases
    )

    suspicious_words = [
        "urgent",
        "verify your account",
        "account is blocked",
        "bank account is blocked",
        "account blocked",
        "account suspended",
        "bank account will be blocked",
        "verify your kyc",
        "kyc expired",
        "kyc update",
        "kyc verification",
        "click here",
        "claim reward",
        "claim your reward",
        "winner",
        "lottery",
        "prize",
        "otp",
        "share otp",
        "upi pin",
        "password",
        "send money",
        "bank details",
        "collect request",
        "receive money",
        "immediately",
        "limited time",
        "verify now",
        "unauthorized transaction",
        "refund pending",
        "cashback",
        "free gift"
    ]

    if is_warning:

        protected_terms = ["otp", "upi pin", "password"]

        suspicious_words = [
            word for word in suspicious_words
            if word not in protected_terms
        ]

    score = 0
    detected_words = []
    matched_words = []

    for word in sorted(suspicious_words, key=len, reverse=True):

        if word in message:

            if not any(word in found for found in matched_words):

                matched_words.append(word)
                detected_words.append(word)
                score += 12

    urls = re.findall(
        r'https?://[^\s]+|www\.[^\s]+',
        message
    )

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "is.gd"
    ]

    for url in urls:

        url = url.rstrip(".,!?;:)")

        if url.startswith("www."):
            url = "http://" + url

        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

        score += 25
        detected_words.append("Contains a link")

        if domain in shorteners:
            score += 20
            detected_words.append("URL shortener detected")

        try:
            ipaddress.ip_address(domain)
            score += 20
            detected_words.append("IP address used as website")
        except ValueError:
            pass

        if "xn--" in domain:
            score += 20
            detected_words.append("Punycode domain detected")

    sensitive_terms = [
        "upi pin",
        "atm pin",
        "debit card pin",
        "credit card pin",
        "otp",
        "password"
    ]

    request_terms = [
        "share",
        "send",
        "tell",
        "provide",
        "give",
        "enter",
        "confirm"
    ]

    if (
        not is_warning
        and any(term in message for term in sensitive_terms)
        and any(term in message for term in request_terms)
    ):

        score += 45

        detected_words.append(
            "Request to share sensitive PIN, OTP or password"
        )

    score = min(score, 100)

    if score >= 60:
        status = "HIGH RISK"
    elif score >= 25:
        status = "SUSPICIOUS"
    else:
        status = "LOW RISK"

    return {
        "risk_score": score,
        "status": status,
        "detected_words": detected_words,
        "message": "Risk indicators are not proof of fraud or safety."
    }


# ==================================
# FEATURE 2: ADVANCED WEBSITE SECURITY
# ==================================

def analyze_website(url):

    url = url.strip()

    if not url:

        return {
            "website": url,
            "risk_score": 100,
            "status": "INVALID URL",
            "warnings": ["Website address is empty"]
        }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

    except ValueError:
        domain = ""

    if not domain:

        return {
            "website": url,
            "risk_score": 100,
            "status": "INVALID URL",
            "warnings": ["Invalid website address"]
        }

    score = 0
    warnings = []

    def add_warning(points, warning):

        nonlocal score

        score += points

        if warning not in warnings:
            warnings.append(warning)

    # 1. HTTPS CHECK

    if parsed.scheme == "http":

        add_warning(
            15,
            "Website does not use HTTPS"
        )

    else:

        warnings.append(
            "HTTPS detected, but this does not guarantee safety"
        )

    # 2. URL SHORTENER CHECK

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "is.gd"
    ]

    if domain in shorteners:

        add_warning(
            30,
            "URL shortener detected"
        )

    # 3. IP ADDRESS CHECK

    try:

        ipaddress.ip_address(domain)

        add_warning(
            30,
            "Website uses an IP address"
        )

    except ValueError:
        pass

    # 4. URL @ SYMBOL CHECK

    if "@" in parsed.netloc:

        add_warning(
            35,
            "Suspicious @ symbol in website address"
        )

    # 5. SUSPICIOUS DOMAIN KEYWORDS

    suspicious_patterns = [
        "login",
        "verify",
        "secure",
        "account",
        "free",
        "reward",
        "banking"
    ]

    for word in suspicious_patterns:

        if word in domain:

            add_warning(
                10,
                "Suspicious domain keyword: " + word
            )

    # 6. PUNYCODE CHECK

    if "xn--" in domain:

        add_warning(
            30,
            "Punycode domain detected"
        )

    # 7. FAKE BRAND / TYPO CHECK

    trusted_brand_names = [
        "paypal",
        "google",
        "amazon",
        "microsoft",
        "apple",
        "facebook",
        "instagram",
        "whatsapp",
        "netflix",
        "sbi",
        "hdfc",
        "icici",
        "axisbank",
        "paytm",
        "phonepe"
    ]

    labels = domain.split(".")
    domain_labels = labels[:-1]

    for index, label in enumerate(domain_labels):

        normalized = label.lower().translate(
            str.maketrans({
                "0": "o",
                "1": "l",
                "3": "e",
                "5": "s"
            })
        )

        for brand in trusted_brand_names:

            similarity = SequenceMatcher(
                None,
                normalized,
                brand
            ).ratio()

            # Exact brand with character substitution

            if normalized == brand and label != brand:

                add_warning(
                    35,
                    "Possible fake brand domain: " + brand
                )

            # Brand used in a subdomain

            elif (
                normalized == brand
                and index < len(domain_labels) - 1
            ):

                add_warning(
                    30,
                    "Brand name used in suspicious subdomain: "
                    + brand
                )

            # Similar spelling or fake brand variation

            elif (
                normalized != brand
                and (
                    similarity >= 0.80
                    or brand in normalized
                )
            ):

                add_warning(
                    35,
                    "Possible fake brand domain: " + brand
                )

    # 8. TOO MANY SUBDOMAINS

    if len(labels) > 4:

        add_warning(
            15,
            "Unusually many subdomains detected"
        )

    # 9. EXCESSIVE HYPHENS

    if domain.count("-") >= 2:

        add_warning(
            15,
            "Excessive hyphens in domain"
        )

    # FINAL RISK SCORE

    score = min(score, 100)

    if score >= 60:
        status = "HIGH RISK"

    elif score >= 25:
        status = "SUSPICIOUS"

    else:
        status = "LOW RISK"

    return {
        "website": domain,
        "risk_score": score,
        "status": status,
        "warnings": warnings
    }