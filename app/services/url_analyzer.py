"""
Defensive, local heuristic URL analyzer.

This module NEVER fetches or attacks the submitted URL. It performs purely
structural/textual analysis of the URL string itself. If external
threat-intelligence APIs are configured in the future (VirusTotal, Google
Safe Browsing, URLhaus, AbuseIPDB), they should be added as additional,
clearly-labeled signals — never replacing the local heuristic baseline.
"""
import ipaddress
import re
from urllib.parse import urlparse

from app.services.scoring import Signal

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "reward", "free", "bonus", "prize", "winner", "claim",
    "password", "billing", "suspend", "unlock", "limited", "urgent",
]

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "icu",
    "click", "work", "link", "cam", "cyou", "monster", "country",
}

# A very small illustrative list of commonly impersonated brand names.
# Purely used to flag "brandname" appearing in a domain that is NOT the
# brand's actual known domain — a common impersonation pattern.
COMMONLY_IMPERSONATED_BRANDS = {
    "whatsapp", "facebook", "instagram", "paypal", "apple", "google",
    "microsoft", "amazon", "netflix", "bank", "gmail", "outlook",
}

KNOWN_LEGITIMATE_DOMAINS = {
    "whatsapp.com", "facebook.com", "instagram.com", "paypal.com",
    "apple.com", "google.com", "microsoft.com", "amazon.com",
    "netflix.com", "gmail.com", "outlook.com",
}


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _looks_like_punycode(host: str) -> bool:
    return "xn--" in host.lower()


def _has_suspicious_chars(url: str) -> bool:
    # Repeated hyphens, @ symbol tricks, many dots, odd unicode confusables
    if "@" in url:
        return True
    if re.search(r"-{2,}", url):
        return True
    if re.search(r"[^\x00-\x7F]", url):
        return True
    return False


def analyze_url(raw_url: str) -> tuple[list[Signal], dict]:
    """
    Returns (signals, metadata) for a submitted URL string.
    metadata includes parsed components useful for the UI/explanation.
    """
    signals: list[Signal] = []
    url = raw_url.strip()

    if not re.match(r"^https?://", url, re.IGNORECASE):
        # Assume http-less input like "example.com/login" — treat missing
        # scheme itself as a minor signal since legitimate shares usually
        # include https.
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    try:
        parsed = urlparse(url_for_parse)
    except Exception:
        signals.append(Signal("unparseable_url", 30, "The URL could not be parsed and has an unusual structure."))
        return signals, {"host": "", "scheme": "", "path": ""}

    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    full_lower = url.lower()

    # HTTPS check
    if scheme != "https":
        signals.append(Signal("no_https", 10, "The link does not use secure HTTPS."))

    # IP address instead of domain
    if host and _is_ip_address(host):
        signals.append(Signal("ip_address_host", 25, "The link uses a raw IP address instead of a domain name."))

    # Excessive length
    if len(url) > 100:
        signals.append(Signal("long_url", 8, "The URL is unusually long, which can be used to hide its true destination."))

    # Many subdomains
    if host:
        label_count = host.count(".")
        if label_count >= 4:
            signals.append(Signal("many_subdomains", 15, "The link uses an unusual number of subdomains."))

    # Punycode / homograph indicator
    if _looks_like_punycode(host):
        signals.append(Signal("punycode", 20, "The domain appears to use punycode encoding, sometimes used to imitate a trusted domain."))

    # Suspicious characters
    if _has_suspicious_chars(url):
        signals.append(Signal("suspicious_chars", 15, "The URL contains unusual characters or formatting often used to disguise links."))

    # Known URL shorteners
    if any(host == s or host.endswith("." + s) for s in KNOWN_SHORTENERS):
        signals.append(Signal("url_shortener", 10, "The link uses a URL-shortening service, which can hide the real destination."))

    # Suspicious TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append(Signal("suspicious_tld", 10, f"The domain uses a top-level domain ('.{tld}') that is frequently abused in scam campaigns."))

    # Suspicious keywords anywhere in URL
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_lower]
    if found_keywords:
        points = min(20, 5 * len(set(found_keywords)))
        signals.append(Signal(
            "suspicious_keywords",
            points,
            f"The URL contains wording commonly seen in phishing links: {', '.join(sorted(set(found_keywords))[:5])}."
        ))

    # Brand impersonation heuristic: brand name appears in domain, but the
    # domain is not the brand's actual known domain.
    if host and host not in KNOWN_LEGITIMATE_DOMAINS:
        for brand in COMMONLY_IMPERSONATED_BRANDS:
            if brand in host and not host.endswith("." + brand + ".com"):
                signals.append(Signal(
                    "brand_impersonation",
                    25,
                    f"The domain references '{brand}' but does not match {brand}'s official domain — a common impersonation pattern."
                ))
                break

    metadata = {"host": host, "scheme": scheme, "path": path}
    return signals, metadata
