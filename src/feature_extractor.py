import re
import math
import ipaddress
import tldextract
from urllib.parse import urlparse, parse_qs


SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "paypal",
    "bank",
    "billing",
    "payment",
    "wallet",
    "auth",
]

SUSPICIOUS_PATH_PATTERNS = [
    "/wp-content/",
    "/wp-includes/",
    "/plugins/",
    "/themes/",
    "/cgi-bin/",
    "/upload/",
    "/uploads/",
]

SUSPICIOUS_PATH_WORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "virefication",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "billing",
    "payment",
    "paypal",
    "bank",
]


def has_ip_address(url):
    try:
        hostname = urlparse(url).hostname
        if hostname is None:
            return 0
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def count_special_characters(url):
    special_chars = "@?&=_%~-"
    return sum(url.count(char) for char in special_chars)


def count_digits(url):
    return sum(char.isdigit() for char in url)


def count_letters(url):
    return sum(char.isalpha() for char in url)


def calculate_entropy(text):
    if not text:
        return 0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0
    length = len(text)
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def get_vowel_consonant_ratios(text):
    text_alpha = [c.lower() for c in text if c.isalpha()]
    if not text_alpha:
        return 0.0, 0.0

    vowels = set("aeiou")
    v_count = sum(1 for c in text_alpha if c in vowels)
    c_count = len(text_alpha) - v_count

    return v_count / len(text_alpha), c_count / len(text_alpha)


def get_max_consecutive_consonants(text):
    text_lower = text.lower()
    consonants_pattern = r"[bcdfghjklmnpqrstvwxyz]{2,}"
    matches = re.findall(consonants_pattern, text_lower)
    if not matches:
        return 0
    return max(len(m) for m in matches)


def has_long_numeric_sequence(url):
    return int(bool(re.search(r"\d{6,}", url)))


def has_hex_like_sequence(url):
    return int(bool(re.search(r"[a-f0-9]{12,}", url.lower())))


def has_double_extension(url):
    return int(bool(
        re.search(
            r"\.(html?|php|asp|aspx|jsp|pdf|docx?|xlsx?|zip)\."
            r"(exe|scr|php|html?|js)",
            url.lower()
        )
    ))


def count_suspicious_path_words(path, query):
    text = (path + "?" + query).lower()
    return sum(text.count(word) for word in SUSPICIOUS_PATH_WORDS)


def suspicious_path_pattern_count(path):
    path_lower = path.lower()
    count = 0
    for pattern in SUSPICIOUS_PATH_PATTERNS:
        if pattern in path_lower:
            count += 1
    return count


def extract_features(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    extracted = tldextract.extract(url)

    domain = extracted.domain
    subdomain = extracted.subdomain
    suffix = extracted.suffix

    features = {}

    # -------------------------
    # Basic URL characteristics
    # -------------------------
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_slashes"] = url.count("/")
    features["num_digits"] = count_digits(url)
    features["num_letters"] = count_letters(url)
    features["num_special_chars"] = count_special_characters(url)

    # -------------------------
    # Security-related features
    # -------------------------
    features["uses_https"] = int(parsed.scheme == "https")
    features["has_ip_address"] = has_ip_address(url)
    features["has_at_symbol"] = int("@" in url)
    features["has_double_slash"] = int("//" in parsed.path)

    # -------------------------
    # Domain characteristics
    # -------------------------
    features["domain_length"] = len(domain)
    features["subdomain_length"] = len(subdomain)
    features["num_subdomains"] = len(subdomain.split(".")) if subdomain else 0
    features["has_subdomain"] = int(bool(subdomain))
    features["has_valid_tld"] = int(bool(suffix))

    # -------------------------
    # Suspicious keywords & patterns
    # -------------------------
    url_lower = url.lower()
    suspicious_word_count = sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)

    features["suspicious_word_count"] = suspicious_word_count
    features["suspicious_path_pattern_count"] = suspicious_path_pattern_count(path)
    features["suspicious_path_word_count"] = count_suspicious_path_words(path, query)
    features["has_long_numeric_sequence"] = has_long_numeric_sequence(url)
    features["has_hex_like_sequence"] = has_hex_like_sequence(url)
    features["has_double_extension"] = has_double_extension(url)

    # -------------------------
    # Path & Token Analysis (NEW)
    # -------------------------
    path_tokens = [t for t in re.split(r"[/._\-\?&=]", path) if t]
    features["num_path_tokens"] = len(path_tokens)
    features["max_path_token_length"] = max((len(t) for t in path_tokens), default=0)
    features["avg_path_token_length"] = (
        sum(len(t) for t in path_tokens) / len(path_tokens) if path_tokens else 0.0
    )
    features["path_entropy"] = calculate_entropy(path)

    # -------------------------
    # Character distributions & Ratios
    # -------------------------
    if len(url) > 0:
        features["digit_ratio"] = count_digits(url) / len(url)
        features["letter_ratio"] = count_letters(url) / len(url)
    else:
        features["digit_ratio"] = 0.0
        features["letter_ratio"] = 0.0

    v_ratio, c_ratio = get_vowel_consonant_ratios(url)
    features["vowel_ratio"] = v_ratio
    features["consonant_ratio"] = c_ratio
    features["max_consecutive_consonants"] = get_max_consecutive_consonants(url)

    # -------------------------
    # Entropy
    # -------------------------
    features["url_entropy"] = calculate_entropy(url)

    return features