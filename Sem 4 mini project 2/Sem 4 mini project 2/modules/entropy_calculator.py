"""
entropy_calculator.py
---------------------
Shannon Entropy-Based Password Strength Evaluation Module.

Computes password entropy using:
    Entropy (bits) = Length × log₂(Character Set Size)

Author: Password Strength Research Project
"""

import math


# Character set sizes used for entropy calculation
CHARSET_SIZES = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "symbols": 32,
}


def calculate_entropy(password: str) -> dict:
    """
    Calculate Shannon entropy for the given password.

    The effective character set is determined by the character types
    present in the password, then entropy is computed as:
        H = N × log₂(C)
    where N = password length and C = character set size.

    Args:
        password (str): The password to evaluate.

    Returns:
        dict: A dictionary containing:
            - entropy (float): Entropy value in bits.
            - charset_size (int): Effective character set size used.
            - classification (str): Strength label.
            - charsets_used (list): Character types detected.
            - length (int): Length of the password.
            - bits_per_char (float): log₂(charset_size).
    """
    if not password:
        return _empty_result()

    length = len(password)
    charsets_used = []
    charset_size = 0

    # Detect which character categories are present
    if any(c.islower() for c in password):
        charsets_used.append("Lowercase (a–z)")
        charset_size += CHARSET_SIZES["lowercase"]

    if any(c.isupper() for c in password):
        charsets_used.append("Uppercase (A–Z)")
        charset_size += CHARSET_SIZES["uppercase"]

    if any(c.isdigit() for c in password):
        charsets_used.append("Digits (0–9)")
        charset_size += CHARSET_SIZES["digits"]

    if any(not c.isalnum() for c in password):
        charsets_used.append("Symbols (!@#…)")
        charset_size += CHARSET_SIZES["symbols"]

    # Avoid log2(0); default to 1 if charset is somehow empty
    if charset_size == 0:
        charset_size = 1

    bits_per_char = math.log2(charset_size)
    entropy = round(length * bits_per_char, 2)
    classification = classify_entropy(entropy)

    return {
        "entropy": entropy,
        "charset_size": charset_size,
        "classification": classification,
        "charsets_used": charsets_used,
        "length": length,
        "bits_per_char": round(bits_per_char, 4),
        "score": _entropy_to_score(entropy)
    }


def classify_entropy(entropy: float) -> str:
    """
    Classify the entropy value into a human-readable strength label.

    Thresholds (in bits):
        < 40   → Weak
        40–60  → Medium
        60–80  → Strong
        > 80   → Very Strong

    Args:
        entropy (float): Entropy value in bits.

    Returns:
        str: Strength classification label.
    """
    if entropy < 40:
        return "Weak"
    elif entropy < 60:
        return "Medium"
    elif entropy < 80:
        return "Strong"
    else:
        return "Very Strong"


def _entropy_to_score(entropy: float) -> int:
    """
    Convert entropy (bits) to a normalized 0–100 score for comparison.

    Uses 100 bits as the maximum reference point.

    Args:
        entropy (float): Entropy value in bits.

    Returns:
        int: Normalized score between 0 and 100.
    """
    max_entropy = 100.0
    score = min(int((entropy / max_entropy) * 100), 100)
    return score


def _empty_result() -> dict:
    """Return a default empty result when no password is provided."""
    return {
        "entropy": 0.0,
        "charset_size": 0,
        "classification": "Weak",
        "charsets_used": [],
        "length": 0,
        "bits_per_char": 0.0,
        "score": 0
    }
