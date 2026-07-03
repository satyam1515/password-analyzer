"""
pattern_detector.py
-------------------
Keyboard Pattern Detection Module.

Detects common keyboard walk patterns, sequential patterns, and
dictionary-like patterns that significantly reduce password security.

Author: Password Strength Research Project
"""

import re


# ── Common keyboard walk and sequential patterns ───────────────────────────────
KEYBOARD_PATTERNS = [
    # Horizontal QWERTY rows
    "qwerty", "qwertyuiop",
    "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm",

    # Numeric sequences
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "654321", "0987654321",

    # Mixed keyboard walks
    "1qaz2wsx", "2wsx3edc", "qazwsx", "qazwsxedc",
    "qwerty123", "password", "pass123", "admin123",

    # Repeated characters
    "aaaaaa", "111111", "000000",
]

# Regex-based pattern checks for sequential runs
_SEQ_DIGITS_RE = re.compile(r'(0123|1234|2345|3456|4567|5678|6789|7890|9876|8765|7654|6543|5432|4321|3210)', re.IGNORECASE)
_SEQ_ALPHA_RE  = re.compile(r'(abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz|zyxw|yxwv|xwvu|wvut|vuts|utsr|tsrq|srqp|rqpo|qpon|ponm|onml|nmlk|mlkj|lkji|kjihg|jihg|ihgf|hgfe|gfed|fedc|edcb|dcba)', re.IGNORECASE)
_REPEAT_RE     = re.compile(r'(.)\1{2,}')  # Any char repeated 3+ times


def detect_patterns(password: str) -> dict:
    """
    Detect keyboard walk patterns, sequential patterns, and repetitions
    in the given password.

    Args:
        password (str): The password to analyse.

    Returns:
        dict: A dictionary containing:
            - patterns_found (list): Names of all detected patterns.
            - has_pattern (bool): True if any pattern was detected.
            - penalty (int): Score penalty (0–30) to apply to the hybrid score.
            - pattern_score (int): Score component (0–100, lower = more patterns).
            - warning (str): Human-readable warning message or empty string.
    """
    if not password:
        return _empty_result()

    password_lower = password.lower()
    patterns_found = []

    # ── 1. Static keyboard-pattern list ───────────────────────────────────────
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            patterns_found.append(f"Common pattern: '{pattern}'")

    # ── 2. Sequential digit runs ──────────────────────────────────────────────
    if _SEQ_DIGITS_RE.search(password_lower):
        patterns_found.append("Sequential digit sequence (e.g. 1234)")

    # ── 3. Sequential alphabetic runs ────────────────────────────────────────
    if _SEQ_ALPHA_RE.search(password_lower):
        patterns_found.append("Sequential letter sequence (e.g. abcd)")

    # ── 4. Repeated characters ────────────────────────────────────────────────
    repeat_match = _REPEAT_RE.search(password)
    if repeat_match:
        patterns_found.append(f"Repeated character: '{repeat_match.group(1)}' × {len(repeat_match.group())}")

    # ── Deduplicate while preserving order ────────────────────────────────────
    seen = set()
    unique_patterns = []
    for p in patterns_found:
        if p not in seen:
            seen.add(p)
            unique_patterns.append(p)

    has_pattern = len(unique_patterns) > 0
    penalty = min(30, len(unique_patterns) * 10)  # Max 30-point penalty
    pattern_score = max(0, 100 - len(unique_patterns) * 25)

    warning = ""
    if has_pattern:
        warning = (
            "⚠️ Keyboard Pattern Detected — predictable patterns "
            "drastically reduce password security."
        )

    return {
        "patterns_found": unique_patterns,
        "has_pattern": has_pattern,
        "penalty": penalty,
        "pattern_score": pattern_score,
        "warning": warning
    }


def _empty_result() -> dict:
    """Return a default empty result when no password is provided."""
    return {
        "patterns_found": [],
        "has_pattern": False,
        "penalty": 0,
        "pattern_score": 100,
        "warning": ""
    }
