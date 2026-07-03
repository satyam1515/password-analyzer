"""
rules_checker.py
----------------
Rules-Based Password Strength Evaluation Module.

This module evaluates password strength using a set of predefined
security rules and calculates a score from 0 to 100.

Author: Password Strength Research Project
"""

import re


def evaluate_rules(password: str) -> dict:
    """
    Evaluate the password against a set of security rules.

    Args:
        password (str): The password to evaluate.

    Returns:
        dict: A dictionary containing:
            - rules (list): Each rule with its name, passed status, and description.
            - score (int): Rules-based score from 0 to 100.
            - classification (str): 'Weak', 'Medium', or 'Strong'.
            - passed_count (int): Number of rules passed.
            - total_rules (int): Total number of rules.
    """
    if not password:
        return _empty_result()

    rules = []
    score = 0

    # ── Rule 1: Minimum Length (8 characters) ─────────────────────────────────
    min_len_passed = len(password) >= 8
    rules.append({
        "name": "Minimum Length (≥ 8 chars)",
        "passed": min_len_passed,
        "description": f"Password is {len(password)} character(s) long.",
        "points": 20,
        "icon": "fa-ruler"
    })
    if min_len_passed:
        score += 20

    # ── Rule 2: Length Bonus (above 12 characters) ────────────────────────────
    long_len_passed = len(password) >= 12
    rules.append({
        "name": "Length Bonus (≥ 12 chars)",
        "passed": long_len_passed,
        "description": "Extra credit for passwords longer than 12 characters.",
        "points": 10,
        "icon": "fa-star"
    })
    if long_len_passed:
        score += 10

    # ── Rule 3: Uppercase Letters ─────────────────────────────────────────────
    has_upper = bool(re.search(r'[A-Z]', password))
    rules.append({
        "name": "Uppercase Letters (A–Z)",
        "passed": has_upper,
        "description": "Contains at least one uppercase letter.",
        "points": 20,
        "icon": "fa-font"
    })
    if has_upper:
        score += 20

    # ── Rule 4: Lowercase Letters ─────────────────────────────────────────────
    has_lower = bool(re.search(r'[a-z]', password))
    rules.append({
        "name": "Lowercase Letters (a–z)",
        "passed": has_lower,
        "description": "Contains at least one lowercase letter.",
        "points": 15,
        "icon": "fa-font"
    })
    if has_lower:
        score += 15

    # ── Rule 5: Numbers ───────────────────────────────────────────────────────
    has_digit = bool(re.search(r'[0-9]', password))
    rules.append({
        "name": "Numeric Digits (0–9)",
        "passed": has_digit,
        "description": "Contains at least one numeric digit.",
        "points": 20,
        "icon": "fa-hashtag"
    })
    if has_digit:
        score += 20

    # ── Rule 6: Special Characters ────────────────────────────────────────────
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'\/~`]', password))
    rules.append({
        "name": "Special Characters (!@#$…)",
        "passed": has_special,
        "description": "Contains at least one special character.",
        "points": 15,
        "icon": "fa-at"
    })
    if has_special:
        score += 15

    # ── Classification ────────────────────────────────────────────────────────
    classification = classify_score(score)
    passed_count = sum(1 for r in rules if r["passed"])

    return {
        "rules": rules,
        "score": score,
        "classification": classification,
        "passed_count": passed_count,
        "total_rules": len(rules)
    }


def classify_score(score: int) -> str:
    """
    Classify a rules-based score into a strength label.

    Args:
        score (int): Score between 0 and 100.

    Returns:
        str: 'Weak', 'Medium', or 'Strong'.
    """
    if score <= 40:
        return "Weak"
    elif score <= 70:
        return "Medium"
    else:
        return "Strong"


def _empty_result() -> dict:
    """Return a default empty result when no password is provided."""
    return {
        "rules": [],
        "score": 0,
        "classification": "Weak",
        "passed_count": 0,
        "total_rules": 6
    }
