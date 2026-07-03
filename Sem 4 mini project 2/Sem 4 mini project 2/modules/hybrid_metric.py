"""
hybrid_metric.py
----------------
Hybrid Password Strength Score Module.

Combines three evaluation methods and a pattern penalty into a single
weighted hybrid score:

    Hybrid Score = (30% × Rules Score) + (30% × Entropy Score)
                 + (30% × zxcvbn Score) + (10% × Pattern Score)

Author: Password Strength Research Project
"""


# ── Weightings (Person 2 Research Model) ───────────────────────────────────────
WEIGHTS = {
    "rules":        0.30,
    "entropy":      0.30,
    "dict_aware":   0.20,
    "pattern":      0.10,
    "crack_resist": 0.10,
}


def compute_hybrid(
    rules_score: int,
    entropy_score: int,
    dict_aware_score: int,
    pattern_score: int,
    crack_resist_score: int
) -> dict:
    """
    Compute the hybrid password strength score.

    Args:
        rules_score        (int): Rules-based score (0–100).
        entropy_score      (int): Entropy-based score (0–100).
        dict_aware_score   (int): Dictionary awareness score (zxcvbn normalized) (0–100).
        pattern_score      (int): Pattern score (0–100; 100 = no patterns).
        crack_resist_score (int): Crack resistance score (entropy_bits capped at 100) (0-100).

    Returns:
        dict: A dictionary containing:
            - hybrid_score (int): Final weighted score (0–100).
            - classification (str): 'Weak', 'Medium', 'Strong', or 'Very Strong'.
            - color (str): Bootstrap colour class.
            - breakdown (dict): Per-component weighted contributions.
            - suggestions (list): Improvement suggestions if score is low.
    """
    hybrid_score = int(
        rules_score        * WEIGHTS["rules"]        +
        entropy_score      * WEIGHTS["entropy"]      +
        dict_aware_score   * WEIGHTS["dict_aware"]   +
        pattern_score      * WEIGHTS["pattern"]      +
        crack_resist_score * WEIGHTS["crack_resist"]
    )
    hybrid_score = max(0, min(100, hybrid_score))  # Clamp to [0, 100]

    classification = classify_hybrid(hybrid_score)
    color = _score_color(hybrid_score)
    suggestions = generate_suggestions(
        hybrid_score, rules_score, entropy_score, dict_aware_score, pattern_score
    )

    return {
        "hybrid_score": hybrid_score,
        "classification": classification,
        "color": color,
        "breakdown": {
            "rules_contribution":   round(rules_score        * WEIGHTS["rules"],        1),
            "entropy_contribution": round(entropy_score      * WEIGHTS["entropy"],      1),
            "dict_contribution":    round(dict_aware_score   * WEIGHTS["dict_aware"],   1),
            "pattern_contribution": round(pattern_score      * WEIGHTS["pattern"],      1),
            "crack_contribution":   round(crack_resist_score * WEIGHTS["crack_resist"], 1),
        },
        "weights": WEIGHTS,
        "suggestions": suggestions,
    }


def classify_hybrid(score: int) -> str:
    """
    Classify a hybrid score into a strength label.

    Args:
        score (int): Score between 0 and 100.

    Returns:
        str: 'Weak', 'Medium', 'Strong', or 'Very Strong'.
    """
    if score <= 40:
        return "Weak"
    elif score <= 60:
        return "Medium"
    elif score <= 80:
        return "Strong"
    else:
        return "Very Strong"


def _score_color(score: int) -> str:
    """Map a numeric score to a Bootstrap colour class."""
    if score <= 40:
        return "danger"
    elif score <= 60:
        return "warning"
    elif score <= 80:
        return "info"
    else:
        return "success"


def generate_suggestions(
    hybrid_score: int,
    rules_score: int,
    entropy_score: int,
    zxcvbn_score: int,
    pattern_score: int
) -> list:
    """
    Generate targeted password improvement suggestions based on scores.

    Args:
        hybrid_score  (int): Final hybrid score.
        rules_score   (int): Rules-based score.
        entropy_score (int): Entropy-based score.
        zxcvbn_score  (int): zxcvbn score.
        pattern_score (int): Pattern score.

    Returns:
        list: A list of actionable suggestion strings.
    """
    suggestions = []

    if hybrid_score > 80:
        return ["✅ Your password meets all strength criteria. Excellent!"]

    if rules_score < 60:
        suggestions.append("🔡 Increase password length to at least 12 characters.")
        suggestions.append("🔠 Add a mix of uppercase and lowercase letters.")
        suggestions.append("🔢 Include numeric digits (0–9).")
        suggestions.append("🔣 Add special characters such as !@#$%^&*.")

    if entropy_score < 50:
        suggestions.append(
            "📐 Use a wider variety of character types to increase entropy."
        )

    if zxcvbn_score < 50:
        suggestions.append("📚 Avoid dictionary words and common phrases.")
        suggestions.append("🚫 Do not use personal information (names, birthdays).")

    if pattern_score < 75:
        suggestions.append("⌨️  Avoid keyboard patterns like 'qwerty' or '12345'.")
        suggestions.append("🔄 Avoid repeating the same character multiple times.")

    if hybrid_score <= 40:
        suggestions.append(
            "💡 Consider using a passphrase: four random words joined together."
        )
        suggestions.append("🔐 Use a password manager to generate strong passwords.")

    # Deduplicate
    return list(dict.fromkeys(suggestions))
