"""
zxcvbn_analyzer.py
------------------
zxcvbn-Based Password Strength Evaluation Module.

Uses the `zxcvbn` library (Dropbox's realistic password strength estimator)
to provide crack-time estimates, feedback, and warnings.

Author: Password Strength Research Project
"""

try:
    from zxcvbn import zxcvbn as _zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False


# Human-readable crack-time mappings for display
_SCORE_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong"
}

_SCORE_COLORS = {
    0: "danger",
    1: "warning",
    2: "info",
    3: "success",
    4: "success"
}


def analyze_zxcvbn(password: str) -> dict:
    """
    Run zxcvbn analysis on the provided password.

    Args:
        password (str): The password to analyse.

    Returns:
        dict: A dictionary containing:
            - score (int): zxcvbn score (0–4).
            - score_label (str): Human-readable score label.
            - score_color (str): Bootstrap colour class.
            - crack_time_display (str): Estimated time to crack (offline).
            - crack_time_online (str): Estimated online crack time.
            - guesses (int): Estimated number of guesses needed.
            - guesses_log10 (float): log₁₀ of guesses.
            - feedback_warning (str): zxcvbn warning text (if any).
            - feedback_suggestions (list): List of suggestion strings.
            - normalized_score (int): Score normalized to 0–100.
            - available (bool): Whether zxcvbn is installed.
    """
    if not password:
        return _empty_result()

    if not ZXCVBN_AVAILABLE:
        return _unavailable_result()

    try:
        result = _zxcvbn(password)
    except Exception as exc:
        return _error_result(str(exc))

    score = result.get("score", 0)
    feedback = result.get("feedback", {})
    crack_times = result.get("crack_times_display", {})

    # Extract crack time for offline slow hashing (bcrypt-like)
    crack_offline = crack_times.get(
        "offline_slow_hashing_1e4_per_second", "unknown"
    )
    crack_online = crack_times.get(
        "online_no_throttling_10_per_second", "unknown"
    )

    # Normalize to 0–100
    normalized_score = (score / 4) * 100

    return {
        "score": score,
        "score_label": _SCORE_LABELS.get(score, "Unknown"),
        "score_color": _SCORE_COLORS.get(score, "secondary"),
        "crack_time_display": crack_offline,
        "crack_time_online": crack_online,
        "guesses": result.get("guesses", 0),
        "guesses_log10": round(result.get("guesses_log10", 0), 2),
        "feedback_warning": feedback.get("warning", ""),
        "feedback_suggestions": feedback.get("suggestions", []),
        "normalized_score": int(normalized_score),
        "available": True,
        "error": None
    }


def _empty_result() -> dict:
    """Return default result for empty password input."""
    return {
        "score": 0,
        "score_label": "Very Weak",
        "score_color": "danger",
        "crack_time_display": "instant",
        "crack_time_online": "instant",
        "guesses": 0,
        "guesses_log10": 0.0,
        "feedback_warning": "",
        "feedback_suggestions": [],
        "normalized_score": 0,
        "available": ZXCVBN_AVAILABLE,
        "error": None
    }


def _unavailable_result() -> dict:
    """Return result when zxcvbn library is not installed."""
    return {
        "score": 0,
        "score_label": "N/A",
        "score_color": "secondary",
        "crack_time_display": "N/A",
        "crack_time_online": "N/A",
        "guesses": 0,
        "guesses_log10": 0.0,
        "feedback_warning": "zxcvbn library is not installed.",
        "feedback_suggestions": ["Run: pip install zxcvbn"],
        "normalized_score": 0,
        "available": False,
        "error": "zxcvbn not installed"
    }


def _error_result(error_msg: str) -> dict:
    """Return result when zxcvbn raises an unexpected exception."""
    return {
        "score": 0,
        "score_label": "Error",
        "score_color": "secondary",
        "crack_time_display": "N/A",
        "crack_time_online": "N/A",
        "guesses": 0,
        "guesses_log10": 0.0,
        "feedback_warning": f"Analysis error: {error_msg}",
        "feedback_suggestions": [],
        "normalized_score": 0,
        "available": True,
        "error": error_msg
    }
