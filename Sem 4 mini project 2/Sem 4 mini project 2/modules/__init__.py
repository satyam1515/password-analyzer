"""
__init__.py
-----------
Modules package initialiser.
Exposes each analysis function at the package level for clean imports.
"""

from .rules_checker      import evaluate_rules
from .entropy_calculator import calculate_entropy
from .pattern_detector   import detect_patterns
from .zxcvbn_analyzer    import analyze_zxcvbn
from .hybrid_metric      import compute_hybrid, generate_suggestions

__all__ = [
    "evaluate_rules",
    "calculate_entropy",
    "detect_patterns",
    "analyze_zxcvbn",
    "compute_hybrid",
    "generate_suggestions",
]
