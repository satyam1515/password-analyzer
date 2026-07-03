"""
app.py
------
Main Flask Application Entry Point.

Research Project: A Comparative Analysis of Password Strength Metrics:
                  Rules-Based vs. Entropy-Based Evaluation

Run with:
    python app.py

Author: Password Strength Research Project
"""

import os
import io
import base64
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend (no GUI)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from flask import Flask, render_template, request, jsonify

from modules.rules_checker      import evaluate_rules
from modules.entropy_calculator import calculate_entropy
from modules.pattern_detector   import detect_patterns
from modules.zxcvbn_analyzer    import analyze_zxcvbn
from modules.hybrid_metric      import compute_hybrid
from modules.pwned_checker      import check_pwned


# ── Flask Application Factory ──────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "pws-research-2024-secret")

# Ensure the charts directory exists
os.makedirs(os.path.join("static", "charts"), exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Render the main application page."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyse a submitted password using all evaluation modules.

    Expects JSON body: {"password": "<the_password>"}

    Returns:
        JSON response with analysis results from all modules and a
        base64-encoded comparison chart image.
    """
    data = request.get_json(silent=True)

    if not data or "password" not in data:
        return jsonify({"error": "No password provided."}), 400

    password = data["password"]

    # ── Input validation ───────────────────────────────────────────────────────
    if len(password) > 512:
        return jsonify({"error": "Password too long (max 512 characters)."}), 400

    # ── Run all analyses ───────────────────────────────────────────────────────
    rules_result   = evaluate_rules(password)
    entropy_result = calculate_entropy(password)
    pattern_result = detect_patterns(password)
    zxcvbn_result  = analyze_zxcvbn(password)
    pwned_count    = check_pwned(password)

    # ── Compute hybrid score ───────────────────────────────────────────────────
    hybrid_result = compute_hybrid(
        rules_score        = rules_result["score"],
        entropy_score      = entropy_result["score"],
        dict_aware_score   = zxcvbn_result["normalized_score"],
        pattern_score      = pattern_result["pattern_score"],
        crack_resist_score = min(100, int(entropy_result["entropy"]))
    )

    # ── Generate comparison chart ──────────────────────────────────────────────
    chart_b64 = _generate_comparison_chart(
        rules_score   = rules_result["score"],
        entropy_score = entropy_result["score"],
        zxcvbn_score  = zxcvbn_result["normalized_score"],
        hybrid_score  = hybrid_result["hybrid_score"],
        pattern_score = pattern_result["pattern_score"]
    )

    return jsonify({
        "rules":   rules_result,
        "entropy": entropy_result,
        "pattern": pattern_result,
        "zxcvbn":  zxcvbn_result,
        "hybrid":  hybrid_result,
        "pwned_count": pwned_count,
        "chart":   chart_b64,
        "password_length": len(password)
    })

@app.route("/analyze_batch", methods=["POST"])
def analyze_batch():
    """
    API Endpoint for batch password analysis.
    Expects JSON: { "passwords": ["pass1", "pass2", ...] }
    """
    data = request.get_json()
    if not data or "passwords" not in data:
        return jsonify({"error": "Invalid request. Missing 'passwords'."}), 400

    passwords = data.get("passwords", [])
    if len(passwords) > 50:
        return jsonify({"error": "Batch limit is 50 passwords at a time."}), 400

    results = []
    for password in passwords:
        if len(password) > 512:
            continue
            
        rules_result   = evaluate_rules(password)
        entropy_result = calculate_entropy(password)
        pattern_result = detect_patterns(password)
        zxcvbn_result  = analyze_zxcvbn(password)
        pwned_count    = check_pwned(password)

        hybrid_result = compute_hybrid(
            rules_score        = rules_result["score"],
            entropy_score      = entropy_result["score"],
            dict_aware_score   = zxcvbn_result["normalized_score"],
            pattern_score      = pattern_result["pattern_score"],
            crack_resist_score = min(100, int(entropy_result["entropy"]))
        )

        results.append({
            "password": password,
            "length": len(password),
            "rules_score": rules_result["score"],
            "entropy_score": entropy_result["score"],
            "dict_aware_score": zxcvbn_result["normalized_score"],
            "pattern_score": pattern_result["pattern_score"],
            "hybrid_score": hybrid_result["hybrid_score"],
            "pwned_count": pwned_count,
            "classification": hybrid_result["classification"]
        })

    return jsonify({"results": results})


# ══════════════════════════════════════════════════════════════════════════════
# CHART GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def _generate_comparison_chart(
    rules_score: int,
    entropy_score: int,
    zxcvbn_score: int,
    hybrid_score: int,
    pattern_score: int
) -> str:
    """
    Generate a multi-panel Matplotlib comparison chart and return it as
    a base64-encoded PNG string.

    Args:
        rules_score   (int): Rules-based score (0–100).
        entropy_score (int): Entropy-based score (0–100).
        zxcvbn_score  (int): zxcvbn normalized score (0–100).
        hybrid_score  (int): Hybrid combined score (0–100).
        pattern_score (int): Pattern detection score (0–100).

    Returns:
        str: Base64-encoded PNG image string.
    """

    # ── Colour palette (cybersecurity theme) ──────────────────────────────────
    BG_COLOR   = "#0d1117"
    CARD_COLOR = "#161b22"
    ACCENT     = "#58a6ff"
    GRID_COLOR = "#30363d"
    TEXT_COLOR = "#c9d1d9"

    labels = ["Rules\nBased", "Entropy\nBased", "zxcvbn\nScore", "Pattern\nScore", "Hybrid\nScore"]
    scores = [rules_score, entropy_score, zxcvbn_score, pattern_score, hybrid_score]
    colors = [_score_to_hex(s) for s in scores]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5), facecolor=BG_COLOR)
    fig.patch.set_facecolor(BG_COLOR)

    # ── Left: Grouped Bar Chart ───────────────────────────────────────────────
    ax1 = axes[0]
    ax1.set_facecolor(CARD_COLOR)
    x = np.arange(len(labels))
    bars = ax1.bar(x, scores, color=colors, width=0.55, zorder=3,
                   edgecolor=BG_COLOR, linewidth=1.2)

    # Value labels on bars
    for bar, score in zip(bars, scores):
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1.5,
            f"{score}",
            ha="center", va="bottom",
            color=TEXT_COLOR, fontsize=11, fontweight="bold"
        )

    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, color=TEXT_COLOR, fontsize=9)
    ax1.set_ylim(0, 115)
    ax1.set_ylabel("Score (0–100)", color=TEXT_COLOR, fontsize=10)
    ax1.set_title("Password Metric Comparison", color=ACCENT, fontsize=13, fontweight="bold", pad=12)
    ax1.tick_params(colors=TEXT_COLOR)
    ax1.spines[:].set_color(GRID_COLOR)
    ax1.yaxis.grid(True, color=GRID_COLOR, linestyle="--", alpha=0.5, zorder=0)
    ax1.set_axisbelow(True)

    # Threshold lines
    for threshold, label in [(40, "Weak"), (70, "Medium")]:
        ax1.axhline(y=threshold, color="#ff7b72", linestyle=":", linewidth=1, alpha=0.6)
        ax1.text(len(labels) - 0.5, threshold + 1, label,
                 color="#ff7b72", fontsize=8, alpha=0.8)

    # ── Right: Radar / Spider Chart ───────────────────────────────────────────
    radar_labels = ["Rules", "Entropy", "zxcvbn", "Pattern", "Hybrid"]
    radar_scores = [s / 100.0 for s in scores]

    num_vars = len(radar_labels)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    radar_scores_plot = radar_scores + [radar_scores[0]]
    angles_plot = angles + [angles[0]]

    ax2 = fig.add_subplot(122, polar=True, facecolor=CARD_COLOR)
    ax2.set_facecolor(CARD_COLOR)

    ax2.plot(angles_plot, radar_scores_plot, color=ACCENT, linewidth=2, linestyle="solid")
    ax2.fill(angles_plot, radar_scores_plot, color=ACCENT, alpha=0.2)

    ax2.set_xticks(angles)
    ax2.set_xticklabels(radar_labels, color=TEXT_COLOR, fontsize=10)
    ax2.set_ylim(0, 1)
    ax2.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax2.set_yticklabels(["25", "50", "75", "100"], color=GRID_COLOR, fontsize=7)
    ax2.grid(color=GRID_COLOR, linestyle="--", alpha=0.5)
    ax2.spines["polar"].set_color(GRID_COLOR)
    ax2.set_title("Radar Analysis", color=ACCENT, fontsize=13, fontweight="bold", pad=18)

    # Data point markers
    for angle, val in zip(angles, radar_scores):
        ax2.plot(angle, val, "o", color=ACCENT, markersize=6, zorder=5)

    # ── Legend ────────────────────────────────────────────────────────────────
    legend_patches = [
        mpatches.Patch(color="#ff7b72", label="Weak (0–40)"),
        mpatches.Patch(color="#f0a500", label="Medium (41–70)"),
        mpatches.Patch(color="#3fb950", label="Strong (71–100)"),
    ]
    fig.legend(
        handles=legend_patches,
        loc="lower center",
        ncol=3,
        fontsize=9,
        facecolor=CARD_COLOR,
        edgecolor=GRID_COLOR,
        labelcolor=TEXT_COLOR,
        framealpha=0.8,
        bbox_to_anchor=(0.5, -0.02)
    )

    plt.tight_layout(rect=[0, 0.06, 1, 1])

    # ── Encode to base64 ──────────────────────────────────────────────────────
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor=BG_COLOR)
    plt.close(fig)
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode("utf-8")
    return img_b64


def _score_to_hex(score: int) -> str:
    """Map a 0–100 score to a colour hex string."""
    if score <= 40:
        return "#ff7b72"   # Red  – Weak
    elif score <= 70:
        return "#f0a500"   # Amber – Medium
    else:
        return "#3fb950"   # Green – Strong


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  Password Strength Research Application")
    print("  Running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
