"""
regression_model.py  (Part 9)
─────────────────────────────
Linear Regression Analysis for Password Strength Research.

Trains two linear‑regression models:
  1. Target = zxcvbn_score   (proxy for crack resistance)
  2. Target = log10(TTC)     (estimated time‑to‑crack based on entropy)

Generates publication‑quality graphs and a results CSV.

Author : Student Research Team – Person 2
Date   : June 2026
"""

import sys
import os
import math

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_squared_error, mean_absolute_error

# ── Paths ───────────────────────────────────────────────────────────────────────
DATASET_PATH = os.path.join(PROJECT_ROOT, "datasets", "cleaned_passwords.csv")
GRAPHS_DIR   = os.path.join(PROJECT_ROOT, "graphs")
RESULTS_DIR  = os.path.join(PROJECT_ROOT, "regression_analysis")
RESULTS_CSV  = os.path.join(RESULTS_DIR, "regression_results.csv")

# ── Dark‑theme palette ──────────────────────────────────────────────────────────
BG_COLOR      = "#0d1117"
TEXT_COLOR    = "#c9d1d9"
ACCENT_1      = "#58a6ff"
ACCENT_2      = "#f78166"
GRID_COLOR    = "#21262d"
SPINE_COLOR   = "#30363d"

# ── Feature columns ────────────────────────────────────────────────────────────
FEATURES = [
    "length",
    "entropy_bits",
    "rules_score",
    "has_pattern",
    "pattern_score",
    "has_upper",
    "has_lower",
    "has_digit",
    "has_special",
]


def _style_axis(ax, title="", xlabel="", ylabel=""):
    """Apply dark‑theme styling to a matplotlib axis."""
    ax.set_facecolor(BG_COLOR)
    ax.set_title(title, color=TEXT_COLOR, fontsize=14, fontweight="bold", pad=12)
    ax.set_xlabel(xlabel, color=TEXT_COLOR, fontsize=11)
    ax.set_ylabel(ylabel, color=TEXT_COLOR, fontsize=11)
    ax.tick_params(colors=TEXT_COLOR, labelsize=9)
    for spine in ax.spines.values():
        spine.set_color(SPINE_COLOR)
    ax.grid(True, color=GRID_COLOR, linestyle="--", linewidth=0.5, alpha=0.7)


def load_data():
    """Load and prepare the dataset.  Returns (X, y_zxcvbn, y_ttc, feature_names)."""
    df = pd.read_csv(DATASET_PATH)

    # Ensure has_pattern is numeric (0/1)
    if df["has_pattern"].dtype == object:
        df["has_pattern"] = df["has_pattern"].map(
            {True: 1, False: 0, "True": 1, "False": 0, "true": 1, "false": 0}
        ).fillna(0).astype(int)
    else:
        df["has_pattern"] = df["has_pattern"].astype(int)

    # Boolean columns → int
    for col in ["has_upper", "has_lower", "has_digit", "has_special"]:
        if df[col].dtype == object:
            df[col] = df[col].map(
                {True: 1, False: 0, "True": 1, "False": 0, "true": 1, "false": 0}
            ).fillna(0).astype(int)
        else:
            df[col] = df[col].astype(int)

    X = df[FEATURES].values
    y_zxcvbn = df["zxcvbn_score"].values

    # Estimated log10(TTC) = entropy_bits × log10(2) − 10
    # (assumes MD5 hash‑rate ≈ 10^10 guesses / second)
    log10_2 = math.log10(2)
    y_ttc = df["entropy_bits"].values * log10_2 - 10
    y_ttc = np.clip(y_ttc, 0, None)  # floor at 0

    return X, y_zxcvbn, y_ttc, FEATURES, df


def train_and_evaluate(X, y, random_state=42):
    """Split, fit, evaluate.  Returns (model, metrics_dict, X_test, y_test, y_pred)."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state
    )
    model = LinearRegression()
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    metrics = {
        "R²":  round(r2_score(y_test, y_pred), 4),
        "MSE": round(mean_squared_error(y_test, y_pred), 4),
        "MAE": round(mean_absolute_error(y_test, y_pred), 4),
    }
    return model, metrics, X_test, y_test, y_pred


# ── Plotting helpers ────────────────────────────────────────────────────────────

def plot_feature_importance(model_zxcvbn, model_ttc, feature_names, save_path):
    """Horizontal bar chart of regression coefficients for both models."""
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.patch.set_facecolor(BG_COLOR)
    fig.suptitle("Feature Importance (Linear Regression Coefficients)",
                 color=TEXT_COLOR, fontsize=16, fontweight="bold", y=0.98)

    for ax, model, title, color in zip(
        axes,
        [model_zxcvbn, model_ttc],
        ["Target: zxcvbn Score", "Target: log₁₀(TTC)"],
        [ACCENT_1, ACCENT_2],
    ):
        coefs = model.coef_
        order = np.argsort(np.abs(coefs))
        sorted_names = [feature_names[i] for i in order]
        sorted_coefs = coefs[order]

        bars = ax.barh(sorted_names, sorted_coefs, color=color, edgecolor=color, alpha=0.85)
        _style_axis(ax, title=title, xlabel="Coefficient Value")
        # value labels
        for bar, val in zip(bars, sorted_coefs):
            ax.text(
                val + (0.01 * np.sign(val) * max(abs(sorted_coefs))),
                bar.get_y() + bar.get_height() / 2,
                f"{val:.3f}",
                va="center", ha="left" if val >= 0 else "right",
                color=TEXT_COLOR, fontsize=8,
            )

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(save_path, dpi=150, facecolor=BG_COLOR, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ Saved: {save_path}")


def plot_actual_vs_predicted(y_test_z, y_pred_z, y_test_t, y_pred_t, save_path):
    """Scatter: actual vs predicted for both models."""
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.patch.set_facecolor(BG_COLOR)
    fig.suptitle("Actual vs Predicted",
                 color=TEXT_COLOR, fontsize=16, fontweight="bold", y=0.98)

    data_pairs = [
        (y_test_z, y_pred_z, "zxcvbn Score", ACCENT_1),
        (y_test_t, y_pred_t, "log₁₀(TTC)", ACCENT_2),
    ]
    for ax, (yt, yp, label, clr) in zip(axes, data_pairs):
        ax.scatter(yt, yp, alpha=0.4, s=12, color=clr, edgecolors="none")
        lo = min(yt.min(), yp.min())
        hi = max(yt.max(), yp.max())
        ax.plot([lo, hi], [lo, hi], "--", color="#f0883e", linewidth=1.2, label="Ideal")
        _style_axis(ax, title=f"Target: {label}", xlabel="Actual", ylabel="Predicted")
        ax.legend(facecolor=BG_COLOR, edgecolor=SPINE_COLOR, labelcolor=TEXT_COLOR)

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(save_path, dpi=150, facecolor=BG_COLOR, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ Saved: {save_path}")


def plot_residuals(y_test_z, y_pred_z, y_test_t, y_pred_t, save_path):
    """Residuals (predicted − actual) vs predicted."""
    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.patch.set_facecolor(BG_COLOR)
    fig.suptitle("Residual Analysis",
                 color=TEXT_COLOR, fontsize=16, fontweight="bold", y=0.98)

    data_pairs = [
        (y_test_z, y_pred_z, "zxcvbn Score", ACCENT_1),
        (y_test_t, y_pred_t, "log₁₀(TTC)", ACCENT_2),
    ]
    for ax, (yt, yp, label, clr) in zip(axes, data_pairs):
        residuals = yp - yt
        ax.scatter(yp, residuals, alpha=0.4, s=12, color=clr, edgecolors="none")
        ax.axhline(0, color="#f0883e", linewidth=1.2, linestyle="--")
        _style_axis(ax, title=f"Target: {label}", xlabel="Predicted", ylabel="Residual")

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(save_path, dpi=150, facecolor=BG_COLOR, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ Saved: {save_path}")


# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    """Run the full regression analysis pipeline."""
    os.makedirs(GRAPHS_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 70)
    print("  LINEAR REGRESSION ANALYSIS – Password Strength Research")
    print("=" * 70)

    # 1. Load data
    print("\n[1/6] Loading dataset …")
    X, y_zxcvbn, y_ttc, feat_names, df = load_data()
    print(f"      Samples : {X.shape[0]}")
    print(f"      Features: {X.shape[1]}  →  {feat_names}")

    # 2. Train models
    print("\n[2/6] Training zxcvbn‑score model …")
    model_z, met_z, Xt_z, yt_z, yp_z = train_and_evaluate(X, y_zxcvbn)
    print(f"      R² = {met_z['R²']:.4f}  |  MSE = {met_z['MSE']:.4f}  |  MAE = {met_z['MAE']:.4f}")

    print("\n[3/6] Training log₁₀(TTC) model …")
    model_t, met_t, Xt_t, yt_t, yp_t = train_and_evaluate(X, y_ttc)
    print(f"      R² = {met_t['R²']:.4f}  |  MSE = {met_t['MSE']:.4f}  |  MAE = {met_t['MAE']:.4f}")

    # 3. Feature importance
    print("\n[4/6] Generating feature importance chart …")
    plot_feature_importance(
        model_z, model_t, feat_names,
        os.path.join(GRAPHS_DIR, "feature_importance.png"),
    )

    # 4. Actual vs predicted
    print("[5/6] Generating actual vs predicted plot …")
    plot_actual_vs_predicted(
        yt_z, yp_z, yt_t, yp_t,
        os.path.join(GRAPHS_DIR, "regression_actual_vs_predicted.png"),
    )

    # 5. Residuals
    print("[6/6] Generating residuals plot …")
    plot_residuals(
        yt_z, yp_z, yt_t, yp_t,
        os.path.join(GRAPHS_DIR, "regression_residuals.png"),
    )

    # 6. Save metrics CSV
    results_df = pd.DataFrame({
        "metric": ["R²", "MSE", "MAE"],
        "zxcvbn_model": [met_z["R²"], met_z["MSE"], met_z["MAE"]],
        "ttc_model":    [met_t["R²"], met_t["MSE"], met_t["MAE"]],
    })
    results_df.to_csv(RESULTS_CSV, index=False)
    print(f"\n  ✓ Metrics saved: {RESULTS_CSV}")

    # 7. Console summary
    print("\n" + "─" * 70)
    print("  MODEL SUMMARY")
    print("─" * 70)
    print(f"  {'Metric':<8} {'zxcvbn Model':>14} {'TTC Model':>14}")
    print(f"  {'─'*8} {'─'*14} {'─'*14}")
    for m in ["R²", "MSE", "MAE"]:
        print(f"  {m:<8} {met_z[m]:>14.4f} {met_t[m]:>14.4f}")

    print("\n  Feature coefficients (zxcvbn model):")
    for name, coef in sorted(
        zip(feat_names, model_z.coef_), key=lambda x: abs(x[1]), reverse=True
    ):
        print(f"    {name:<16} {coef:>+10.4f}")

    print(f"\n  Intercept (zxcvbn) : {model_z.intercept_:>+10.4f}")
    print(f"  Intercept (TTC)    : {model_t.intercept_:>+10.4f}")
    print("=" * 70)
    print("  Analysis complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
