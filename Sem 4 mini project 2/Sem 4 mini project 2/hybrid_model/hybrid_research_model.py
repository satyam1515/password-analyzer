"""
hybrid_research_model.py  (Part 10)
────────────────────────────────────
Person 2's Hybrid Password Strength Model.

Weights (30/30/20/10/10):
    30 %  Rules Score
    30 %  Entropy Score
    20 %  Dictionary Awareness  (zxcvbn‑based)
    10 %  Pattern Detection
    10 %  Crack Resistance      (entropy‑derived TTC)

Compares with Person 1's hybrid (30/30/30/10) already stored in the CSV
and produces comparison graphs + summary CSVs.

Author : Student Research Team – Person 2
Date   : June 2026
"""

import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

# ── Paths ───────────────────────────────────────────────────────────────────────
DATASET_PATH = os.path.join(PROJECT_ROOT, "datasets", "cleaned_passwords.csv")
GRAPHS_DIR   = os.path.join(PROJECT_ROOT, "graphs")
OUTPUT_DIR   = os.path.join(PROJECT_ROOT, "hybrid_model")

# ── Dark‑theme palette ──────────────────────────────────────────────────────────
BG       = "#0d1117"
TEXT     = "#c9d1d9"
ACCENT_P1 = "#58a6ff"   # Person 1  – blue
ACCENT_P2 = "#f78166"   # Person 2  – orange
GRID     = "#21262d"
SPINE    = "#30363d"

# ── Person 2 weights ───────────────────────────────────────────────────────────
W_RULES   = 0.30
W_ENTROPY = 0.30
W_DICT    = 0.20
W_PATTERN = 0.10
W_CRACK   = 0.10

# ── Classification thresholds (Person 2) ────────────────────────────────────────
CLASS_ORDER = ["Weak", "Medium", "Strong", "Very Strong"]


def classify_p2(score: float) -> str:
    """Classify a Person 2 hybrid score."""
    if score <= 30:
        return "Weak"
    elif score <= 55:
        return "Medium"
    elif score <= 80:
        return "Strong"
    else:
        return "Very Strong"


def _style(ax, title="", xlabel="", ylabel=""):
    """Apply dark‑theme styling."""
    ax.set_facecolor(BG)
    ax.set_title(title, color=TEXT, fontsize=14, fontweight="bold", pad=12)
    ax.set_xlabel(xlabel, color=TEXT, fontsize=11)
    ax.set_ylabel(ylabel, color=TEXT, fontsize=11)
    ax.tick_params(colors=TEXT, labelsize=9)
    for s in ax.spines.values():
        s.set_color(SPINE)
    ax.grid(True, color=GRID, linestyle="--", linewidth=0.5, alpha=0.7)


# ── Core computation ───────────────────────────────────────────────────────────

def compute_person2_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Add Person 2 hybrid score & classification columns to *df*."""
    # Dictionary awareness score  ── proxy: zxcvbn_score is already 0‑100
    df["dict_awareness"] = df["zxcvbn_score"].clip(0, 100)

    # Crack resistance score  ── entropy‑based, capped at 100
    df["crack_resistance"] = df["entropy_bits"].clip(0, 100)

    # Hybrid score
    df["p2_hybrid"] = (
        W_RULES   * df["rules_score"]
        + W_ENTROPY * df["entropy_score"]
        + W_DICT    * df["dict_awareness"]
        + W_PATTERN * df["pattern_score"]
        + W_CRACK   * df["crack_resistance"]
    ).round(2).clip(0, 100)

    df["p2_class"] = df["p2_hybrid"].apply(classify_p2)
    return df


# ── Plotting ────────────────────────────────────────────────────────────────────

def scatter_comparison(df, save_path):
    """Person 1 vs Person 2 hybrid scatter with diagonal."""
    fig, ax = plt.subplots(figsize=(8, 8))
    fig.patch.set_facecolor(BG)

    ax.scatter(df["hybrid_score"], df["p2_hybrid"],
               alpha=0.35, s=14, color=ACCENT_P1, edgecolors="none", label="Passwords")
    ax.plot([0, 100], [0, 100], "--", color=ACCENT_P2, linewidth=1.2, label="y = x")
    _style(ax,
           title="Hybrid Score Comparison: Person 1 vs Person 2",
           xlabel="Person 1 Hybrid Score",
           ylabel="Person 2 Hybrid Score")
    ax.legend(facecolor=BG, edgecolor=SPINE, labelcolor=TEXT)
    ax.set_xlim(-2, 102)
    ax.set_ylim(-2, 102)

    plt.tight_layout()
    fig.savefig(save_path, dpi=150, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ Saved: {save_path}")


def distribution_overlay(df, save_path):
    """Overlapping histograms of both hybrid scores."""
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG)

    bins = np.arange(0, 105, 5)
    ax.hist(df["hybrid_score"], bins=bins, alpha=0.55, color=ACCENT_P1,
            edgecolor=ACCENT_P1, linewidth=0.6, label="Person 1 (30/30/30/10)")
    ax.hist(df["p2_hybrid"], bins=bins, alpha=0.55, color=ACCENT_P2,
            edgecolor=ACCENT_P2, linewidth=0.6, label="Person 2 (30/30/20/10/10)")
    _style(ax,
           title="Hybrid Score Distribution Comparison",
           xlabel="Hybrid Score",
           ylabel="Frequency")
    ax.legend(facecolor=BG, edgecolor=SPINE, labelcolor=TEXT, fontsize=10)

    plt.tight_layout()
    fig.savefig(save_path, dpi=150, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ Saved: {save_path}")


def agreement_matrix(df, save_path):
    """Classification agreement heatmap (confusion matrix style)."""
    # Build confusion matrix
    labels = CLASS_ORDER
    matrix = pd.DataFrame(0, index=labels, columns=labels)
    for _, row in df.iterrows():
        p1_cls = row["hybrid_classification"]
        p2_cls = row["p2_class"]
        if p1_cls in labels and p2_cls in labels:
            matrix.loc[p1_cls, p2_cls] += 1

    fig, ax = plt.subplots(figsize=(8, 7))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    # Custom colormap
    cmap = LinearSegmentedColormap.from_list("dark_blue", [BG, ACCENT_P1])
    data = matrix.values.astype(float)
    im = ax.imshow(data, cmap=cmap, aspect="auto")

    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, color=TEXT, fontsize=10, rotation=30, ha="right")
    ax.set_yticklabels(labels, color=TEXT, fontsize=10)
    ax.set_xlabel("Person 2 Classification", color=TEXT, fontsize=11)
    ax.set_ylabel("Person 1 Classification", color=TEXT, fontsize=11)
    ax.set_title("Classification Agreement Matrix", color=TEXT, fontsize=14,
                 fontweight="bold", pad=12)

    # Annotate cells
    for i in range(len(labels)):
        for j in range(len(labels)):
            val = int(data[i, j])
            text_clr = BG if val > data.max() * 0.6 else TEXT
            ax.text(j, i, str(val), ha="center", va="center",
                    color=text_clr, fontsize=12, fontweight="bold")

    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.ax.yaxis.set_tick_params(color=TEXT)
    cbar.ax.set_ylabel("Count", color=TEXT)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=TEXT)

    for s in ax.spines.values():
        s.set_color(SPINE)

    plt.tight_layout()
    fig.savefig(save_path, dpi=150, facecolor=BG, bbox_inches="tight")
    plt.close(fig)
    print(f"  ✓ Saved: {save_path}")


# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(GRAPHS_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 70)
    print("  HYBRID MODEL COMPARISON – Person 1 vs Person 2")
    print("=" * 70)

    # 1. Load & compute
    print("\n[1/5] Loading dataset …")
    df = pd.read_csv(DATASET_PATH)
    print(f"      Loaded {len(df)} passwords.")

    print("[2/5] Computing Person 2 hybrid scores …")
    df = compute_person2_scores(df)

    # 3. Graphs
    print("[3/5] Generating comparison graphs …")
    scatter_comparison(df, os.path.join(GRAPHS_DIR, "hybrid_comparison_scatter.png"))
    distribution_overlay(df, os.path.join(GRAPHS_DIR, "hybrid_comparison_distribution.png"))
    agreement_matrix(df, os.path.join(GRAPHS_DIR, "hybrid_agreement_matrix.png"))

    # 4. Agreement rate
    df["agreement"] = (df["hybrid_classification"] == df["p2_class"]).astype(int)
    agreement_rate = df["agreement"].mean() * 100

    # 5. Correlation
    corr = df["hybrid_score"].corr(df["p2_hybrid"])

    # 6. Save comparison CSV
    comp_csv = os.path.join(OUTPUT_DIR, "hybrid_comparison.csv")
    df[["password", "hybrid_score", "hybrid_classification",
        "p2_hybrid", "p2_class", "agreement"]].to_csv(comp_csv, index=False)
    print(f"  ✓ Saved: {comp_csv}")

    # 7. Save evaluation CSV
    eval_data = {
        "metric": [
            "Person 1 Mean Hybrid",
            "Person 2 Mean Hybrid",
            "Person 1 Std Dev",
            "Person 2 Std Dev",
            "Pearson Correlation",
            "Agreement Rate (%)",
            "Person 1 Median",
            "Person 2 Median",
            "Mean Absolute Difference",
        ],
        "value": [
            round(df["hybrid_score"].mean(), 2),
            round(df["p2_hybrid"].mean(), 2),
            round(df["hybrid_score"].std(), 2),
            round(df["p2_hybrid"].std(), 2),
            round(corr, 4),
            round(agreement_rate, 2),
            round(df["hybrid_score"].median(), 2),
            round(df["p2_hybrid"].median(), 2),
            round((df["hybrid_score"] - df["p2_hybrid"]).abs().mean(), 2),
        ],
    }
    eval_csv = os.path.join(OUTPUT_DIR, "model_evaluation.csv")
    pd.DataFrame(eval_data).to_csv(eval_csv, index=False)
    print(f"  ✓ Saved: {eval_csv}")

    # Console summary
    print("\n" + "─" * 70)
    print("  MODEL COMPARISON SUMMARY")
    print("─" * 70)
    print(f"  Person 1 weights : 30% Rules / 30% Entropy / 30% zxcvbn / 10% Pattern")
    print(f"  Person 2 weights : 30% Rules / 30% Entropy / 20% Dict‑Aware / 10% Pattern / 10% Crack‑Resist")
    print(f"  {'─'*50}")
    print(f"  {'Metric':<30} {'Person 1':>10} {'Person 2':>10}")
    print(f"  {'─'*30} {'─'*10} {'─'*10}")
    print(f"  {'Mean Hybrid Score':<30} {df['hybrid_score'].mean():>10.2f} {df['p2_hybrid'].mean():>10.2f}")
    print(f"  {'Std Dev':<30} {df['hybrid_score'].std():>10.2f} {df['p2_hybrid'].std():>10.2f}")
    print(f"  {'Median':<30} {df['hybrid_score'].median():>10.2f} {df['p2_hybrid'].median():>10.2f}")
    print(f"  {'─'*50}")
    print(f"  Pearson Correlation   : {corr:.4f}")
    print(f"  Agreement Rate        : {agreement_rate:.2f}%")
    print(f"  Mean |Δ|              : {(df['hybrid_score'] - df['p2_hybrid']).abs().mean():.2f}")

    # Classification distribution
    print(f"\n  Classification Distribution:")
    print(f"  {'Class':<14} {'Person 1':>10} {'Person 2':>10}")
    print(f"  {'─'*14} {'─'*10} {'─'*10}")
    for cls in CLASS_ORDER:
        p1_cnt = (df["hybrid_classification"] == cls).sum()
        p2_cnt = (df["p2_class"] == cls).sum()
        print(f"  {cls:<14} {p1_cnt:>10} {p2_cnt:>10}")

    print("\n" + "=" * 70)
    print("  Analysis complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
