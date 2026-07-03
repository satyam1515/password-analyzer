"""
statistical_analysis.py
-----------------------
Part 8 – Statistical / Correlation Analysis for the Password Strength
Research Project.

Computes Pearson and Spearman correlations between numeric password
strength metrics, generates annotated heatmaps and scatter plots, and
exports summary CSVs.

Author: Password Strength Research Project
"""

import sys, os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import TwoSlopeNorm
from scipy.stats import pearsonr, spearmanr
from itertools import combinations

# ── Dark-theme colour palette ──────────────────────────────────────────────────
BG       = "#0d1117"
TEXT     = "#c9d1d9"
BLUE     = "#58a6ff"
GREEN    = "#3fb950"
ORANGE   = "#f0a500"
RED      = "#ff7b72"
PURPLE   = "#bc8cff"
CYAN     = "#39d5ff"
ACCENT   = [BLUE, GREEN, ORANGE, RED, PURPLE, CYAN]

plt.rcParams.update({
    "figure.facecolor":  BG,
    "axes.facecolor":    BG,
    "savefig.facecolor": BG,
    "text.color":        TEXT,
    "axes.labelcolor":   TEXT,
    "xtick.color":       TEXT,
    "ytick.color":       TEXT,
    "axes.edgecolor":    TEXT,
    "legend.facecolor":  BG,
    "legend.edgecolor":  TEXT,
    "legend.labelcolor": TEXT,
    "figure.dpi":        150,
    "savefig.dpi":       150,
    "font.size":         11,
    "axes.titlesize":    14,
    "axes.labelsize":    12,
})

GRAPHS_DIR   = os.path.join(PROJECT_ROOT, "graphs")
ANALYSIS_DIR = os.path.join(PROJECT_ROOT, "analysis")
DATA_PATH    = os.path.join(PROJECT_ROOT, "datasets", "cleaned_passwords.csv")

# Variables to correlate and their display names
VARIABLES = ["entropy_bits", "rules_score", "length", "pattern_score",
             "zxcvbn_score", "hybrid_score"]
LABELS    = {
    "entropy_bits":  "Entropy (bits)",
    "rules_score":   "Rules Score",
    "length":        "Length",
    "pattern_score": "Pattern Score",
    "zxcvbn_score":  "zxcvbn Score",
    "hybrid_score":  "Hybrid Score",
}


def load_data() -> pd.DataFrame:
    """Load the cleaned password dataset."""
    df = pd.read_csv(DATA_PATH)
    print(f"✅  Loaded {len(df):,} passwords from {DATA_PATH}\n")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# Correlation calculations
# ──────────────────────────────────────────────────────────────────────────────
def compute_correlations(df: pd.DataFrame) -> tuple:
    """Compute pair-wise Pearson and Spearman correlations with p-values."""
    pairs = list(combinations(VARIABLES, 2))
    results = []

    for v1, v2 in pairs:
        x = df[v1].dropna()
        y = df[v2].dropna()
        # Align indices
        common = x.index.intersection(y.index)
        x, y = x.loc[common], y.loc[common]

        pr, pp = pearsonr(x, y)
        sr, sp = spearmanr(x, y)
        results.append({
            "variable_1": v1,
            "variable_2": v2,
            "pearson_r":  round(pr, 4),
            "pearson_p":  pp,
            "spearman_r": round(sr, 4),
            "spearman_p": sp,
        })

    corr_df = pd.DataFrame(results)
    return corr_df


def build_matrix(corr_df: pd.DataFrame, col: str) -> pd.DataFrame:
    """Build a symmetric N×N correlation matrix from pair-wise data."""
    n = len(VARIABLES)
    mat = pd.DataFrame(np.eye(n), index=VARIABLES, columns=VARIABLES)
    for _, row in corr_df.iterrows():
        mat.loc[row["variable_1"], row["variable_2"]] = row[col]
        mat.loc[row["variable_2"], row["variable_1"]] = row[col]
    return mat


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH – Correlation Heatmap
# ──────────────────────────────────────────────────────────────────────────────
def plot_correlation_heatmap(pearson_mat: pd.DataFrame) -> None:
    """Annotated correlation matrix heatmap using a diverging colourmap."""
    n = len(VARIABLES)
    fig, ax = plt.subplots(figsize=(9, 8))

    data = pearson_mat.values
    norm = TwoSlopeNorm(vmin=-1, vcenter=0, vmax=1)
    cmap = plt.cm.RdBu_r

    im = ax.imshow(data, cmap=cmap, norm=norm, aspect="auto")
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.ax.yaxis.set_tick_params(color=TEXT)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=TEXT)
    cbar.outline.set_edgecolor(TEXT)

    # Annotate cells
    for i in range(n):
        for j in range(n):
            val = data[i, j]
            colour = "white" if abs(val) > 0.5 else TEXT
            ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                    fontsize=11, fontweight="bold", color=colour)

    nice_labels = [LABELS[v] for v in VARIABLES]
    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(nice_labels, rotation=35, ha="right", fontsize=10)
    ax.set_yticklabels(nice_labels, fontsize=10)
    ax.set_title("Pearson Correlation Matrix", fontsize=15, pad=14)

    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "correlation_heatmap.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPHS – Top-3 Strongest Correlation Scatter Plots
# ──────────────────────────────────────────────────────────────────────────────
def plot_top_scatters(df: pd.DataFrame, corr_df: pd.DataFrame) -> None:
    """Generate scatter plots for the three strongest Pearson correlations."""
    top3 = corr_df.reindex(corr_df["pearson_r"].abs().sort_values(ascending=False).index).head(3)

    for idx, (_, row) in enumerate(top3.iterrows(), start=1):
        v1, v2 = row["variable_1"], row["variable_2"]
        r = row["pearson_r"]

        fig, ax = plt.subplots(figsize=(8, 6))
        color = ACCENT[idx - 1]
        ax.scatter(df[v1], df[v2], c=color, alpha=0.3, s=10, edgecolors="none")
        ax.set_xlabel(LABELS[v1])
        ax.set_ylabel(LABELS[v2])
        ax.set_title(f"{LABELS[v1]} vs {LABELS[v2]}  (r = {r:.3f})", fontsize=13)

        # Trend line
        z = np.polyfit(df[v1].dropna(), df[v2].dropna(), 1)
        p = np.poly1d(z)
        x_line = np.linspace(df[v1].min(), df[v1].max(), 200)
        ax.plot(x_line, p(x_line), color=ORANGE, linewidth=2, linestyle="--",
                label=f"Linear fit (slope={z[0]:.2f})")
        ax.legend(fontsize=9)

        plt.tight_layout()
        path = os.path.join(GRAPHS_DIR, f"scatter_correlation_{idx}.png")
        fig.savefig(path)
        plt.close(fig)
        print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Print correlation tables
# ──────────────────────────────────────────────────────────────────────────────
def print_tables(corr_df: pd.DataFrame, pearson_mat: pd.DataFrame,
                 spearman_mat: pd.DataFrame) -> None:
    sep = "=" * 70
    print(f"\n{sep}")
    print("  📋  PEARSON CORRELATION MATRIX")
    print(sep)
    display = pearson_mat.copy()
    display.index   = [LABELS[v] for v in display.index]
    display.columns = [LABELS[v] for v in display.columns]
    print(display.round(3).to_string())

    print(f"\n{sep}")
    print("  📋  SPEARMAN CORRELATION MATRIX")
    print(sep)
    display = spearman_mat.copy()
    display.index   = [LABELS[v] for v in display.index]
    display.columns = [LABELS[v] for v in display.columns]
    print(display.round(3).to_string())

    # Pearson vs Spearman comparison
    print(f"\n{sep}")
    print("  📋  PEARSON vs SPEARMAN COMPARISON")
    print(sep)
    print(f"\n  {'Variable Pair':<40} {'Pearson r':>10} {'Spearman r':>11} {'Diff':>8}")
    print(f"  {'-' * 70}")
    sorted_df = corr_df.reindex(corr_df["pearson_r"].abs().sort_values(ascending=False).index)
    for _, row in sorted_df.iterrows():
        pair = f"{LABELS[row['variable_1']]} ↔ {LABELS[row['variable_2']]}"
        diff = abs(row["pearson_r"] - row["spearman_r"])
        sig_p = "***" if row["pearson_p"] < 0.001 else ("**" if row["pearson_p"] < 0.01 else
                ("*" if row["pearson_p"] < 0.05 else ""))
        print(f"  {pair:<40} {row['pearson_r']:>9.4f}{sig_p} {row['spearman_r']:>10.4f} {diff:>8.4f}")

    # Top 5 interpretation
    print(f"\n{sep}")
    print("  📋  TOP 5 STRONGEST CORRELATIONS")
    print(sep)
    top5 = sorted_df.head(5)
    for rank, (_, row) in enumerate(top5.iterrows(), 1):
        pair = f"{LABELS[row['variable_1']]} ↔ {LABELS[row['variable_2']]}"
        strength = "very strong" if abs(row["pearson_r"]) > 0.8 else (
            "strong" if abs(row["pearson_r"]) > 0.6 else (
            "moderate" if abs(row["pearson_r"]) > 0.4 else "weak"))
        direction = "positive" if row["pearson_r"] > 0 else "negative"
        sig = "significant" if row["pearson_p"] < 0.05 else "not significant"
        print(f"  {rank}. {pair}")
        print(f"     Pearson r = {row['pearson_r']:.4f} — {strength} {direction} correlation ({sig})")
        print()

    print(sep)


# ──────────────────────────────────────────────────────────────────────────────
# Descriptive Statistics
# ──────────────────────────────────────────────────────────────────────────────
def descriptive_stats(df: pd.DataFrame) -> pd.DataFrame:
    """Compute and print descriptive statistics for all variables."""
    desc = df[VARIABLES].describe().T
    desc.index = [LABELS[v] for v in desc.index]

    print("\n" + "=" * 70)
    print("  📋  DESCRIPTIVE STATISTICS")
    print("=" * 70)
    print(desc.round(3).to_string())
    print()
    return desc


# ──────────────────────────────────────────────────────────────────────────────
# Export
# ──────────────────────────────────────────────────────────────────────────────
def export_results(corr_df: pd.DataFrame, desc: pd.DataFrame) -> None:
    """Save correlation results and statistical summary to CSV."""
    corr_path = os.path.join(ANALYSIS_DIR, "correlation_results.csv")
    corr_df.to_csv(corr_path, index=False)
    print(f"  💾  Saved correlation results → {corr_path}")

    stat_path = os.path.join(ANALYSIS_DIR, "statistical_summary.csv")
    desc.to_csv(stat_path)
    print(f"  💾  Saved statistical summary → {stat_path}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    os.makedirs(GRAPHS_DIR, exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)

    df = load_data()

    # Descriptive statistics
    desc = descriptive_stats(df)

    # Correlations
    corr_df = compute_correlations(df)
    pearson_mat  = build_matrix(corr_df, "pearson_r")
    spearman_mat = build_matrix(corr_df, "spearman_r")

    # Print tables
    print_tables(corr_df, pearson_mat, spearman_mat)

    # Graphs
    print("\n  🖼️  Generating graphs …\n")
    plot_correlation_heatmap(pearson_mat)
    plot_top_scatters(df, corr_df)

    # Export
    export_results(corr_df, desc)

    print(f"\n  ✅  Statistical analysis complete.")
    print(f"  📁  Outputs: {GRAPHS_DIR}/  and  {ANALYSIS_DIR}/\n")


if __name__ == "__main__":
    main()
