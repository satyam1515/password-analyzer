"""
eda_analysis.py
---------------
Part 2 – Exploratory Data Analysis (EDA) for the Password Strength
Research Project.

Generates 8 publication-quality graphs and prints summary statistics.
All visuals follow the project's dark theme colour palette.

Author: Password Strength Research Project
"""

import sys, os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

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

# ── Global matplotlib defaults ─────────────────────────────────────────────────
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

GRAPHS_DIR = os.path.join(PROJECT_ROOT, "graphs")
DATA_PATH  = os.path.join(PROJECT_ROOT, "datasets", "cleaned_passwords.csv")


def load_data() -> pd.DataFrame:
    """Load the cleaned password dataset."""
    df = pd.read_csv(DATA_PATH)
    print(f"✅  Loaded {len(df):,} passwords from {DATA_PATH}\n")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 1 – Password Length Distribution (Histogram)
# ──────────────────────────────────────────────────────────────────────────────
def plot_length_distribution(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 5))
    max_len = int(df["length"].quantile(0.99))  # trim extreme outliers
    bins = range(0, max_len + 2)
    ax.hist(df["length"], bins=bins, color=BLUE, edgecolor=BG, alpha=0.85)
    ax.set_xlabel("Password Length")
    ax.set_ylabel("Frequency")
    ax.set_title("Password Length Distribution")
    ax.axvline(df["length"].median(), color=ORANGE, linestyle="--", linewidth=1.5,
               label=f'Median = {df["length"].median():.0f}')
    ax.axvline(df["length"].mean(), color=RED, linestyle="--", linewidth=1.5,
               label=f'Mean = {df["length"].mean():.1f}')
    ax.legend()
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "password_length_distribution.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 2 – Character Type Usage (Pie Chart)
# ──────────────────────────────────────────────────────────────────────────────
def plot_character_type_usage(df: pd.DataFrame) -> None:
    labels = ["Uppercase", "Lowercase", "Digits", "Symbols"]
    cols   = ["has_upper", "has_lower", "has_digit", "has_special"]
    sizes  = [df[c].sum() for c in cols]
    colors = [BLUE, GREEN, ORANGE, PURPLE]
    explode = (0.04, 0.04, 0.04, 0.04)

    fig, ax = plt.subplots(figsize=(7, 7))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, explode=explode,
        autopct="%1.1f%%", startangle=140,
        textprops={"color": TEXT, "fontsize": 12},
        pctdistance=0.78
    )
    for at in autotexts:
        at.set_fontsize(10)
        at.set_color(BG)
        at.set_fontweight("bold")
    ax.set_title("Character Type Usage Across Passwords")
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "character_type_usage.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 3 – Source Category Distribution (Bar Chart)
# ──────────────────────────────────────────────────────────────────────────────
def plot_source_category_distribution(df: pd.DataFrame) -> None:
    counts = df["source_category"].value_counts()
    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(counts.index, counts.values, color=ACCENT[:len(counts)],
                  edgecolor=BG, alpha=0.9)
    ax.set_xlabel("Source Category")
    ax.set_ylabel("Number of Passwords")
    ax.set_title("Password Distribution by Source Category")
    ax.tick_params(axis="x", rotation=30)
    # value labels
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + counts.max() * 0.01,
                f"{int(h):,}", ha="center", va="bottom", fontsize=9, color=TEXT)
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "source_category_distribution.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 4 – Top 20 Most Common Passwords (Horizontal Bar Chart)
# ──────────────────────────────────────────────────────────────────────────────
def plot_top_passwords(df: pd.DataFrame) -> None:
    top = df["password"].value_counts().head(20).sort_values()
    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(top.index.astype(str), top.values, color=CYAN, edgecolor=BG, alpha=0.85)
    ax.set_xlabel("Frequency")
    ax.set_title("Top 20 Most Common Passwords")
    for bar in bars:
        w = bar.get_width()
        ax.text(w + top.max() * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{int(w):,}", ha="left", va="center", fontsize=9, color=TEXT)
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "top_20_common_passwords.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 5 – Password Length vs Rules Score (Scatter)
# ──────────────────────────────────────────────────────────────────────────────
def plot_length_vs_rules(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(df["length"], df["rules_score"], c=BLUE, alpha=0.3, s=8, edgecolors="none")
    ax.set_xlabel("Password Length")
    ax.set_ylabel("Rules Score (0–100)")
    ax.set_title("Password Length vs Rules Score")

    # trend line
    z = np.polyfit(df["length"], df["rules_score"], 1)
    p = np.poly1d(z)
    x_line = np.linspace(df["length"].min(), df["length"].max(), 200)
    ax.plot(x_line, p(x_line), color=ORANGE, linewidth=2, linestyle="--",
            label=f"Trend (slope={z[0]:.2f})")
    ax.legend()
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "length_vs_rules_score.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 6 – Password Length vs Entropy (Scatter)
# ──────────────────────────────────────────────────────────────────────────────
def plot_length_vs_entropy(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(df["length"], df["entropy_bits"], c=GREEN, alpha=0.3, s=8, edgecolors="none")
    ax.set_xlabel("Password Length")
    ax.set_ylabel("Entropy (bits)")
    ax.set_title("Password Length vs Entropy")

    z = np.polyfit(df["length"], df["entropy_bits"], 1)
    p = np.poly1d(z)
    x_line = np.linspace(df["length"].min(), df["length"].max(), 200)
    ax.plot(x_line, p(x_line), color=ORANGE, linewidth=2, linestyle="--",
            label=f"Trend (slope={z[0]:.2f})")
    ax.legend()
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "length_vs_entropy.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 7 – Character Category Distribution (Stacked Bar Chart)
# ──────────────────────────────────────────────────────────────────────────────
def plot_char_category_stacked(df: pd.DataFrame) -> None:
    categories = df["source_category"].unique()
    char_cols  = ["has_upper", "has_lower", "has_digit", "has_special"]
    char_names = ["Uppercase", "Lowercase", "Digits", "Symbols"]
    colors     = [BLUE, GREEN, ORANGE, PURPLE]

    # compute percentages
    pct_data = {}
    for cat in categories:
        sub = df[df["source_category"] == cat]
        pct_data[cat] = [(sub[c].sum() / len(sub)) * 100 for c in char_cols]

    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(categories))
    width = 0.55
    bottom = np.zeros(len(categories))

    for i, (name, color) in enumerate(zip(char_names, colors)):
        vals = [pct_data[cat][i] for cat in categories]
        ax.bar(x, vals, width, bottom=bottom, label=name, color=color,
               edgecolor=BG, alpha=0.9)
        bottom += np.array(vals)

    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=30, ha="right")
    ax.set_ylabel("Percentage of Passwords (%)")
    ax.set_title("Character Category Distribution by Source")
    ax.legend(loc="upper right")
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "character_category_distribution.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 8 – Score Distributions (Overlaid Histograms)
# ──────────────────────────────────────────────────────────────────────────────
def plot_score_distributions(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 5))
    bins = np.arange(0, 105, 5)
    ax.hist(df["rules_score"], bins=bins, color=BLUE, alpha=0.55, label="Rules Score",
            edgecolor=BG)
    ax.hist(df["entropy_score"], bins=bins, color=GREEN, alpha=0.55, label="Entropy Score",
            edgecolor=BG)
    ax.hist(df["hybrid_score"], bins=bins, color=ORANGE, alpha=0.55, label="Hybrid Score",
            edgecolor=BG)
    ax.set_xlabel("Score (0–100)")
    ax.set_ylabel("Frequency")
    ax.set_title("Score Distributions (Rules · Entropy · Hybrid)")
    ax.legend()
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "score_distributions.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Summary Statistics
# ──────────────────────────────────────────────────────────────────────────────
def print_summary(df: pd.DataFrame) -> None:
    sep = "=" * 65
    print(f"\n{sep}")
    print("  📋  SUMMARY STATISTICS")
    print(sep)

    print(f"\n  Total passwords analysed : {len(df):,}")
    print(f"  Unique passwords         : {df['password'].nunique():,}")
    print(f"  Duplicate passwords      : {len(df) - df['password'].nunique():,}")

    # Length statistics
    print(f"\n  ── Password Length ──")
    print(f"  Mean   : {df['length'].mean():.2f}")
    print(f"  Median : {df['length'].median():.0f}")
    print(f"  Std    : {df['length'].std():.2f}")
    print(f"  Min    : {df['length'].min()}")
    print(f"  Max    : {df['length'].max()}")

    # Character type percentages
    print(f"\n  ── Character Type Presence ──")
    for col, label in [("has_upper", "Uppercase"), ("has_lower", "Lowercase"),
                       ("has_digit", "Digits"), ("has_special", "Symbols")]:
        pct = df[col].mean() * 100
        print(f"  {label:<12}: {pct:6.2f}%  ({df[col].sum():,} passwords)")

    # Score distributions
    print(f"\n  ── Score Summary (mean ± std) ──")
    for col, label in [("rules_score", "Rules Score"),
                       ("entropy_score", "Entropy Score"),
                       ("hybrid_score", "Hybrid Score")]:
        print(f"  {label:<15}: {df[col].mean():6.2f} ± {df[col].std():.2f}")

    # Classification distributions
    print(f"\n  ── Rules Classification ──")
    for cls, cnt in df["rules_classification"].value_counts().items():
        print(f"  {cls:<12}: {cnt:>6,}  ({cnt/len(df)*100:.1f}%)")

    print(f"\n  ── Entropy Classification ──")
    for cls, cnt in df["entropy_classification"].value_counts().items():
        print(f"  {cls:<12}: {cnt:>6,}  ({cnt/len(df)*100:.1f}%)")

    print(f"\n  ── Hybrid Classification ──")
    for cls, cnt in df["hybrid_classification"].value_counts().items():
        print(f"  {cls:<12}: {cnt:>6,}  ({cnt/len(df)*100:.1f}%)")

    # Source category
    print(f"\n  ── Source Categories ──")
    for cat, cnt in df["source_category"].value_counts().items():
        print(f"  {cat:<20}: {cnt:>6,}  ({cnt/len(df)*100:.1f}%)")

    print(f"\n{sep}\n")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    os.makedirs(GRAPHS_DIR, exist_ok=True)

    df = load_data()
    print_summary(df)

    print("  🖼️  Generating graphs …\n")
    plot_length_distribution(df)
    plot_character_type_usage(df)
    plot_source_category_distribution(df)
    plot_top_passwords(df)
    plot_length_vs_rules(df)
    plot_length_vs_entropy(df)
    plot_char_category_stacked(df)
    plot_score_distributions(df)

    print(f"\n  ✅  All 8 EDA graphs saved to {GRAPHS_DIR}/")


if __name__ == "__main__":
    main()
