"""
classification_analysis.py
--------------------------
Part 3 – Classification Analysis for the Password Strength Research Project.

Compares Rules-Based vs Entropy-Based password classifications, identifies
false positives/negatives, and generates confusion matrix visualisations
and classification metrics.

Author: Password Strength Research Project
"""

import sys, os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score

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

CLASS_ORDER  = ["Weak", "Medium", "Strong"]
LABEL_MAP    = {"Weak": 0, "Medium": 1, "Strong": 2, "Very Strong": 2}


def load_data() -> pd.DataFrame:
    """Load the cleaned password dataset."""
    df = pd.read_csv(DATA_PATH)
    print(f"✅  Loaded {len(df):,} passwords from {DATA_PATH}\n")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# Cross-tabulation
# ──────────────────────────────────────────────────────────────────────────────
def cross_tabulation(df: pd.DataFrame) -> pd.DataFrame:
    """Print and return a cross-tabulation of rules vs entropy classifications."""
    ct = pd.crosstab(
        df["rules_classification"],
        df["entropy_classification"],
        margins=True,
        margins_name="Total",
    )
    print("=" * 65)
    print("  📋  CROSS-TABULATION: Rules vs Entropy Classification")
    print("=" * 65)
    print(ct.to_string())
    print()
    return ct


# ──────────────────────────────────────────────────────────────────────────────
# False Positives & False Negatives
# ──────────────────────────────────────────────────────────────────────────────
def identify_misclassifications(df: pd.DataFrame) -> tuple:
    """Find false positives and false negatives relative to entropy baseline."""

    # FALSE POSITIVES: Rules says Strong, Entropy says Weak
    fp_mask = (df["rules_classification"] == "Strong") & (df["entropy_classification"] == "Weak")
    false_positives = df[fp_mask].copy()

    # FALSE NEGATIVES: Rules says Weak, Entropy says Strong or Very Strong
    fn_mask = (df["rules_classification"] == "Weak") & (
        df["entropy_classification"].isin(["Strong", "Very Strong"])
    )
    false_negatives = df[fn_mask].copy()

    # Print summaries
    sep = "-" * 65
    print(sep)
    print(f"  ⚠️  FALSE POSITIVES (Rules=Strong, Entropy=Weak): {len(false_positives):,}")
    print(sep)
    if len(false_positives) > 0:
        sample = false_positives.head(15)[["password", "rules_score", "entropy_bits",
                                           "rules_classification", "entropy_classification"]]
        print(sample.to_string(index=False))
    else:
        print("  None found.")

    print()
    print(sep)
    print(f"  ⚠️  FALSE NEGATIVES (Rules=Weak, Entropy=Strong/Very Strong): {len(false_negatives):,}")
    print(sep)
    if len(false_negatives) > 0:
        sample = false_negatives.head(15)[["password", "rules_score", "entropy_bits",
                                           "rules_classification", "entropy_classification"]]
        print(sample.to_string(index=False))
    else:
        print("  None found.")
    print()

    # Save false positives CSV
    fp_path = os.path.join(ANALYSIS_DIR, "false_positives_examples.csv")
    false_positives.to_csv(fp_path, index=False)
    print(f"  💾  Saved false positives → {fp_path}  ({len(false_positives):,} rows)")

    return false_positives, false_negatives


# ──────────────────────────────────────────────────────────────────────────────
# Confusion Matrix & Classification Report
# ──────────────────────────────────────────────────────────────────────────────
def compute_metrics(df: pd.DataFrame) -> dict:
    """Compute confusion matrix and sklearn classification metrics."""

    # Map to numeric labels (entropy 'Very Strong' → 'Strong' = 2)
    y_true = df["entropy_classification"].map(LABEL_MAP).values
    y_pred = df["rules_classification"].map(LABEL_MAP).values

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2])
    acc = accuracy_score(y_true, y_pred)
    report = classification_report(y_true, y_pred, labels=[0, 1, 2],
                                   target_names=CLASS_ORDER, output_dict=True,
                                   zero_division=0)

    # Print
    print("=" * 65)
    print("  📊  CLASSIFICATION METRICS  (Entropy = Ground Truth)")
    print("=" * 65)
    print(f"\n  Overall Accuracy : {acc:.4f}  ({acc*100:.2f}%)\n")
    print(f"  {'Class':<10} {'Precision':>10} {'Recall':>10} {'F1 Score':>10} {'Support':>10}")
    print(f"  {'-'*50}")
    for cls in CLASS_ORDER:
        r = report[cls]
        print(f"  {cls:<10} {r['precision']:>10.4f} {r['recall']:>10.4f} "
              f"{r['f1-score']:>10.4f} {int(r['support']):>10}")
    print()

    # Save classification report CSV
    rows = []
    for cls in CLASS_ORDER:
        r = report[cls]
        rows.append({
            "class": cls,
            "precision": round(r["precision"], 4),
            "recall": round(r["recall"], 4),
            "f1_score": round(r["f1-score"], 4),
            "support": int(r["support"]),
        })
    rows.append({
        "class": "accuracy",
        "precision": round(acc, 4),
        "recall": round(acc, 4),
        "f1_score": round(acc, 4),
        "support": int(report["weighted avg"]["support"]),
    })
    for avg in ["macro avg", "weighted avg"]:
        r = report[avg]
        rows.append({
            "class": avg,
            "precision": round(r["precision"], 4),
            "recall": round(r["recall"], 4),
            "f1_score": round(r["f1-score"], 4),
            "support": int(r["support"]),
        })
    rpt_path = os.path.join(ANALYSIS_DIR, "classification_report.csv")
    pd.DataFrame(rows).to_csv(rpt_path, index=False)
    print(f"  💾  Saved classification report → {rpt_path}")

    return {"cm": cm, "accuracy": acc, "report": report}


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 1 – Confusion Matrix Heatmap
# ──────────────────────────────────────────────────────────────────────────────
def plot_confusion_matrix(cm: np.ndarray) -> None:
    """Generate an annotated confusion matrix heatmap."""
    fig, ax = plt.subplots(figsize=(7, 6))

    # Create a blue-toned colourmap
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list(
        "dark_blue", ["#0d1117", "#1a3a5c", "#2a6496", "#58a6ff", "#a5d6ff"]
    )

    im = ax.imshow(cm, interpolation="nearest", cmap=cmap, aspect="auto")
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.ax.yaxis.set_tick_params(color=TEXT)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=TEXT)
    cbar.outline.set_edgecolor(TEXT)

    # Annotate cells
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            colour = BG if cm[i, j] > thresh else TEXT
            ax.text(j, i, f"{cm[i, j]:,}",
                    ha="center", va="center", fontsize=14, fontweight="bold",
                    color=colour)

    ax.set_xticks([0, 1, 2])
    ax.set_yticks([0, 1, 2])
    ax.set_xticklabels(CLASS_ORDER, fontsize=12)
    ax.set_yticklabels(CLASS_ORDER, fontsize=12)
    ax.set_xlabel("Predicted Label (Rules-Based)", fontsize=13)
    ax.set_ylabel("True Label (Entropy-Based)", fontsize=13)
    ax.set_title("Confusion Matrix: Rules vs Entropy Classification", fontsize=14, pad=12)

    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "confusion_matrix.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH 2 – Classification Comparison (Grouped Bar)
# ──────────────────────────────────────────────────────────────────────────────
def plot_classification_comparison(df: pd.DataFrame) -> None:
    """Grouped bar chart comparing rules vs entropy classification distributions."""
    # Normalise entropy labels: Very Strong → Strong
    entropy_mapped = df["entropy_classification"].replace("Very Strong", "Strong")

    rules_counts   = df["rules_classification"].value_counts().reindex(CLASS_ORDER, fill_value=0)
    entropy_counts = entropy_mapped.value_counts().reindex(CLASS_ORDER, fill_value=0)

    x = np.arange(len(CLASS_ORDER))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    bars1 = ax.bar(x - width / 2, rules_counts.values, width, label="Rules-Based",
                   color=BLUE, edgecolor=BG, alpha=0.9)
    bars2 = ax.bar(x + width / 2, entropy_counts.values, width, label="Entropy-Based",
                   color=GREEN, edgecolor=BG, alpha=0.9)

    # value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + max(rules_counts.max(),
                    entropy_counts.max()) * 0.01,
                    f"{int(h):,}", ha="center", va="bottom", fontsize=9, color=TEXT)

    ax.set_xticks(x)
    ax.set_xticklabels(CLASS_ORDER, fontsize=12)
    ax.set_ylabel("Number of Passwords")
    ax.set_title("Classification Comparison: Rules vs Entropy")
    ax.legend()
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "classification_comparison.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    os.makedirs(GRAPHS_DIR, exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)

    df = load_data()

    # Step 1: Cross-tabulation
    cross_tabulation(df)

    # Step 2: False positives & negatives
    identify_misclassifications(df)

    # Step 3: Confusion matrix & metrics
    metrics = compute_metrics(df)

    # Step 4: Generate graphs
    print("\n  🖼️  Generating graphs …\n")
    plot_confusion_matrix(metrics["cm"])
    plot_classification_comparison(df)

    print(f"\n  ✅  Classification analysis complete.")
    print(f"  📁  Outputs: {GRAPHS_DIR}/  and  {ANALYSIS_DIR}/\n")


if __name__ == "__main__":
    main()
