"""
ttc_analysis.py
---------------
Part 7 – Time-To-Crack (TTC) Analysis for the Password Strength
Research Project.

Estimates how long each password would take to crack under various
hashing algorithms, produces scatter/CDF plots, and exports a
comprehensive CSV.

Author: Password Strength Research Project
"""

import sys, os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from modules.zxcvbn_analyzer import analyze_zxcvbn

# ── Dark-theme colour palette ──────────────────────────────────────────────────
BG       = "#0d1117"
TEXT     = "#c9d1d9"
BLUE     = "#58a6ff"
GREEN    = "#3fb950"
ORANGE   = "#f0a500"
RED      = "#ff7b72"
PURPLE   = "#bc8cff"
CYAN     = "#39d5ff"

CATEGORY_COLORS = {
    "Instant":   RED,
    "Seconds":   ORANGE,
    "Minutes":   "#e8b004",
    "Hours":     PURPLE,
    "Days":      CYAN,
    "Years":     BLUE,
    "Centuries": GREEN,
}

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

# ── Hash rates (guesses per second) ────────────────────────────────────────────
HASH_RATES = {
    "md5":    1e10,
    "sha1":   5e9,
    "sha256": 2e9,
    "bcrypt": 1e4,
}

# ── TTC category thresholds (in seconds) ──────────────────────────────────────
TTC_THRESHOLDS = [
    (1,            "Instant"),
    (60,           "Seconds"),
    (3600,         "Minutes"),
    (86400,        "Hours"),
    (31536000,     "Days"),       # 1 year
    (3153600000,   "Years"),      # 100 years
    (np.inf,       "Centuries"),
]


def load_data() -> pd.DataFrame:
    """Load the cleaned password dataset."""
    df = pd.read_csv(DATA_PATH)
    print(f"✅  Loaded {len(df):,} passwords from {DATA_PATH}\n")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# TTC helpers
# ──────────────────────────────────────────────────────────────────────────────
def entropy_to_seconds(entropy_bits: float, hash_rate: float) -> float:
    """Convert entropy bits to crack time in seconds.

    Uses 2^entropy / (2 * hash_rate) for average case but the spec says
    2^entropy / hash_rate, so we follow the spec.
    """
    try:
        keyspace = 2.0 ** entropy_bits
    except OverflowError:
        return np.inf
    if np.isinf(keyspace) or np.isnan(keyspace):
        return np.inf
    return keyspace / hash_rate


def categorise_ttc(seconds: float) -> str:
    """Map crack-time seconds to a human-readable category."""
    for threshold, label in TTC_THRESHOLDS:
        if seconds < threshold:
            return label
    return "Centuries"


def seconds_to_human(seconds: float) -> str:
    """Convert seconds to a human-readable duration string."""
    if np.isinf(seconds) or seconds > 1e30:
        return "∞ (heat death)"
    if seconds < 1:
        return "< 1 second"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    if seconds < 3153600000:
        return f"{seconds / 31536000:.1f} years"
    if seconds < 3.1536e13:
        return f"{seconds / 3153600000:.1f} centuries"
    return f"{seconds / 31536000:.2e} years"


# ──────────────────────────────────────────────────────────────────────────────
# Compute TTC columns
# ──────────────────────────────────────────────────────────────────────────────
def compute_ttc(df: pd.DataFrame) -> pd.DataFrame:
    """Add TTC columns to the DataFrame."""
    print("  ⏳  Computing entropy-based TTC …")

    # Vectorised entropy → seconds (using bcrypt for categorisation)
    for algo, rate in HASH_RATES.items():
        col = f"ttc_{algo}_seconds"
        df[col] = df["entropy_bits"].apply(lambda e, r=rate: entropy_to_seconds(e, r))

    # Human-readable columns
    for algo in HASH_RATES:
        sec_col  = f"ttc_{algo}_seconds"
        human_col = f"ttc_{algo}"
        df[human_col] = df[sec_col].apply(seconds_to_human)

    # TTC category (based on bcrypt)
    df["ttc_category"] = df["ttc_bcrypt_seconds"].apply(categorise_ttc)

    # Fetch zxcvbn guesses for each password
    print("  ⏳  Fetching zxcvbn guesses (this may take a moment) …")
    guesses_list = []
    passwords = df["password"].astype(str).tolist()
    for i, pw in enumerate(passwords):
        try:
            result = analyze_zxcvbn(pw)
            guesses_list.append(float(result.get("guesses", 0)))
        except Exception:
            guesses_list.append(0.0)
        if (i + 1) % 500 == 0:
            print(f"      … processed {i + 1:,} / {len(passwords):,}")

    df["zxcvbn_guesses"] = guesses_list
    for algo, rate in HASH_RATES.items():
        df[f"ttc_zxcvbn_{algo}_seconds"] = df["zxcvbn_guesses"] / rate

    print("  ✅  TTC computation complete.\n")
    return df


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH A – Entropy vs Crack Time (bcrypt, log-scale y)
# ──────────────────────────────────────────────────────────────────────────────
def plot_entropy_vs_crack_time(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))

    # Use log10 of bcrypt seconds (clip to avoid log(0))
    log_ttc = np.log10(df["ttc_bcrypt_seconds"].clip(lower=1e-10))
    log_ttc = log_ttc.replace([np.inf, -np.inf], np.nan).fillna(log_ttc[np.isfinite(log_ttc)].max())

    colors = df["ttc_category"].map(CATEGORY_COLORS).fillna(TEXT)
    ax.scatter(df["entropy_bits"], log_ttc, c=colors, alpha=0.4, s=10, edgecolors="none")
    ax.set_xlabel("Entropy (bits)")
    ax.set_ylabel("log₁₀( Crack Time in seconds )  [bcrypt]")
    ax.set_title("Entropy vs Time-To-Crack (bcrypt)")

    # Add reference lines
    ref_lines = {
        "1 hour":    np.log10(3600),
        "1 day":     np.log10(86400),
        "1 year":    np.log10(31536000),
        "100 years": np.log10(3153600000),
    }
    for label, val in ref_lines.items():
        ax.axhline(val, color=ORANGE, linestyle=":", linewidth=0.8, alpha=0.6)
        ax.text(df["entropy_bits"].max() * 0.98, val + 0.3, label,
                ha="right", fontsize=8, color=ORANGE, alpha=0.8)

    # Legend for categories
    from matplotlib.lines import Line2D
    handles = [Line2D([0], [0], marker="o", color="w", markerfacecolor=c,
               markersize=7, label=cat, linestyle="None")
               for cat, c in CATEGORY_COLORS.items()]
    ax.legend(handles=handles, loc="upper left", fontsize=8, framealpha=0.7)

    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "entropy_vs_crack_time.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH B – Rules Score vs Crack Time
# ──────────────────────────────────────────────────────────────────────────────
def plot_rules_vs_crack_time(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    log_ttc = np.log10(df["ttc_bcrypt_seconds"].clip(lower=1e-10))
    log_ttc = log_ttc.replace([np.inf, -np.inf], np.nan).fillna(log_ttc[np.isfinite(log_ttc)].max())

    colors = df["ttc_category"].map(CATEGORY_COLORS).fillna(TEXT)
    ax.scatter(df["rules_score"], log_ttc, c=colors, alpha=0.4, s=10, edgecolors="none")
    ax.set_xlabel("Rules Score (0–100)")
    ax.set_ylabel("log₁₀( Crack Time in seconds )  [bcrypt]")
    ax.set_title("Rules Score vs Time-To-Crack (bcrypt)")
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "rules_score_vs_crack_time.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH C – Password Length vs Crack Time
# ──────────────────────────────────────────────────────────────────────────────
def plot_length_vs_crack_time(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    log_ttc = np.log10(df["ttc_bcrypt_seconds"].clip(lower=1e-10))
    log_ttc = log_ttc.replace([np.inf, -np.inf], np.nan).fillna(log_ttc[np.isfinite(log_ttc)].max())

    colors = df["ttc_category"].map(CATEGORY_COLORS).fillna(TEXT)
    ax.scatter(df["length"], log_ttc, c=colors, alpha=0.4, s=10, edgecolors="none")
    ax.set_xlabel("Password Length")
    ax.set_ylabel("log₁₀( Crack Time in seconds )  [bcrypt]")
    ax.set_title("Password Length vs Time-To-Crack (bcrypt)")
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "length_vs_crack_time.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH D – Hybrid Score vs Crack Time
# ──────────────────────────────────────────────────────────────────────────────
def plot_hybrid_vs_crack_time(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    log_ttc = np.log10(df["ttc_bcrypt_seconds"].clip(lower=1e-10))
    log_ttc = log_ttc.replace([np.inf, -np.inf], np.nan).fillna(log_ttc[np.isfinite(log_ttc)].max())

    colors = df["ttc_category"].map(CATEGORY_COLORS).fillna(TEXT)
    ax.scatter(df["hybrid_score"], log_ttc, c=colors, alpha=0.4, s=10, edgecolors="none")
    ax.set_xlabel("Hybrid Score (0–100)")
    ax.set_ylabel("log₁₀( Crack Time in seconds )  [bcrypt]")
    ax.set_title("Hybrid Score vs Time-To-Crack (bcrypt)")
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "hybrid_score_vs_crack_time.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# GRAPH E – CDF of Crack Times (bcrypt)
# ──────────────────────────────────────────────────────────────────────────────
def plot_crack_time_cdf(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))

    finite = df["ttc_bcrypt_seconds"][np.isfinite(df["ttc_bcrypt_seconds"])]
    sorted_ttc = np.sort(finite.values)
    cdf = np.arange(1, len(sorted_ttc) + 1) / len(sorted_ttc)
    log_ttc = np.log10(np.clip(sorted_ttc, 1e-10, None))

    ax.plot(log_ttc, cdf, color=CYAN, linewidth=2)
    ax.fill_between(log_ttc, cdf, alpha=0.15, color=CYAN)
    ax.set_xlabel("log₁₀( Crack Time in seconds )  [bcrypt]")
    ax.set_ylabel("Cumulative Proportion")
    ax.set_title("CDF of Password Crack Times (bcrypt)")
    ax.set_ylim(0, 1.02)

    # Reference lines
    refs = {"1 sec": 0, "1 min": np.log10(60), "1 hr": np.log10(3600),
            "1 day": np.log10(86400), "1 yr": np.log10(31536000),
            "100 yr": np.log10(3153600000)}
    for lbl, val in refs.items():
        ax.axvline(val, color=ORANGE, linestyle=":", linewidth=0.8, alpha=0.5)
        ax.text(val, 1.03, lbl, ha="center", fontsize=7, color=ORANGE, alpha=0.8)

    ax.grid(axis="y", color=TEXT, alpha=0.1)
    plt.tight_layout()
    path = os.path.join(GRAPHS_DIR, "crack_time_cdf.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"  📊  Saved {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Export CSV
# ──────────────────────────────────────────────────────────────────────────────
def export_csv(df: pd.DataFrame) -> None:
    """Save analysis CSV with TTC results."""
    out_cols = [
        "password", "entropy_bits", "rules_score", "hybrid_score", "length",
        "ttc_md5", "ttc_sha256", "ttc_bcrypt", "ttc_category",
    ]
    out_path = os.path.join(ANALYSIS_DIR, "ttc_analysis.csv")
    df[out_cols].to_csv(out_path, index=False)
    print(f"\n  💾  Saved TTC analysis → {out_path}  ({len(df):,} rows)")


# ──────────────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────────────
def print_summary(df: pd.DataFrame) -> None:
    sep = "=" * 65
    print(f"\n{sep}")
    print("  📋  TIME-TO-CRACK SUMMARY STATISTICS")
    print(sep)

    # Category distribution
    print(f"\n  ── TTC Category Distribution (bcrypt) ──")
    cat_order = ["Instant", "Seconds", "Minutes", "Hours", "Days", "Years", "Centuries"]
    cat_counts = df["ttc_category"].value_counts()
    for cat in cat_order:
        cnt = cat_counts.get(cat, 0)
        pct = cnt / len(df) * 100
        print(f"  {cat:<12}: {cnt:>6,}  ({pct:5.1f}%)")

    # Key stats
    finite_bcrypt = df["ttc_bcrypt_seconds"][np.isfinite(df["ttc_bcrypt_seconds"])]
    if len(finite_bcrypt) > 0:
        print(f"\n  ── Crack Time Statistics (bcrypt, finite values) ──")
        print(f"  Mean   : {seconds_to_human(finite_bcrypt.mean())}")
        print(f"  Median : {seconds_to_human(finite_bcrypt.median())}")

    # Key percentages
    lt_1hr = (df["ttc_bcrypt_seconds"] < 3600).sum()
    gt_100yr = (df["ttc_bcrypt_seconds"] > 3153600000).sum()
    print(f"\n  ── Key Thresholds ──")
    print(f"  Crackable in < 1 hour  : {lt_1hr:>6,}  ({lt_1hr/len(df)*100:.1f}%)")
    print(f"  Requires > 100 years   : {gt_100yr:>6,}  ({gt_100yr/len(df)*100:.1f}%)")

    print(f"\n{sep}\n")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    os.makedirs(GRAPHS_DIR, exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)

    df = load_data()
    df = compute_ttc(df)

    print_summary(df)

    print("  🖼️  Generating graphs …\n")
    plot_entropy_vs_crack_time(df)
    plot_rules_vs_crack_time(df)
    plot_length_vs_crack_time(df)
    plot_hybrid_vs_crack_time(df)
    plot_crack_time_cdf(df)

    export_csv(df)

    print(f"\n  ✅  TTC analysis complete.")
    print(f"  📁  Outputs: {GRAPHS_DIR}/  and  {ANALYSIS_DIR}/\n")


if __name__ == "__main__":
    main()
