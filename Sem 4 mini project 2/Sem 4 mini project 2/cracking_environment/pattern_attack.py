"""
==========================================================
pattern_attack.py
==========================================================
Pattern-Based Attack Analysis

Tests passwords containing keyboard patterns and measures
their vulnerability to pattern-based cracking attacks.

Compares crack success rates between patterned and
non-patterned passwords.

Research Project: A Comparative Analysis of Password Strength
Metrics: Rules-Based vs. Entropy-Based Evaluation

Usage:
    python cracking_environment/pattern_attack.py

Author: Research Project Team (Person 2)
==========================================================
"""

import sys
import os
import re
import time
import math

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# ── Dark theme colours ──────────────────────────────────────────
BG_COLOR   = '#0d1117'
CARD_COLOR = '#161b22'
TEXT_COLOR = '#c9d1d9'
GRID_COLOR = '#30363d'
BLUE       = '#58a6ff'
GREEN      = '#3fb950'
ORANGE     = '#f0a500'
RED        = '#ff7b72'
PURPLE     = '#bc8cff'
CYAN       = '#39d5ff'


# ── Known keyboard patterns for attack simulation ──────────────
ATTACK_PATTERNS = [
    # Horizontal QWERTY rows
    'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl',
    'zxcvbn', 'zxcvbnm', 'qwert', 'asdfg',
    # Numeric sequences
    '123456', '1234567', '12345678', '123456789', '1234567890',
    '654321', '0987654321', '987654',
    # Keyboard walks (column-wise)
    '1qaz2wsx', '2wsx3edc', '1qaz', '3edc4rfv',
    'qazwsx', 'wsxedc', 'edcrfv',
    '1q2w3e', '1q2w3e4r', '1q2w3e4r5t',
    # Mixed well-known
    'qwerty123', 'password', 'password1', 'password123',
    'abc123', 'abcdef', 'abcdefgh',
    'iloveyou', 'trustno1', 'letmein',
    'admin123', 'welcome1', 'monkey123',
    # Repeated characters
    'aaaaaa', 'bbbbbb', '111111', '000000',
    'aaaa', 'bbbb', '1111', '0000',
    # Symbol sequences
    '!@#$%^', '!@#$%', '!@#$',
]

# Regex patterns for sequential detection
SEQ_DIGITS_RE = re.compile(
    r'(0123|1234|2345|3456|4567|5678|6789|7890|'
    r'9876|8765|7654|6543|5432|4321|3210)',
    re.IGNORECASE
)
SEQ_ALPHA_RE = re.compile(
    r'(abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|'
    r'klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|'
    r'uvwx|vwxy|wxyz|zyxw|yxwv|xwvu|wvut|vuts|utsr|tsrq|'
    r'srqp|rqpo|qpon|ponm|onml|nmlk|mlkj|lkji|kjihg|jihg|'
    r'ihgf|hgfe|gfed|fedc|edcb|dcba)',
    re.IGNORECASE
)
REPEAT_RE = re.compile(r'(.)\1{2,}')


def detect_attack_patterns(password: str) -> dict:
    """
    Detect if a password contains attackable patterns.
    
    Returns:
        dict with pattern info and estimated crack difficulty.
    """
    pw_lower = password.lower()
    found_patterns = []
    
    # Check known patterns
    for pattern in ATTACK_PATTERNS:
        if pattern in pw_lower:
            found_patterns.append(('known', pattern))
    
    # Check sequential digits
    if SEQ_DIGITS_RE.search(pw_lower):
        found_patterns.append(('sequential_digits', SEQ_DIGITS_RE.search(pw_lower).group()))
    
    # Check sequential alpha
    if SEQ_ALPHA_RE.search(pw_lower):
        found_patterns.append(('sequential_alpha', SEQ_ALPHA_RE.search(pw_lower).group()))
    
    # Check repeated characters
    repeat_match = REPEAT_RE.search(password)
    if repeat_match:
        found_patterns.append(('repeated', repeat_match.group()))
    
    has_pattern = len(found_patterns) > 0
    
    # Estimate crack difficulty
    if has_pattern:
        # Passwords with known patterns are cracked very quickly
        # Common patterns are in the first few thousand guesses
        pattern_types = set(p[0] for p in found_patterns)
        
        if 'known' in pattern_types:
            # Known patterns: cracked in first ~10,000 guesses
            estimated_guesses = 10_000
            crack_category = 'Instant'
        elif 'sequential_digits' in pattern_types or 'sequential_alpha' in pattern_types:
            # Sequential patterns: cracked within ~100,000 guesses
            estimated_guesses = 100_000
            crack_category = 'Seconds'
        else:
            # Repeated chars: cracked within ~50,000 guesses
            estimated_guesses = 50_000
            crack_category = 'Seconds'
    else:
        # No patterns: use entropy-based estimation
        charset = 0
        if any(c.islower() for c in password): charset += 26
        if any(c.isupper() for c in password): charset += 26
        if any(c.isdigit() for c in password): charset += 10
        if any(not c.isalnum() for c in password): charset += 32
        charset = max(charset, 1)
        
        estimated_guesses = charset ** len(password)
        
        # Categorize
        ttc_seconds = estimated_guesses / 1e10  # MD5 rate
        if ttc_seconds < 1:
            crack_category = 'Instant'
        elif ttc_seconds < 60:
            crack_category = 'Seconds'
        elif ttc_seconds < 3600:
            crack_category = 'Minutes'
        elif ttc_seconds < 86400:
            crack_category = 'Hours'
        elif ttc_seconds < 365.25 * 86400:
            crack_category = 'Days'
        elif ttc_seconds < 100 * 365.25 * 86400:
            crack_category = 'Years'
        else:
            crack_category = 'Centuries'
    
    return {
        'has_pattern': has_pattern,
        'patterns': found_patterns,
        'pattern_count': len(found_patterns),
        'estimated_guesses': estimated_guesses,
        'crack_category': crack_category,
        'cracked_by_pattern': has_pattern,  # Assume all patterned passwords are cracked
    }


def run_pattern_attack():
    """Run the full pattern attack analysis."""
    print("=" * 66)
    print("  🔓 Pattern-Based Attack Analysis")
    print("=" * 66)
    
    # ── Load dataset ────────────────────────────────────────────
    csv_path = os.path.join(PROJECT_ROOT, 'datasets', 'cleaned_passwords.csv')
    if not os.path.exists(csv_path):
        print(f"\n  ✗ Dataset not found: {csv_path}")
        print("    Run datasets/collect_datasets.py and datasets/clean_datasets.py first.")
        return
    
    df = pd.read_csv(csv_path)
    total = len(df)
    print(f"\n  Loaded {total:,} passwords from dataset.\n")
    
    # ── Run pattern detection on all passwords ──────────────────
    print("  Analyzing passwords for patterns...")
    start_time = time.time()
    
    results = []
    for _, row in df.iterrows():
        password = str(row['password'])
        attack_result = detect_attack_patterns(password)
        
        results.append({
            'password': password,
            'has_pattern': attack_result['has_pattern'],
            'pattern_count': attack_result['pattern_count'],
            'estimated_guesses': min(attack_result['estimated_guesses'], 1e30),
            'crack_category': attack_result['crack_category'],
            'cracked_by_pattern': attack_result['cracked_by_pattern'],
            'rules_score': row.get('rules_score', 0),
            'entropy_bits': row.get('entropy_bits', 0),
            'entropy_score': row.get('entropy_score', 0),
            'rules_classification': row.get('rules_classification', 'Weak'),
            'entropy_classification': row.get('entropy_classification', 'Weak'),
            'pattern_score': row.get('pattern_score', 100),
            'length': row.get('length', len(password)),
        })
    
    results_df = pd.DataFrame(results)
    elapsed = time.time() - start_time
    print(f"  Analysis completed in {elapsed:.1f}s\n")
    
    # ── Calculate statistics ────────────────────────────────────
    patterned = results_df[results_df['has_pattern'] == True]
    non_patterned = results_df[results_df['has_pattern'] == False]
    
    patterned_count = len(patterned)
    non_patterned_count = len(non_patterned)
    patterned_cracked = patterned['cracked_by_pattern'].sum()
    
    print("  ── Pattern Attack Results ──────────────────────────")
    print(f"  Total passwords analyzed:      {total:,}")
    print(f"  Passwords WITH patterns:       {patterned_count:,} ({patterned_count/total*100:.1f}%)")
    print(f"  Passwords WITHOUT patterns:    {non_patterned_count:,} ({non_patterned_count/total*100:.1f}%)")
    print(f"  Pattern-cracked passwords:     {patterned_cracked:,} ({patterned_cracked/total*100:.1f}%)")
    print()
    
    # ── Crack category breakdown ────────────────────────────────
    print("  ── Crack Time Categories (Patterned) ──────────────")
    if len(patterned) > 0:
        cat_counts = patterned['crack_category'].value_counts()
        for cat, count in cat_counts.items():
            pct = count / len(patterned) * 100
            print(f"    {cat:<15s}: {count:>6,} ({pct:.1f}%)")
    print()
    
    print("  ── Crack Time Categories (Non-Patterned) ──────────")
    if len(non_patterned) > 0:
        cat_counts = non_patterned['crack_category'].value_counts()
        for cat, count in cat_counts.items():
            pct = count / len(non_patterned) * 100
            print(f"    {cat:<15s}: {count:>6,} ({pct:.1f}%)")
    print()
    
    # ── Rules score comparison ──────────────────────────────────
    print("  ── Average Scores Comparison ──────────────────────")
    if len(patterned) > 0:
        print(f"    Patterned passwords:")
        print(f"      Avg Rules Score:   {patterned['rules_score'].mean():.1f}")
        print(f"      Avg Entropy (bits): {patterned['entropy_bits'].mean():.1f}")
        print(f"      Avg Pattern Score: {patterned['pattern_score'].mean():.1f}")
    if len(non_patterned) > 0:
        print(f"    Non-patterned passwords:")
        print(f"      Avg Rules Score:   {non_patterned['rules_score'].mean():.1f}")
        print(f"      Avg Entropy (bits): {non_patterned['entropy_bits'].mean():.1f}")
        print(f"      Avg Pattern Score: {non_patterned['pattern_score'].mean():.1f}")
    print()
    
    # ── False positive analysis ─────────────────────────────────
    if len(patterned) > 0:
        strong_by_rules = patterned[patterned['rules_classification'] == 'Strong']
        print(f"  ⚠ Patterned passwords rated 'Strong' by Rules: {len(strong_by_rules):,}")
        if len(strong_by_rules) > 0:
            print("    Examples (first 10):")
            for _, row in strong_by_rules.head(10).iterrows():
                print(f"      '{row['password']}' (Rules: {row['rules_score']}, Entropy: {row['entropy_bits']:.1f} bits)")
    print()
    
    # ── Save results ────────────────────────────────────────────
    output_path = os.path.join(PROJECT_ROOT, 'cracking_environment', 'pattern_attack_results.csv')
    results_df.to_csv(output_path, index=False)
    print(f"  ✓ Results saved to: {output_path}")
    
    # ── Generate graphs ─────────────────────────────────────────
    graphs_dir = os.path.join(PROJECT_ROOT, 'graphs')
    os.makedirs(graphs_dir, exist_ok=True)
    
    _generate_success_rate_chart(results_df, graphs_dir)
    _generate_comparison_chart(patterned, non_patterned, graphs_dir)
    _generate_crack_category_chart(results_df, graphs_dir)
    
    print(f"\n  ✓ All graphs saved to: {graphs_dir}")
    print("\n" + "=" * 66)


def _generate_success_rate_chart(df, graphs_dir):
    """Generate pattern attack success rate by classification."""
    fig, ax = plt.subplots(figsize=(10, 6), dpi=150)
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)
    
    # Group by rules classification
    classifications = ['Weak', 'Medium', 'Strong']
    patterned_rates = []
    total_counts = []
    
    for cls in classifications:
        subset = df[df['rules_classification'] == cls]
        if len(subset) > 0:
            rate = subset['cracked_by_pattern'].mean() * 100
            patterned_rates.append(rate)
            total_counts.append(len(subset))
        else:
            patterned_rates.append(0)
            total_counts.append(0)
    
    x = np.arange(len(classifications))
    colors = [RED, ORANGE, GREEN]
    
    bars = ax.bar(x, patterned_rates, width=0.5, color=colors,
                  edgecolor=BG_COLOR, linewidth=1.5, alpha=0.9, zorder=3)
    
    # Value labels
    for bar, rate, count in zip(bars, patterned_rates, total_counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f'{rate:.1f}%\n(n={count:,})',
                ha='center', va='bottom', color=TEXT_COLOR,
                fontsize=10, fontweight='bold')
    
    ax.set_xticks(x)
    ax.set_xticklabels(classifications, color=TEXT_COLOR, fontsize=11)
    ax.set_ylabel('Pattern Attack Success Rate (%)', color=TEXT_COLOR, fontsize=11)
    ax.set_title('Pattern Attack Success Rate by Rules Classification',
                 color=CYAN, fontsize=14, fontweight='bold', pad=15)
    ax.set_ylim(0, max(patterned_rates) * 1.25 if patterned_rates else 100)
    ax.tick_params(colors=TEXT_COLOR)
    ax.spines[:].set_color(GRID_COLOR)
    ax.yaxis.grid(True, color=GRID_COLOR, linestyle='--', alpha=0.4, zorder=0)
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    filepath = os.path.join(graphs_dir, 'pattern_attack_success_rate.png')
    fig.savefig(filepath, facecolor=BG_COLOR, edgecolor='none', bbox_inches='tight')
    plt.close(fig)
    print(f"  ✓ Saved: {filepath}")


def _generate_comparison_chart(patterned, non_patterned, graphs_dir):
    """Generate patterned vs non-patterned comparison chart."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 6), dpi=150)
    fig.patch.set_facecolor(BG_COLOR)
    fig.suptitle('Patterned vs Non-Patterned Passwords',
                 color=CYAN, fontsize=15, fontweight='bold', y=1.02)
    
    # ── Left: Average scores comparison ─────────────────────────
    ax1 = axes[0]
    ax1.set_facecolor(BG_COLOR)
    
    metrics = ['Rules Score', 'Entropy Score', 'Pattern Score']
    if len(patterned) > 0 and len(non_patterned) > 0:
        patterned_avgs = [
            patterned['rules_score'].mean(),
            patterned['entropy_score'].mean(),
            patterned['pattern_score'].mean(),
        ]
        non_patterned_avgs = [
            non_patterned['rules_score'].mean(),
            non_patterned['entropy_score'].mean(),
            non_patterned['pattern_score'].mean(),
        ]
    else:
        patterned_avgs = [0, 0, 0]
        non_patterned_avgs = [0, 0, 0]
    
    x = np.arange(len(metrics))
    width = 0.3
    
    bars1 = ax1.bar(x - width/2, patterned_avgs, width, color=RED,
                    label='With Patterns', alpha=0.85, zorder=3)
    bars2 = ax1.bar(x + width/2, non_patterned_avgs, width, color=GREEN,
                    label='No Patterns', alpha=0.85, zorder=3)
    
    # Value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                     f'{bar.get_height():.0f}', ha='center', va='bottom',
                     color=TEXT_COLOR, fontsize=9, fontweight='bold')
    
    ax1.set_xticks(x)
    ax1.set_xticklabels(metrics, color=TEXT_COLOR, fontsize=10)
    ax1.set_ylabel('Average Score', color=TEXT_COLOR, fontsize=11)
    ax1.set_title('Average Metric Scores', color=BLUE, fontsize=12, fontweight='bold')
    ax1.legend(fontsize=9, facecolor=CARD_COLOR, edgecolor=GRID_COLOR,
               labelcolor=TEXT_COLOR)
    ax1.tick_params(colors=TEXT_COLOR)
    ax1.spines[:].set_color(GRID_COLOR)
    ax1.yaxis.grid(True, color=GRID_COLOR, linestyle='--', alpha=0.4, zorder=0)
    ax1.set_axisbelow(True)
    
    # ── Right: Crack category distribution ──────────────────────
    ax2 = axes[1]
    ax2.set_facecolor(BG_COLOR)
    
    categories_order = ['Instant', 'Seconds', 'Minutes', 'Hours', 'Days', 'Years', 'Centuries']
    
    if len(patterned) > 0:
        pat_cats = patterned['crack_category'].value_counts()
        pat_vals = [pat_cats.get(c, 0) / len(patterned) * 100 for c in categories_order]
    else:
        pat_vals = [0] * len(categories_order)
    
    if len(non_patterned) > 0:
        nopat_cats = non_patterned['crack_category'].value_counts()
        nopat_vals = [nopat_cats.get(c, 0) / len(non_patterned) * 100 for c in categories_order]
    else:
        nopat_vals = [0] * len(categories_order)
    
    x2 = np.arange(len(categories_order))
    bars3 = ax2.bar(x2 - width/2, pat_vals, width, color=RED,
                    label='With Patterns', alpha=0.85, zorder=3)
    bars4 = ax2.bar(x2 + width/2, nopat_vals, width, color=GREEN,
                    label='No Patterns', alpha=0.85, zorder=3)
    
    ax2.set_xticks(x2)
    ax2.set_xticklabels(categories_order, color=TEXT_COLOR, fontsize=8, rotation=30, ha='right')
    ax2.set_ylabel('Percentage (%)', color=TEXT_COLOR, fontsize=11)
    ax2.set_title('Crack Time Distribution', color=BLUE, fontsize=12, fontweight='bold')
    ax2.legend(fontsize=9, facecolor=CARD_COLOR, edgecolor=GRID_COLOR,
               labelcolor=TEXT_COLOR)
    ax2.tick_params(colors=TEXT_COLOR)
    ax2.spines[:].set_color(GRID_COLOR)
    ax2.yaxis.grid(True, color=GRID_COLOR, linestyle='--', alpha=0.4, zorder=0)
    ax2.set_axisbelow(True)
    
    plt.tight_layout()
    filepath = os.path.join(graphs_dir, 'pattern_vs_nopattern.png')
    fig.savefig(filepath, facecolor=BG_COLOR, edgecolor='none', bbox_inches='tight')
    plt.close(fig)
    print(f"  ✓ Saved: {filepath}")


def _generate_crack_category_chart(df, graphs_dir):
    """Generate overall crack category distribution pie chart."""
    fig, ax = plt.subplots(figsize=(8, 8), dpi=150)
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)
    
    categories_order = ['Instant', 'Seconds', 'Minutes', 'Hours', 'Days', 'Years', 'Centuries']
    cat_colors = [RED, '#ff9966', ORANGE, '#ffcc00', GREEN, BLUE, CYAN]
    
    cat_counts = df['crack_category'].value_counts()
    sizes = [cat_counts.get(c, 0) for c in categories_order]
    
    # Filter out zero categories
    filtered = [(c, s, col) for c, s, col in zip(categories_order, sizes, cat_colors) if s > 0]
    if not filtered:
        plt.close(fig)
        return
    
    labels, sizes, colors = zip(*filtered)
    
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct='%1.1f%%',
        startangle=90, pctdistance=0.85,
        wedgeprops=dict(edgecolor=BG_COLOR, linewidth=2),
        textprops=dict(color=TEXT_COLOR, fontsize=10)
    )
    
    for autotext in autotexts:
        autotext.set_fontsize(9)
        autotext.set_fontweight('bold')
    
    # Draw centre circle for donut style
    centre = plt.Circle((0, 0), 0.60, fc=BG_COLOR)
    ax.add_artist(centre)
    
    ax.set_title('Overall Crack Time Distribution (Pattern Attack)',
                 color=CYAN, fontsize=14, fontweight='bold', pad=20)
    
    plt.tight_layout()
    filepath = os.path.join(graphs_dir, 'pattern_crack_distribution.png')
    fig.savefig(filepath, facecolor=BG_COLOR, edgecolor='none', bbox_inches='tight')
    plt.close(fig)
    print(f"  ✓ Saved: {filepath}")


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    run_pattern_attack()
