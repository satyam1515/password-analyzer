"""
clean_datasets.py
-----------------
Password Dataset Cleaning and Feature Engineering Pipeline.

Loads raw_passwords.csv, performs data cleaning, computes strength metrics
using Person 1's existing modules (rules_checker, entropy_calculator,
pattern_detector, zxcvbn_analyzer, hybrid_metric), and outputs enriched
datasets ready for analysis.

Cleaning Steps:
    1. Remove duplicate passwords
    2. Remove empty / whitespace-only passwords
    3. Remove passwords longer than 128 characters
    4. Compute strength features using all five analysis modules
    5. Add character composition columns

Outputs:
    datasets/cleaned_passwords.csv     — all passwords with computed features
    datasets/password_statistics.csv   — summary statistics


"""

import csv
import os
import sys
from collections import Counter

# ── Add project root to sys.path so we can import Person 1's modules ────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from modules.rules_checker import evaluate_rules
from modules.entropy_calculator import calculate_entropy
from modules.pattern_detector import detect_patterns
from modules.zxcvbn_analyzer import analyze_zxcvbn
from modules.hybrid_metric import compute_hybrid

# ── File Paths ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(SCRIPT_DIR, "raw_passwords.csv")
CLEANED_FILE = os.path.join(SCRIPT_DIR, "cleaned_passwords.csv")
STATS_FILE = os.path.join(SCRIPT_DIR, "password_statistics.csv")


# =============================================================================
# Step 1: Load and Clean Raw Data
# =============================================================================

def load_raw_passwords(filepath):
    """
    Load passwords from the raw CSV file.

    Args:
        filepath (str): Path to raw_passwords.csv.

    Returns:
        list[dict]: List of password records with 'password' and 'source_category'.
    """
    records = []
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append({
                'password': row['password'],
                'source_category': row['source_category'],
            })
    return records


def clean_passwords(records):
    """
    Clean the password dataset by removing duplicates, blanks, and outliers.

    Args:
        records (list[dict]): Raw password records.

    Returns:
        tuple: (cleaned_records, cleaning_stats)
    """
    original_count = len(records)
    stats = {
        'original_count': original_count,
        'empty_removed': 0,
        'duplicate_removed': 0,
        'too_long_removed': 0,
    }

    # Step 1: Remove empty or whitespace-only passwords
    filtered = []
    for rec in records:
        pw = rec['password']
        if pw is None or pw.strip() == '':
            stats['empty_removed'] += 1
        else:
            filtered.append(rec)

    # Step 2: Remove passwords longer than 128 characters
    length_filtered = []
    for rec in filtered:
        if len(rec['password']) > 128:
            stats['too_long_removed'] += 1
        else:
            length_filtered.append(rec)

    # Step 3: Remove duplicates (keep first occurrence)
    seen = set()
    unique = []
    for rec in length_filtered:
        pw = rec['password']
        if pw not in seen:
            seen.add(pw)
            unique.append(rec)
        else:
            stats['duplicate_removed'] += 1

    stats['cleaned_count'] = len(unique)
    return unique, stats


# =============================================================================
# Step 2: Compute Strength Features
# =============================================================================

def compute_features(password):
    """
    Compute all strength features for a single password using Person 1's modules.

    Args:
        password (str): The password to analyse.

    Returns:
        dict: Dictionary of computed feature values.
    """
    # Run each analysis module
    rules_result = evaluate_rules(password)
    entropy_result = calculate_entropy(password)
    pattern_result = detect_patterns(password)
    zxcvbn_result = analyze_zxcvbn(password)

    # 5. Hybrid Model Computation
    hybrid_result = compute_hybrid(
        rules_score=rules_result['score'],
        entropy_score=entropy_result['score'],
        dict_aware_score=zxcvbn_result['normalized_score'],
        pattern_score=pattern_result['pattern_score'],
        crack_resist_score=min(100, int(entropy_result['entropy']))
    )

    # Character composition analysis
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    return {
        'length': len(password),
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_special': has_special,
        'rules_score': rules_result['score'],
        'rules_classification': rules_result['classification'],
        'entropy_bits': entropy_result['entropy'],
        'entropy_score': entropy_result['score'],
        'entropy_classification': entropy_result['classification'],
        'pattern_score': pattern_result['pattern_score'],
        'has_pattern': pattern_result['has_pattern'],
        'zxcvbn_score': zxcvbn_result['normalized_score'],
        'hybrid_score': hybrid_result['hybrid_score'],
        'hybrid_classification': hybrid_result['classification'],
    }


def process_dataset(records):
    """
    Process all password records by computing features.

    Args:
        records (list[dict]): Cleaned password records.

    Returns:
        list[dict]: Records enriched with computed features.
    """
    total = len(records)
    enriched = []

    print(f"  Processing {total:,} passwords...")
    print(f"  {'─' * 50}")

    for idx, rec in enumerate(records):
        if (idx + 1) % 1000 == 0 or idx == 0 or (idx + 1) == total:
            progress = ((idx + 1) / total) * 100
            print(f"    [{idx + 1:>6,} / {total:,}]  {progress:5.1f}%  ", end='')
            print(f"Current: {rec['password'][:20]}..." if len(rec['password']) > 20 else f"Current: {rec['password']}")

        features = compute_features(rec['password'])
        enriched_record = {
            'password': rec['password'],
            'source_category': rec['source_category'],
            **features,
        }
        enriched.append(enriched_record)

    return enriched


# =============================================================================
# Step 3: Generate Summary Statistics
# =============================================================================

def compute_summary_statistics(enriched_records):
    """
    Compute summary statistics for the cleaned dataset.

    Args:
        enriched_records (list[dict]): Enriched password records.

    Returns:
        list[dict]: Summary statistics as key-value pairs.
    """
    total = len(enriched_records)
    if total == 0:
        return [{'metric': 'total_passwords', 'value': '0'}]

    # Basic statistics
    lengths = [r['length'] for r in enriched_records]
    avg_length = sum(lengths) / total
    min_length = min(lengths)
    max_length = max(lengths)

    # Character type distribution
    upper_count = sum(1 for r in enriched_records if r['has_upper'])
    lower_count = sum(1 for r in enriched_records if r['has_lower'])
    digit_count = sum(1 for r in enriched_records if r['has_digit'])
    special_count = sum(1 for r in enriched_records if r['has_special'])

    # Score averages
    avg_rules = sum(r['rules_score'] for r in enriched_records) / total
    avg_entropy = sum(r['entropy_bits'] for r in enriched_records) / total
    avg_hybrid = sum(r['hybrid_score'] for r in enriched_records) / total

    # Classification distribution
    rules_cls = Counter(r['rules_classification'] for r in enriched_records)
    entropy_cls = Counter(r['entropy_classification'] for r in enriched_records)
    hybrid_cls = Counter(r['hybrid_classification'] for r in enriched_records)

    # Pattern statistics
    pattern_count = sum(1 for r in enriched_records if r['has_pattern'])

    # Most common passwords (by length)
    length_dist = Counter(r['length'] for r in enriched_records)
    most_common_length = length_dist.most_common(1)[0][0]

    # Source category distribution
    source_dist = Counter(r['source_category'] for r in enriched_records)

    # Build statistics list
    stats = [
        {'metric': 'total_passwords', 'value': str(total)},
        {'metric': 'avg_length', 'value': f'{avg_length:.2f}'},
        {'metric': 'min_length', 'value': str(min_length)},
        {'metric': 'max_length', 'value': str(max_length)},
        {'metric': 'most_common_length', 'value': str(most_common_length)},
        {'metric': 'pct_has_uppercase', 'value': f'{(upper_count / total) * 100:.1f}%'},
        {'metric': 'pct_has_lowercase', 'value': f'{(lower_count / total) * 100:.1f}%'},
        {'metric': 'pct_has_digit', 'value': f'{(digit_count / total) * 100:.1f}%'},
        {'metric': 'pct_has_special', 'value': f'{(special_count / total) * 100:.1f}%'},
        {'metric': 'pct_has_patterns', 'value': f'{(pattern_count / total) * 100:.1f}%'},
        {'metric': 'avg_rules_score', 'value': f'{avg_rules:.2f}'},
        {'metric': 'avg_entropy_bits', 'value': f'{avg_entropy:.2f}'},
        {'metric': 'avg_hybrid_score', 'value': f'{avg_hybrid:.2f}'},
    ]

    # Add classification breakdown
    for cls_name, cls_counter, prefix in [
        ('rules', rules_cls, 'rules_classification'),
        ('entropy', entropy_cls, 'entropy_classification'),
        ('hybrid', hybrid_cls, 'hybrid_classification'),
    ]:
        for label, count in cls_counter.most_common():
            pct = (count / total) * 100
            stats.append({
                'metric': f'{prefix}_{label}',
                'value': f'{count} ({pct:.1f}%)',
            })

    # Add source category breakdown
    for cat, count in source_dist.most_common():
        pct = (count / total) * 100
        stats.append({
            'metric': f'source_{cat}',
            'value': f'{count} ({pct:.1f}%)',
        })

    return stats


# =============================================================================
# Step 4: Save Outputs
# =============================================================================

def save_cleaned_csv(enriched_records, filepath):
    """
    Save the enriched password dataset to a CSV file.

    Args:
        enriched_records (list[dict]): Enriched records.
        filepath (str): Output file path.
    """
    if not enriched_records:
        print("  [!] No records to save.")
        return

    fieldnames = [
        'password', 'source_category', 'length',
        'has_upper', 'has_lower', 'has_digit', 'has_special',
        'rules_score', 'rules_classification',
        'entropy_bits', 'entropy_score', 'entropy_classification',
        'pattern_score', 'has_pattern',
        'zxcvbn_score',
        'hybrid_score', 'hybrid_classification',
    ]

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in enriched_records:
            writer.writerow(rec)

    print(f"  [OK] Saved {len(enriched_records):,} records to {filepath}")


def save_statistics_csv(stats, filepath):
    """
    Save summary statistics to a CSV file.

    Args:
        stats (list[dict]): Summary statistics.
        filepath (str): Output file path.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['metric', 'value'])
        writer.writeheader()
        for row in stats:
            writer.writerow(row)

    print(f"  [OK] Saved statistics to {filepath}")


# =============================================================================
# Main Pipeline
# =============================================================================

def run_pipeline():
    """
    Execute the full data cleaning and feature engineering pipeline.
    """
    print("=" * 70)
    print("  PASSWORD DATASET CLEANING & FEATURE ENGINEERING PIPELINE")
    print("=" * 70)
    print()

    # ── Step 1: Load raw data ─────────────────────────────────────────────────
    print("[Step 1/4] Loading raw password dataset...")
    if not os.path.exists(INPUT_FILE):
        print(f"  [X] Error: Input file not found at {INPUT_FILE}")
        print(f"     Please run collect_datasets.py first.")
        sys.exit(1)

    records = load_raw_passwords(INPUT_FILE)
    print(f"  > Loaded {len(records):,} raw passwords")
    print()

    # ── Step 2: Clean data ────────────────────────────────────────────────────
    print("[Step 2/4] Cleaning dataset...")
    cleaned, cleaning_stats = clean_passwords(records)
    print(f"  > Original count:     {cleaning_stats['original_count']:>6,}")
    print(f"  > Empty removed:      {cleaning_stats['empty_removed']:>6,}")
    print(f"  > Duplicates removed: {cleaning_stats['duplicate_removed']:>6,}")
    print(f"  > Too long removed:   {cleaning_stats['too_long_removed']:>6,}")
    print(f"  > Final clean count:  {cleaning_stats['cleaned_count']:>6,}")
    print()

    # ── Step 3: Compute features ──────────────────────────────────────────────
    print("[Step 3/4] Computing strength features using analysis modules...")
    enriched = process_dataset(cleaned)
    print(f"  > Features computed for {len(enriched):,} passwords")
    print()

    # ── Step 4: Save outputs ──────────────────────────────────────────────────
    print("[Step 4/4] Saving outputs...")
    save_cleaned_csv(enriched, CLEANED_FILE)

    statistics = compute_summary_statistics(enriched)
    save_statistics_csv(statistics, STATS_FILE)
    print()

    # ── Print Summary Report ──────────────────────────────────────────────────
    print("=" * 70)
    print("  SUMMARY REPORT")
    print("=" * 70)
    print()

    for stat in statistics:
        metric = stat['metric'].replace('_', ' ').title()
        print(f"  {metric:<40} {stat['value']}")

    print()
    print("=" * 70)
    print("  Pipeline completed successfully!")
    print("=" * 70)


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    run_pipeline()
