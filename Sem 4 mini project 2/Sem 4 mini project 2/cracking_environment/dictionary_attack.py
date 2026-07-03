"""
dictionary_attack.py
--------------------
Simulated Dictionary Attack for Password Cracking Research.

This script simulates a dictionary-based password cracking attack by
comparing passwords against a comprehensive wordlist of common passwords,
dictionary words, and their variations (leetspeak, case changes, suffixes).

The simulation measures:
    - Number of passwords cracked (exact match or variation)
    - Success rate per strength classification
    - Estimated crack time based on hash rate assumptions

Hash Rate Assumptions (modern GPU):
    - MD5:    10,000,000,000 hashes/second (10 B/s)
    - SHA-1:   5,000,000,000 hashes/second (5 B/s)
    - SHA-256:  2,000,000,000 hashes/second (2 B/s)

Output:
    cracking_environment/dictionary_attack_results.csv
    graphs/dictionary_attack_results.png

⚠️  FOR ACADEMIC RESEARCH ONLY.

Author: Password Strength Research Project (Person 2 – Analysis)
"""

import csv
import math
import os
import random
import string
import sys
from collections import Counter, defaultdict

# ── Add project root to sys.path ────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# ── Matplotlib Configuration (must be before pyplot import) ─────────────────────
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt

# ── Reproducibility ─────────────────────────────────────────────────────────────
SEED = 42
random.seed(SEED)

# ── File Paths ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(PROJECT_ROOT, "datasets")
GRAPHS_DIR = os.path.join(PROJECT_ROOT, "graphs")
INPUT_FILE = os.path.join(DATASETS_DIR, "cleaned_passwords.csv")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "dictionary_attack_results.csv")
GRAPH_FILE = os.path.join(GRAPHS_DIR, "dictionary_attack_results.png")

# ── Hash Rate Assumptions (hashes per second) ──────────────────────────────────
HASH_RATES = {
    'MD5':    10_000_000_000,   # 10 billion/sec
    'SHA1':    5_000_000_000,   # 5 billion/sec
    'SHA256':  2_000_000_000,   # 2 billion/sec
}

# ── Dark Theme Colors (matching project aesthetic) ──────────────────────────────
COLORS = {
    'bg': '#0d1117',
    'card_bg': '#161b22',
    'text': '#c9d1d9',
    'text_secondary': '#8b949e',
    'accent': '#58a6ff',
    'green': '#3fb950',
    'red': '#f85149',
    'orange': '#d29922',
    'purple': '#bc8cff',
    'border': '#30363d',
}


# =============================================================================
# Wordlist Builder
# =============================================================================

# Common passwords known from major data breaches
_COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "admin",
    "welcome", "hello", "charlie", "donald", "login", "princess", "starwars",
    "solo", "qwerty123", "admin123", "welcome1", "666666", "abc1234",
    "trustme", "iloveu", "batman", "access", "hello123", "god",
    "love", "test", "pass", "pass123", "summer", "winter", "spring",
    "autumn", "computer", "internet", "soccer", "hockey", "ranger", "buster",
    "jordan", "hunter", "amanda", "jennifer", "jessica", "joshua", "pepper",
    "andrew", "matthew", "daniel", "david", "robert", "thomas", "william",
    "richard", "joseph", "charles", "george", "flower", "cheese",
    "butter", "cookie", "orange", "banana", "apple", "cherry",
    "chocolate", "coffee", "pizza", "taco", "ninja", "pirate",
    "wizard", "magic", "secret", "diamond", "silver", "golden",
    "purple", "yellow", "music", "gamer", "player", "winner",
    "killer", "sniper", "matrix", "avatar", "legend", "phoenix",
    "falcon", "eagle", "tiger", "lion", "panther", "wolf", "bear",
    "shark", "dolphin", "horse", "kitten", "puppy", "angel", "devil",
    "king", "queen", "prince", "knight", "castle",
]

# Dictionary words commonly used in passwords
_DICTIONARY_WORDS = [
    "security", "computer", "internet", "database", "network", "software",
    "hardware", "keyboard", "monitor", "program", "algorithm", "function",
    "football", "baseball", "basketball", "cricket", "tennis", "swimming",
    "mountain", "ocean", "river", "forest", "desert", "island",
    "diamond", "crystal", "emerald", "sapphire", "ruby", "platinum",
    "elephant", "giraffe", "penguin", "dolphin", "cheetah", "leopard",
    "butterfly", "dragonfly", "scorpion", "midnight", "twilight", "sunshine",
    "rainbow", "thunder", "lightning", "champion", "warrior", "guardian",
    "defender", "explorer", "pioneer", "harmony", "melody", "rhythm",
    "electric", "magnetic", "acoustic", "nuclear", "quantum", "digital",
    "abstract", "creative", "fantastic", "beautiful", "wonderful", "adventure",
]

# Keyboard patterns
_KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "654321", "0987654321", "1qaz2wsx", "qazwsx", "qwerty123",
    "1q2w3e4r", "1q2w3e", "asd123", "qwe123", "111111", "000000",
    "abcdef", "abcdefgh",
]

# Leetspeak substitution map
_LEET_MAP = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['7'],
    'l': ['1'],
}


def build_wordlist():
    """
    Build a comprehensive wordlist for the dictionary attack.

    The wordlist includes:
        - Base common passwords
        - Case variations (lowercase, uppercase, capitalized)
        - Suffix variations (numbers, special characters, years)
        - Leetspeak substitutions
        - Keyboard patterns

    Returns:
        set: A set of all wordlist entries (for O(1) lookup).
    """
    wordlist = set()

    all_bases = list(set(_COMMON_PASSWORDS + _DICTIONARY_WORDS + _KEYBOARD_PATTERNS))

    for word in all_bases:
        # Original forms
        wordlist.add(word)
        wordlist.add(word.lower())
        wordlist.add(word.upper())
        wordlist.add(word.capitalize())

        # Common suffixes
        for suffix in ['1', '12', '123', '!', '!!', '@', '#', '$',
                        '2020', '2021', '2022', '2023', '2024', '2025',
                        '01', '99', '007', '69', '420', '!@#', '!1']:
            wordlist.add(word + suffix)
            wordlist.add(word.capitalize() + suffix)
            wordlist.add(word.lower() + suffix)

        # Leetspeak (single substitution)
        for i, ch in enumerate(word.lower()):
            if ch in _LEET_MAP:
                for repl in _LEET_MAP[ch]:
                    leet = word.lower()[:i] + repl + word.lower()[i+1:]
                    wordlist.add(leet)

    # Add pure numeric patterns
    for length in range(1, 11):
        # Sequential numbers
        for start in range(10):
            seq = ''.join(str((start + i) % 10) for i in range(length))
            wordlist.add(seq)
        # Repeated digits
        for digit in '0123456789':
            wordlist.add(digit * length)

    # Common names with numbers
    names = [
        "john", "jane", "mike", "sara", "alex", "emma", "ryan", "lisa",
        "mark", "anna", "paul", "kate", "james", "sarah", "david", "emily",
        "chris", "laura", "kevin", "maria", "brian", "diana", "steve",
    ]
    for name in names:
        for suffix in ['1', '12', '123', '!', '@', '2024', '1990', '2000', '99']:
            wordlist.add(name + suffix)
            wordlist.add(name.capitalize() + suffix)

    return wordlist


def check_variation_match(password, wordlist):
    """
    Check if a password matches any entry in the wordlist via common
    transformations (not just exact match).

    Transformations checked:
        1. Exact match (case-insensitive)
        2. Stripped of trailing digits/specials → match base word
        3. Common prefix/suffix removal

    Args:
        password (str): The password to check.
        wordlist (set): The wordlist set.

    Returns:
        tuple: (matched: bool, method: str)
    """
    # 1. Exact match (case-sensitive)
    if password in wordlist:
        return True, "exact_match"

    # 2. Case-insensitive match
    if password.lower() in wordlist:
        return True, "case_insensitive"

    # 3. Strip trailing digits and check
    stripped = password.rstrip('0123456789')
    if stripped and stripped.lower() in wordlist:
        return True, "stripped_digits"

    # 4. Strip trailing special characters and check
    stripped_special = password.rstrip('!@#$%^&*()-_=+[]{}|;:,.<>?/~`')
    if stripped_special and stripped_special.lower() in wordlist:
        return True, "stripped_specials"

    # 5. Strip both trailing digits and specials
    stripped_both = stripped.rstrip('!@#$%^&*()-_=+[]{}|;:,.<>?/~`')
    if stripped_both and stripped_both.lower() in wordlist:
        return True, "stripped_both"

    # 6. Check if password is a reversal of a wordlist entry
    if password[::-1].lower() in wordlist:
        return True, "reversed"

    return False, "not_cracked"


# =============================================================================
# Crack Time Estimation
# =============================================================================

def estimate_crack_time(password, hash_algorithm='SHA256'):
    """
    Estimate the time to brute-force a password given a hash algorithm.

    The search space is calculated as: charset_size ^ password_length
    Time = search_space / hash_rate

    Args:
        password (str): The password.
        hash_algorithm (str): Hash algorithm ('MD5', 'SHA1', or 'SHA256').

    Returns:
        float: Estimated time in seconds.
    """
    length = len(password)
    if length == 0:
        return 0.0

    # Determine charset size
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 32
    if charset == 0:
        charset = 26  # fallback

    search_space = charset ** length
    hash_rate = HASH_RATES.get(hash_algorithm, HASH_RATES['SHA256'])

    # Time in seconds (capped to avoid overflow in display)
    time_seconds = search_space / hash_rate
    return min(time_seconds, 1e30)  # Cap at ~3.17e22 years


def format_time(seconds):
    """
    Format seconds into a human-readable time string.

    Args:
        seconds (float): Time in seconds.

    Returns:
        str: Formatted time string.
    """
    if seconds < 0.001:
        return "instant"
    elif seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    elif seconds < 60:
        return f"{seconds:.1f} sec"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} min"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} days"
    elif seconds < 86400 * 365 * 1000:
        return f"{seconds / (86400 * 365):.1f} years"
    elif seconds < 86400 * 365 * 1e6:
        return f"{seconds / (86400 * 365 * 1000):.1f}K years"
    elif seconds < 86400 * 365 * 1e9:
        return f"{seconds / (86400 * 365 * 1e6):.1f}M years"
    else:
        return f"{seconds / (86400 * 365 * 1e9):.1f}B years"


# =============================================================================
# Data Loading
# =============================================================================

def load_cleaned_passwords(filepath):
    """
    Load the cleaned password dataset with all features.

    Args:
        filepath (str): Path to cleaned_passwords.csv.

    Returns:
        list[dict]: List of password records.
    """
    records = []
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)
    return records


# =============================================================================
# Graph Generation
# =============================================================================

def generate_graph(results, output_path):
    """
    Generate a publication-quality bar chart showing dictionary attack
    success rates grouped by password strength classification.

    Args:
        results (list[dict]): Attack results.
        output_path (str): Path to save the graph.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # ── Compute statistics by classification ──────────────────────────────────
    # Group by rules_classification
    rules_groups = defaultdict(lambda: {'total': 0, 'cracked': 0})
    for r in results:
        cls = r['rules_classification']
        rules_groups[cls]['total'] += 1
        if r['cracked'] == 'True' or r['cracked'] is True:
            rules_groups[cls]['cracked'] += 1

    # Group by entropy_classification
    entropy_groups = defaultdict(lambda: {'total': 0, 'cracked': 0})
    for r in results:
        cls = r['entropy_classification']
        entropy_groups[cls]['total'] += 1
        if r['cracked'] == 'True' or r['cracked'] is True:
            entropy_groups[cls]['cracked'] += 1

    # ── Create figure with 2 subplots ─────────────────────────────────────────
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7))
    fig.patch.set_facecolor(COLORS['bg'])

    for ax in [ax1, ax2]:
        ax.set_facecolor(COLORS['card_bg'])
        ax.tick_params(colors=COLORS['text'], labelsize=10)
        ax.spines['bottom'].set_color(COLORS['border'])
        ax.spines['left'].set_color(COLORS['border'])
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

    # ── Subplot 1: Rules-Based Classification ─────────────────────────────────
    rules_order = ['Weak', 'Medium', 'Strong']
    rules_labels = [c for c in rules_order if c in rules_groups]
    rules_rates = []
    rules_totals = []
    for cls in rules_labels:
        total = rules_groups[cls]['total']
        cracked = rules_groups[cls]['cracked']
        rate = (cracked / total * 100) if total > 0 else 0
        rules_rates.append(rate)
        rules_totals.append(total)

    bar_colors_rules = [COLORS['red'] if r > 60 else COLORS['orange'] if r > 30
                        else COLORS['green'] for r in rules_rates]

    bars1 = ax1.bar(rules_labels, rules_rates, color=bar_colors_rules,
                    edgecolor=COLORS['border'], linewidth=0.8, width=0.6, alpha=0.9)

    # Add value labels on bars
    for bar, rate, total in zip(bars1, rules_rates, rules_totals):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                 f'{rate:.1f}%', ha='center', va='bottom',
                 color=COLORS['text'], fontsize=11, fontweight='bold')
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() / 2,
                 f'n={total:,}', ha='center', va='center',
                 color=COLORS['bg'], fontsize=9, fontweight='bold')

    ax1.set_xlabel('Rules Classification', color=COLORS['text'], fontsize=12, fontweight='bold')
    ax1.set_ylabel('Crack Success Rate (%)', color=COLORS['text'], fontsize=12, fontweight='bold')
    ax1.set_title('Dictionary Attack Success by Rules Classification',
                  color=COLORS['accent'], fontsize=13, fontweight='bold', pad=15)
    ax1.set_ylim(0, max(rules_rates + [10]) * 1.2)

    # ── Subplot 2: Entropy-Based Classification ───────────────────────────────
    entropy_order = ['Weak', 'Medium', 'Strong', 'Very Strong']
    entropy_labels = [c for c in entropy_order if c in entropy_groups]
    entropy_rates = []
    entropy_totals = []
    for cls in entropy_labels:
        total = entropy_groups[cls]['total']
        cracked = entropy_groups[cls]['cracked']
        rate = (cracked / total * 100) if total > 0 else 0
        entropy_rates.append(rate)
        entropy_totals.append(total)

    bar_colors_entropy = [COLORS['red'] if r > 60 else COLORS['orange'] if r > 30
                          else COLORS['green'] for r in entropy_rates]

    bars2 = ax2.bar(entropy_labels, entropy_rates, color=bar_colors_entropy,
                    edgecolor=COLORS['border'], linewidth=0.8, width=0.6, alpha=0.9)

    for bar, rate, total in zip(bars2, entropy_rates, entropy_totals):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                 f'{rate:.1f}%', ha='center', va='bottom',
                 color=COLORS['text'], fontsize=11, fontweight='bold')
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() / 2,
                 f'n={total:,}', ha='center', va='center',
                 color=COLORS['bg'], fontsize=9, fontweight='bold')

    ax2.set_xlabel('Entropy Classification', color=COLORS['text'], fontsize=12, fontweight='bold')
    ax2.set_ylabel('Crack Success Rate (%)', color=COLORS['text'], fontsize=12, fontweight='bold')
    ax2.set_title('Dictionary Attack Success by Entropy Classification',
                  color=COLORS['accent'], fontsize=13, fontweight='bold', pad=15)
    ax2.set_ylim(0, max(entropy_rates + [10]) * 1.2)

    # ── Overall title and layout ──────────────────────────────────────────────
    fig.suptitle('Dictionary Attack Simulation Results',
                 color=COLORS['text'], fontsize=16, fontweight='bold', y=0.98)

    # Add summary text at the bottom
    total_passwords = len(results)
    total_cracked = sum(1 for r in results if r['cracked'] == 'True' or r['cracked'] is True)
    overall_rate = (total_cracked / total_passwords * 100) if total_passwords > 0 else 0

    fig.text(0.5, 0.02,
             f'Total Passwords: {total_passwords:,}  |  Cracked: {total_cracked:,}  |  '
             f'Overall Success Rate: {overall_rate:.1f}%',
             ha='center', va='center', color=COLORS['text_secondary'],
             fontsize=11, fontstyle='italic')

    plt.tight_layout(rect=[0, 0.05, 1, 0.93])
    plt.savefig(output_path, dpi=200, facecolor=COLORS['bg'],
                edgecolor='none', bbox_inches='tight')
    plt.close()


# =============================================================================
# Main Attack Simulation
# =============================================================================

def run_dictionary_attack():
    """
    Execute the dictionary attack simulation.
    """
    print("=" * 70)
    print("  DICTIONARY ATTACK SIMULATION")
    print("  Testing passwords against a comprehensive wordlist")
    print("=" * 70)
    print()

    # ── Step 1: Load data ─────────────────────────────────────────────────────
    print("[1/5] Loading cleaned password dataset...")
    if not os.path.exists(INPUT_FILE):
        print(f"  ❌ Error: {INPUT_FILE} not found.")
        print(f"     Please run datasets/clean_datasets.py first.")
        sys.exit(1)

    records = load_cleaned_passwords(INPUT_FILE)
    print(f"  → Loaded {len(records):,} passwords")
    print()

    # ── Step 2: Build wordlist ────────────────────────────────────────────────
    print("[2/5] Building attack wordlist...")
    wordlist = build_wordlist()
    print(f"  → Wordlist contains {len(wordlist):,} entries")
    print()

    # ── Step 3: Run attack ────────────────────────────────────────────────────
    print("[3/5] Running dictionary attack simulation...")
    results = []
    cracked_count = 0
    total = len(records)

    for idx, rec in enumerate(records):
        if (idx + 1) % 2000 == 0 or idx == 0 or (idx + 1) == total:
            progress = ((idx + 1) / total) * 100
            print(f"    [{idx + 1:>6,} / {total:,}]  {progress:5.1f}%  "
                  f"Cracked so far: {cracked_count:,}")

        password = rec['password']
        matched, method = check_variation_match(password, wordlist)
        est_time = estimate_crack_time(password) if not matched else 0.0

        result = {
            'password': password,
            'cracked': matched,
            'method': method,
            'estimated_time_seconds': est_time,
            'rules_score': rec.get('rules_score', '0'),
            'entropy_score': rec.get('entropy_score', '0'),
            'rules_classification': rec.get('rules_classification', 'Unknown'),
            'entropy_classification': rec.get('entropy_classification', 'Unknown'),
        }
        results.append(result)

        if matched:
            cracked_count += 1

    print(f"  → Attack complete: {cracked_count:,} / {total:,} cracked")
    print()

    # ── Step 4: Save results ──────────────────────────────────────────────────
    print("[4/5] Saving results...")
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    fieldnames = ['password', 'cracked', 'method', 'estimated_time_seconds',
                  'rules_score', 'entropy_score', 'rules_classification',
                  'entropy_classification']

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    print(f"  → Saved results to {OUTPUT_FILE}")
    print()

    # ── Step 5: Generate graph ────────────────────────────────────────────────
    print("[5/5] Generating graphs...")
    generate_graph(results, GRAPH_FILE)
    print(f"  → Saved graph to {GRAPH_FILE}")
    print()

    # ── Summary Statistics ────────────────────────────────────────────────────
    print("=" * 70)
    print("  ATTACK SUMMARY")
    print("=" * 70)

    overall_rate = (cracked_count / total * 100) if total > 0 else 0
    print(f"  Total passwords tested:  {total:,}")
    print(f"  Passwords cracked:       {cracked_count:,}")
    print(f"  Overall success rate:    {overall_rate:.1f}%")
    print()

    # Method breakdown
    method_counts = Counter(r['method'] for r in results)
    print("  Crack Method Breakdown:")
    print("  " + "─" * 50)
    for method, count in method_counts.most_common():
        pct = (count / total) * 100
        print(f"    {method:<25} {count:>6,}  ({pct:5.1f}%)")
    print()

    # By rules classification
    print("  Results by Rules Classification:")
    print("  " + "─" * 50)
    rules_groups = defaultdict(lambda: {'total': 0, 'cracked': 0})
    for r in results:
        cls = r['rules_classification']
        rules_groups[cls]['total'] += 1
        if r['cracked'] is True or r['cracked'] == 'True':
            rules_groups[cls]['cracked'] += 1

    for cls in ['Weak', 'Medium', 'Strong']:
        if cls in rules_groups:
            g = rules_groups[cls]
            rate = (g['cracked'] / g['total'] * 100) if g['total'] > 0 else 0
            print(f"    {cls:<12} {g['cracked']:>5,} / {g['total']:>5,}  ({rate:5.1f}%)")

    print()

    # By entropy classification
    print("  Results by Entropy Classification:")
    print("  " + "─" * 50)
    entropy_groups = defaultdict(lambda: {'total': 0, 'cracked': 0})
    for r in results:
        cls = r['entropy_classification']
        entropy_groups[cls]['total'] += 1
        if r['cracked'] is True or r['cracked'] == 'True':
            entropy_groups[cls]['cracked'] += 1

    for cls in ['Weak', 'Medium', 'Strong', 'Very Strong']:
        if cls in entropy_groups:
            g = entropy_groups[cls]
            rate = (g['cracked'] / g['total'] * 100) if g['total'] > 0 else 0
            print(f"    {cls:<15} {g['cracked']:>5,} / {g['total']:>5,}  ({rate:5.1f}%)")

    print()
    print("=" * 70)
    print("  Dictionary attack simulation completed successfully!")
    print("=" * 70)


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    run_dictionary_attack()
