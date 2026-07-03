"""
generate_hashes.py
------------------
Hash Generation Script for Password Cracking Research.

Loads the cleaned password dataset and generates cryptographic hashes
using MD5, SHA-1, and SHA-256 algorithms. These hash files can be used
with tools like hashcat or John the Ripper for cracking analysis.

Output Files:
    cracking_environment/hashes_md5.txt     — MD5 hashes (hash:password)
    cracking_environment/hashes_sha1.txt    — SHA-1 hashes (hash:password)
    cracking_environment/hashes_sha256.txt  — SHA-256 hashes (hash:password)
    cracking_environment/passwords.txt      — Plain passwords (one per line)

⚠️  FOR ACADEMIC RESEARCH ONLY. Do not use on real user credentials.

Author: Password Strength Research Project (Person 2 – Analysis)
"""

import csv
import hashlib
import os
import sys

# ── Add project root to sys.path ────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# ── File Paths ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(PROJECT_ROOT, "datasets")
INPUT_FILE = os.path.join(DATASETS_DIR, "cleaned_passwords.csv")

OUTPUT_MD5 = os.path.join(SCRIPT_DIR, "hashes_md5.txt")
OUTPUT_SHA1 = os.path.join(SCRIPT_DIR, "hashes_sha1.txt")
OUTPUT_SHA256 = os.path.join(SCRIPT_DIR, "hashes_sha256.txt")
OUTPUT_WORDLIST = os.path.join(SCRIPT_DIR, "passwords.txt")


# =============================================================================
# Hash Generation Functions
# =============================================================================

def hash_md5(password):
    """
    Generate MD5 hash of a password.

    Args:
        password (str): The password to hash.

    Returns:
        str: Hexadecimal MD5 hash (32 characters).
    """
    return hashlib.md5(password.encode('utf-8')).hexdigest()


def hash_sha1(password):
    """
    Generate SHA-1 hash of a password.

    Args:
        password (str): The password to hash.

    Returns:
        str: Hexadecimal SHA-1 hash (40 characters).
    """
    return hashlib.sha1(password.encode('utf-8')).hexdigest()


def hash_sha256(password):
    """
    Generate SHA-256 hash of a password.

    Args:
        password (str): The password to hash.

    Returns:
        str: Hexadecimal SHA-256 hash (64 characters).
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# =============================================================================
# Data Loading
# =============================================================================

def load_passwords(filepath):
    """
    Load passwords from the cleaned dataset CSV.

    Args:
        filepath (str): Path to cleaned_passwords.csv.

    Returns:
        list[str]: List of password strings.
    """
    passwords = []
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            pw = row.get('password', '').strip()
            if pw:
                passwords.append(pw)
    return passwords


# =============================================================================
# Hash File Writers
# =============================================================================

def write_hash_file(passwords, hash_func, output_path, algo_name):
    """
    Generate hashes for all passwords and write to a file.

    Format: hash:password (one per line)

    Args:
        passwords (list[str]): List of passwords.
        hash_func (callable): Hash function to use.
        output_path (str): Output file path.
        algo_name (str): Algorithm name for logging.

    Returns:
        dict: Statistics about the generated hashes.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    hash_set = set()       # Track unique hashes
    collision_count = 0     # Count hash collisions (different passwords → same hash)
    hash_to_password = {}   # Map hashes to first password seen

    with open(output_path, 'w', encoding='utf-8') as f:
        for pw in passwords:
            h = hash_func(pw)

            # Check for collisions
            if h in hash_set and hash_to_password.get(h) != pw:
                collision_count += 1
            hash_set.add(h)
            if h not in hash_to_password:
                hash_to_password[h] = pw

            f.write(f"{h}:{pw}\n")

    return {
        'algorithm': algo_name,
        'total_hashes': len(passwords),
        'unique_hashes': len(hash_set),
        'collisions': collision_count,
        'output_file': output_path,
    }


def write_wordlist(passwords, output_path):
    """
    Write plain passwords to a wordlist file (one per line).

    Args:
        passwords (list[str]): List of passwords.
        output_path (str): Output file path.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for pw in passwords:
            f.write(pw + '\n')


# =============================================================================
# Statistics Display
# =============================================================================

def print_hash_stats(stats_list, total_passwords):
    """
    Print a formatted statistics table for all hash algorithms.

    Args:
        stats_list (list[dict]): List of statistics dictionaries.
        total_passwords (int): Total number of passwords processed.
    """
    print()
    print("  Hash Generation Statistics")
    print("  " + "─" * 60)
    print(f"  {'Algorithm':<12} {'Total':>8} {'Unique':>8} {'Collisions':>12} {'File Size':>12}")
    print("  " + "─" * 60)

    for stats in stats_list:
        # Get file size
        file_size = os.path.getsize(stats['output_file'])
        if file_size > 1024 * 1024:
            size_str = f"{file_size / (1024 * 1024):.1f} MB"
        elif file_size > 1024:
            size_str = f"{file_size / 1024:.1f} KB"
        else:
            size_str = f"{file_size} B"

        print(f"  {stats['algorithm']:<12} {stats['total_hashes']:>8,} "
              f"{stats['unique_hashes']:>8,} {stats['collisions']:>12,} "
              f"{size_str:>12}")

    print("  " + "─" * 60)
    print()

    # Hash length examples
    print("  Hash Length Examples (first password):")
    print("  " + "─" * 60)
    print(f"  {'Algorithm':<12} {'Hash Length':>12} {'Example (first 32 chars)'}")
    print("  " + "─" * 60)

    sample_pw = "example_password"
    for algo_name, hash_func in [('MD5', hash_md5), ('SHA-1', hash_sha1), ('SHA-256', hash_sha256)]:
        h = hash_func(sample_pw)
        print(f"  {algo_name:<12} {len(h):>12} chars  {h[:32]}...")
    print("  " + "─" * 60)


# =============================================================================
# Main
# =============================================================================

def main():
    """
    Main function: load passwords, generate hashes, write output files.
    """
    print("=" * 70)
    print("  HASH GENERATION SCRIPT")
    print("  Generating MD5, SHA-1, and SHA-256 hashes for password analysis")
    print("=" * 70)
    print()

    # ── Load passwords ────────────────────────────────────────────────────────
    print("[1/5] Loading cleaned password dataset...")
    if not os.path.exists(INPUT_FILE):
        print(f"  ❌ Error: {INPUT_FILE} not found.")
        print(f"     Please run datasets/clean_datasets.py first.")
        sys.exit(1)

    passwords = load_passwords(INPUT_FILE)
    print(f"  → Loaded {len(passwords):,} passwords")
    print()

    # ── Generate MD5 hashes ───────────────────────────────────────────────────
    print("[2/5] Generating MD5 hashes...")
    md5_stats = write_hash_file(passwords, hash_md5, OUTPUT_MD5, "MD5")
    print(f"  → Wrote {md5_stats['total_hashes']:,} hashes to {OUTPUT_MD5}")

    # ── Generate SHA-1 hashes ─────────────────────────────────────────────────
    print("[3/5] Generating SHA-1 hashes...")
    sha1_stats = write_hash_file(passwords, hash_sha1, OUTPUT_SHA1, "SHA-1")
    print(f"  → Wrote {sha1_stats['total_hashes']:,} hashes to {OUTPUT_SHA1}")

    # ── Generate SHA-256 hashes ───────────────────────────────────────────────
    print("[4/5] Generating SHA-256 hashes...")
    sha256_stats = write_hash_file(passwords, hash_sha256, OUTPUT_SHA256, "SHA-256")
    print(f"  → Wrote {sha256_stats['total_hashes']:,} hashes to {OUTPUT_SHA256}")

    # ── Write plain wordlist ──────────────────────────────────────────────────
    print("[5/5] Writing plain password wordlist...")
    write_wordlist(passwords, OUTPUT_WORDLIST)
    print(f"  → Wrote {len(passwords):,} passwords to {OUTPUT_WORDLIST}")
    print()

    # ── Print statistics ──────────────────────────────────────────────────────
    print_hash_stats([md5_stats, sha1_stats, sha256_stats], len(passwords))

    print("=" * 70)
    print("  Hash generation completed successfully!")
    print("=" * 70)
    print()
    print("  Next steps:")
    print("    1. Use hashes_*.txt with hashcat or John the Ripper")
    print("    2. Use passwords.txt as a wordlist for dictionary attacks")
    print("    3. Run dictionary_attack.py for simulated cracking analysis")
    print()


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    main()
