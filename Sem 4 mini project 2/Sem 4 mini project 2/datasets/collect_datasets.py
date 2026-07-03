"""
collect_datasets.py
-------------------
Synthetic Password Dataset Generator.

Generates approximately 10,000 passwords that mimic real-world password
distributions found in actual data breaches (e.g., RockYou). Since we
cannot redistribute actual leaked datasets, this script creates a
realistic synthetic dataset across six password categories.

Categories:
    1. Common Leaked Passwords (~2000)
    2. Dictionary Words with Substitutions (~2000)
    3. Keyboard Pattern Passwords (~1500)
    4. Short Weak Passwords (~1000)
    5. Medium Complexity Passwords (~2000)
    6. Strong Random Passwords (~1500)

Output:
    datasets/raw_passwords.csv  — columns: password, source_category


"""

import csv
import os
import random
import string
import itertools

# ── Reproducibility ─────────────────────────────────────────────────────────────
SEED = 42
random.seed(SEED)

# ── Output Configuration ────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "raw_passwords.csv")


# =============================================================================
# Category 1: Common Leaked Passwords (~2000)
# =============================================================================

# Base list of the most commonly leaked passwords (from well-known breach lists)
_COMMON_BASE = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "admin",
    "welcome", "hello", "charlie", "donald", "login", "princess", "starwars",
    "solo", "qwerty123", "admin123", "welcome1", "666666", "abc1234",
    "trustme", "iloveu", "batman", "access", "hello123", "god",
    "love", "test", "pass", "pass123", "summer", "winter", "spring",
    "autumn", "january", "february", "march", "april", "may2024",
    "june2024", "july2024", "august", "september", "october", "november",
    "december", "monday", "tuesday", "friday", "sunday", "computer",
    "internet", "soccer", "hockey", "ranger", "buster", "jordan",
    "hunter", "amanda", "jennifer", "jessica", "joshua", "pepper",
    "andrew", "matthew", "daniel", "david", "robert", "thomas", "william",
    "richard", "joseph", "charles", "george", "flower", "cheese",
    "butter", "cookie", "orange", "banana", "apple", "cherry",
    "chocolate", "coffee", "pizza", "taco", "ninja", "pirate",
    "wizard", "magic", "secret", "diamond", "silver", "golden",
    "purple", "yellow", "indigo", "violet", "india", "america",
    "london", "paris", "tokyo", "berlin", "moscow", "sydney",
    "canada", "brazil", "mexico", "guitar", "piano", "music",
    "gamer", "player", "winner", "loser", "killer", "sniper",
    "matrix", "avatar", "legend", "phoenix", "falcon", "eagle",
    "tiger", "lion", "panther", "wolf", "bear", "shark",
    "dolphin", "whale", "horse", "pony", "kitten", "puppy",
    "baby", "angel", "devil", "king", "queen", "prince",
    "knight", "castle", "palace", "temple", "church", "school",
    "college", "university", "student", "teacher", "doctor", "nurse",
    "lawyer", "police", "marine", "soldier", "captain", "general",
]

# Leetspeak substitution maps for generating variations
_LEET_MAP = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['7'],
    'l': ['1'],
    'g': ['9'],
}


def _generate_variations(base_password):
    """Generate common variations of a base password."""
    variations = [base_password]

    # Capitalize first letter
    variations.append(base_password.capitalize())

    # ALL CAPS
    variations.append(base_password.upper())

    # Append common suffixes
    for suffix in ['1', '12', '123', '!', '!!', '@', '#', '2024', '2025', '01', '99']:
        variations.append(base_password + suffix)
        variations.append(base_password.capitalize() + suffix)

    # Leetspeak: replace one or two chars
    pw_lower = base_password.lower()
    for i, ch in enumerate(pw_lower):
        if ch in _LEET_MAP:
            for replacement in _LEET_MAP[ch]:
                leet_pw = pw_lower[:i] + replacement + pw_lower[i+1:]
                variations.append(leet_pw)
                variations.append(leet_pw.capitalize() if leet_pw[0].isalpha() else leet_pw)
            break  # Only replace the first substitutable char for controlled output

    return variations


def generate_common_leaked(target_count=2000):
    """Generate ~2000 common leaked passwords with variations."""
    passwords = []

    for base in _COMMON_BASE:
        passwords.extend(_generate_variations(base))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for pw in passwords:
        if pw not in seen:
            seen.add(pw)
            unique.append(pw)

    # If we have more than target, sample; if fewer, cycle with modifications
    if len(unique) >= target_count:
        random.shuffle(unique)
        return unique[:target_count]
    else:
        # Add more variations to reach target
        extra_needed = target_count - len(unique)
        extras = []
        for base in random.choices(_COMMON_BASE, k=extra_needed):
            suffix = random.choice(['!', '@', '#', '$', '1', '12', '123', '2024', '!!', '##'])
            pw = base + suffix
            if pw not in seen:
                extras.append(pw)
                seen.add(pw)
        unique.extend(extras)
        return unique[:target_count]


# =============================================================================
# Category 2: Dictionary Words with Substitutions (~2000)
# =============================================================================

_DICTIONARY_WORDS = [
    "security", "password", "computer", "internet", "database", "network",
    "software", "hardware", "keyboard", "monitor", "program", "algorithm",
    "function", "variable", "constant", "library", "framework", "platform",
    "server", "client", "browser", "website", "domain", "hosting",
    "backup", "firewall", "antivirus", "malware", "ransomware", "phishing",
    "encryption", "decryption", "certificate", "protocol", "gateway",
    "router", "switch", "modem", "ethernet", "wireless", "bluetooth",
    "football", "baseball", "basketball", "cricket", "tennis", "swimming",
    "running", "cycling", "boxing", "wrestling", "archery", "skating",
    "mountain", "ocean", "river", "forest", "desert", "island",
    "country", "village", "garden", "kitchen", "bedroom", "bathroom",
    "diamond", "crystal", "emerald", "sapphire", "ruby", "platinum",
    "titanium", "mercury", "jupiter", "neptune", "saturn", "uranus",
    "elephant", "giraffe", "penguin", "dolphin", "cheetah", "leopard",
    "butterfly", "dragonfly", "scorpion", "tarantula", "chameleon",
    "broccoli", "avocado", "mushroom", "pineapple", "strawberry",
    "blueberry", "raspberry", "watermelon", "coconut", "mango",
    "electric", "magnetic", "acoustic", "nuclear", "quantum", "digital",
    "abstract", "creative", "fantastic", "beautiful", "wonderful", "adventure",
    "midnight", "twilight", "sunshine", "rainbow", "thunder", "lightning",
    "champion", "warrior", "guardian", "defender", "explorer", "pioneer",
    "harmony", "melody", "rhythm", "symphony", "orchestra", "concert",
]


def _apply_leet(word):
    """Apply leetspeak substitutions to a word."""
    result = list(word.lower())
    for i, ch in enumerate(result):
        if ch in _LEET_MAP and random.random() < 0.5:
            result[i] = random.choice(_LEET_MAP[ch])
    return ''.join(result)


def generate_dictionary_substitutions(target_count=2000):
    """Generate ~2000 dictionary-based passwords with leetspeak substitutions."""
    passwords = []

    for word in _DICTIONARY_WORDS:
        # Plain word
        passwords.append(word)
        passwords.append(word.capitalize())

        # Word + year
        for year in ['2023', '2024', '2025', '2020']:
            passwords.append(word + year)
            passwords.append(word.capitalize() + year)

        # Word + special char
        for suffix in ['!', '@', '#', '$', '!!', '123']:
            passwords.append(word + suffix)
            passwords.append(word.capitalize() + suffix)

        # Leetspeak version
        passwords.append(_apply_leet(word))
        passwords.append(_apply_leet(word).capitalize() if _apply_leet(word)[0].isalpha() else _apply_leet(word))

        # Combined patterns: Word + digit + special
        passwords.append(f"{word.capitalize()}@{random.randint(1, 99)}")
        passwords.append(f"{word.capitalize()}#{random.randint(100, 999)}")

    # Compound words (two words joined)
    for _ in range(200):
        w1 = random.choice(_DICTIONARY_WORDS)
        w2 = random.choice(_DICTIONARY_WORDS)
        passwords.append(w1.capitalize() + w2.capitalize())
        passwords.append(w1 + str(random.randint(1, 99)) + w2)

    # Deduplicate
    seen = set()
    unique = []
    for pw in passwords:
        if pw not in seen:
            seen.add(pw)
            unique.append(pw)

    random.shuffle(unique)
    return unique[:target_count]


# =============================================================================
# Category 3: Keyboard Pattern Passwords (~1500)
# =============================================================================

_KEYBOARD_PATTERNS_BASE = [
    # Horizontal rows
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "qwert", "asdfg", "zxcvb",
    # Number sequences
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "654321", "0987654321", "111111", "222222", "333333",
    "444444", "555555", "666666", "777777", "888888", "999999", "000000",
    # Diagonal keyboard walks
    "1qaz2wsx", "2wsx3edc", "3edc4rfv", "4rfv5tgb", "5tgb6yhn",
    "qazwsx", "qazwsxedc", "wsxedc", "edcrfv",
    "1qaz", "2wsx", "3edc", "4rfv",
    # Repeated/alternating patterns
    "abcabc", "xyzxyz", "aabbcc", "abcdef", "abcdefgh",
    "ababab", "cdcdcd", "efefef",
    # Common keyboard combos
    "qwerty123", "asdf1234", "zxcv1234", "1q2w3e4r",
    "1q2w3e", "q1w2e3r4", "asd123", "qwe123",
    "1234qwer", "qwer1234", "asdf5678",
]


def generate_keyboard_patterns(target_count=1500):
    """Generate ~1500 keyboard-pattern-based passwords."""
    passwords = []

    for pattern in _KEYBOARD_PATTERNS_BASE:
        passwords.append(pattern)
        passwords.append(pattern.upper())
        passwords.append(pattern.capitalize())

        # Pattern + common suffixes
        for suffix in ['!', '!!', '@', '#', '123', '1', '2024', '!@#']:
            passwords.append(pattern + suffix)

        # Double the pattern
        passwords.append(pattern + pattern[:4])

        # Reversed pattern
        passwords.append(pattern[::-1])

    # Generate more sequential patterns programmatically
    for start in range(0, 7):
        seq = ''.join(str(d % 10) for d in range(start, start + 6))
        passwords.append(seq)
        passwords.append(seq + seq[:3])

    # Alpha sequences
    for start_char in 'abcdefghijklmnopqrstu':
        idx = ord(start_char) - ord('a')
        seq = ''.join(chr(ord('a') + (idx + i) % 26) for i in range(6))
        passwords.append(seq)
        passwords.append(seq + str(random.randint(1, 99)))

    # Deduplicate
    seen = set()
    unique = []
    for pw in passwords:
        if pw not in seen:
            seen.add(pw)
            unique.append(pw)

    # Fill remaining with variations if needed
    max_attempts = 20000
    attempts = 0
    while len(unique) < target_count and attempts < max_attempts:
        attempts += 1
        base = random.choice(_KEYBOARD_PATTERNS_BASE)
        suffix = random.choice(['!', '@', '#', '1', '12', '123', '!!', '##',
                                '2024', '2025', '$', '%', '01', '99', 'abc',
                                '!@', '#$', '!!!' , '@@@', '###'])
        # Also add a random digit to create more unique combos
        extra = str(random.randint(0, 999))
        for pw in [base + suffix, base + suffix + extra,
                   base[::-1] + suffix, base.upper() + suffix,
                   base.capitalize() + extra, base + extra]:
            if pw not in seen:
                unique.append(pw)
                seen.add(pw)
            if len(unique) >= target_count:
                break

    random.shuffle(unique)
    return unique[:target_count]


# =============================================================================
# Category 4: Short Weak Passwords (~1000)
# =============================================================================

_SHORT_BASES = [
    "hi", "me", "no", "go", "ok", "up", "yes", "dog", "cat", "sun",
    "moon", "star", "red", "blue", "hot", "ice", "run", "fly", "top",
    "win", "fun", "joy", "sky", "sea", "day", "age", "ace", "aim",
    "air", "art", "bee", "boy", "cup", "dew", "ear", "eye", "fan",
    "gap", "hat", "ink", "jam", "key", "lap", "map", "nap", "oak",
    "pen", "ram", "saw", "tea", "van", "wax", "yam", "zen", "gym",
    "pet", "nut", "fog", "gem", "ivy", "jaw", "keg", "lid", "mug",
    "ash", "bat", "cod", "dip", "elm", "fig", "gut", "hem", "ice",
    "jab", "kit", "log", "mix", "nib", "oat", "peg", "rib", "sip",
    "tin", "urn", "vim", "web", "yew", "zip", "axe", "bow", "cab",
]

_SHORT_NAMES = [
    "amy", "ben", "cam", "dan", "eva", "fin", "gus", "hal", "ivy",
    "jan", "ken", "lee", "max", "ned", "oli", "pat", "ray", "sam",
    "ted", "val", "zoe", "ali", "bob", "cal", "dot", "eli", "fay",
    "gil", "ida", "jay", "kai", "lou", "mel", "noa", "pam", "rex",
    "sue", "tom", "ulf", "vic", "wes", "xia", "yan", "zak",
]


def generate_short_weak(target_count=1000):
    """Generate ~1000 short weak passwords (under 8 characters)."""
    passwords = []

    # Single words and names
    for word in _SHORT_BASES + _SHORT_NAMES:
        passwords.append(word)
        passwords.append(word.upper())
        passwords.append(word + "1")
        passwords.append(word + "12")
        passwords.append(word + "!")

    # Pure numeric (1-7 digits)
    for length in range(1, 8):
        for _ in range(15):
            num = ''.join(random.choices(string.digits, k=length))
            passwords.append(num)

    # 2-4 letter combos
    for _ in range(100):
        length = random.randint(2, 7)
        pw = ''.join(random.choices(string.ascii_lowercase, k=length))
        passwords.append(pw)

    # Common short passwords
    short_common = [
        "a", "1", "12", "abc", "aaa", "111", "000", "xyz", "qwe",
        "asd", "zxc", "test", "pass", "root", "user", "temp",
        "love", "hate", "cool", "lol", "omg", "wtf", "god", "sex",
    ]
    passwords.extend(short_common)

    # Deduplicate and filter to < 8 chars
    seen = set()
    unique = []
    for pw in passwords:
        if pw not in seen and len(pw) < 8:
            seen.add(pw)
            unique.append(pw)

    random.shuffle(unique)
    return unique[:target_count]


# =============================================================================
# Category 5: Medium Complexity Passwords (~2000)
# =============================================================================

_NAMES = [
    "John", "Jane", "Mike", "Sara", "Alex", "Emma", "Ryan", "Lisa",
    "Mark", "Anna", "Paul", "Kate", "James", "Sarah", "David", "Emily",
    "Chris", "Laura", "Kevin", "Maria", "Brian", "Diana", "Steve",
    "Helen", "Peter", "Nicole", "Jason", "Karen", "Tyler", "Megan",
    "Oscar", "Wendy", "Frank", "Grace", "Henry", "Irene", "Larry",
    "Nancy", "Ralph", "Tanya", "Derek", "Bella", "Craig", "Flora",
    "Grant", "Heidi", "Ingrid", "Julia", "Kumar", "Linda",
]

_MEDIUM_WORDS = [
    "Summer", "Winter", "Spring", "Autumn", "Monday", "Friday",
    "Sunday", "Lucky", "Happy", "Crazy", "Super", "Power",
    "Magic", "Royal", "Night", "Dream", "Cloud", "Storm",
    "Flame", "Ocean", "Earth", "World", "Peace", "Light",
    "Dark", "Swift", "Brave", "Noble", "Steel", "Stone",
    "Frost", "Blaze", "Flash", "Ghost", "Spark", "Pulse",
    "Radar", "Orbit", "Nexus", "Prism", "Alpha", "Omega",
]


def generate_medium_complexity(target_count=2000):
    """Generate ~2000 medium-complexity passwords (8-12 chars, some variety)."""
    passwords = []

    # Name + year combinations
    for name in _NAMES:
        for year in ['1990', '1995', '2000', '2005', '2010', '2024']:
            passwords.append(f"{name}{year}")
            passwords.append(f"{name}@{year}")
            passwords.append(f"{name}#{year[-2:]}")

    # Name + special + digits
    for name in _NAMES:
        passwords.append(f"{name}!123")
        passwords.append(f"{name}@2024")
        passwords.append(f"{name}#99")
        passwords.append(f"{name}_01")

    # Word + digit + special combos
    for word in _MEDIUM_WORDS:
        passwords.append(f"{word}2024!")
        passwords.append(f"{word}@123")
        passwords.append(f"{word}#2025")
        passwords.append(f"{word}!!")
        passwords.append(f"My{word}1")
        passwords.append(f"The{word}!")

    # Date-based passwords
    for month in ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']:
        for year in ['2020', '2024', '2025']:
            passwords.append(f"{month}{year}!")
            passwords.append(f"{month}@{year}")

    # Pattern: Word + number + special
    for _ in range(300):
        word = random.choice(_MEDIUM_WORDS)
        num = random.randint(1, 999)
        special = random.choice(['!', '@', '#', '$', '%', '&', '*'])
        passwords.append(f"{word}{num}{special}")

    # Pattern: initial caps + digits
    for _ in range(200):
        name = random.choice(_NAMES)
        digits = ''.join(random.choices(string.digits, k=random.randint(2, 4)))
        passwords.append(f"{name}{digits}")

    # Deduplicate and filter to 8-12 chars
    seen = set()
    unique = []
    for pw in passwords:
        if pw not in seen and 8 <= len(pw) <= 12:
            seen.add(pw)
            unique.append(pw)

    # If not enough, pad with relaxed length (up to 14)
    if len(unique) < target_count:
        for pw in passwords:
            if pw not in seen and 6 <= len(pw) <= 14:
                seen.add(pw)
                unique.append(pw)
                if len(unique) >= target_count:
                    break

    random.shuffle(unique)
    return unique[:target_count]


# =============================================================================
# Category 6: Strong Random Passwords (~1500)
# =============================================================================

_SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`"


def generate_strong_random(target_count=1500):
    """Generate ~1500 strong random passwords (12+ chars, all character types)."""
    passwords = []

    for _ in range(target_count + 200):
        length = random.randint(12, 24)

        # Ensure at least one of each character type
        pw_chars = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice(_SPECIAL_CHARS),
        ]

        # Fill the rest randomly from the full set
        all_chars = string.ascii_letters + string.digits + _SPECIAL_CHARS
        pw_chars.extend(random.choices(all_chars, k=length - 4))

        # Shuffle to avoid predictable first-four pattern
        random.shuffle(pw_chars)
        passwords.append(''.join(pw_chars))

    # Deduplicate
    seen = set()
    unique = []
    for pw in passwords:
        if pw not in seen:
            seen.add(pw)
            unique.append(pw)

    return unique[:target_count]


# =============================================================================
# Main: Generate and Save Dataset
# =============================================================================

def generate_dataset():
    """
    Generate the full synthetic password dataset and save to CSV.

    Returns:
        dict: Statistics about the generated dataset.
    """
    print("=" * 70)
    print("  SYNTHETIC PASSWORD DATASET GENERATOR")
    print("  Generating ~10,000 passwords across 6 categories")
    print("=" * 70)
    print()

    # Generate each category
    print("[1/6] Generating common leaked passwords...")
    common = generate_common_leaked(2000)
    print(f"       -> Generated {len(common)} passwords")

    print("[2/6] Generating dictionary words with substitutions...")
    dictionary = generate_dictionary_substitutions(2000)
    print(f"       -> Generated {len(dictionary)} passwords")

    print("[3/6] Generating keyboard pattern passwords...")
    keyboard = generate_keyboard_patterns(1500)
    print(f"       -> Generated {len(keyboard)} passwords")

    print("[4/6] Generating short weak passwords...")
    short = generate_short_weak(1000)
    print(f"       -> Generated {len(short)} passwords")

    print("[5/6] Generating medium complexity passwords...")
    medium = generate_medium_complexity(2000)
    print(f"       -> Generated {len(medium)} passwords")

    print("[6/6] Generating strong random passwords...")
    strong = generate_strong_random(1500)
    print(f"       -> Generated {len(strong)} passwords")

    # Combine all categories with labels
    all_passwords = []
    categories = [
        (common, "common_leaked"),
        (dictionary, "dictionary_substitution"),
        (keyboard, "keyboard_pattern"),
        (short, "short_weak"),
        (medium, "medium_complexity"),
        (strong, "strong_random"),
    ]

    for passwords, category in categories:
        for pw in passwords:
            all_passwords.append((pw, category))

    # Shuffle the full dataset
    random.shuffle(all_passwords)

    # Write to CSV
    os.makedirs(SCRIPT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['password', 'source_category'])
        for pw, cat in all_passwords:
            writer.writerow([pw, cat])

    # Compute and print statistics
    total = len(all_passwords)
    category_counts = {}
    for _, cat in all_passwords:
        category_counts[cat] = category_counts.get(cat, 0) + 1

    print()
    print("=" * 70)
    print("  DATASET GENERATION COMPLETE")
    print("=" * 70)
    print(f"  Total passwords generated: {total:,}")
    print(f"  Output file: {OUTPUT_FILE}")
    print()
    print("  Category Breakdown:")
    print("  " + "-" * 50)
    for cat, count in sorted(category_counts.items()):
        pct = (count / total) * 100
        print(f"    {cat:<30} {count:>5}  ({pct:5.1f}%)")
    print("  " + "-" * 50)
    print()

    return {
        "total": total,
        "categories": category_counts,
        "output_file": OUTPUT_FILE,
    }


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    stats = generate_dataset()
    print("✅ Dataset generation finished successfully.")
