# Cracking Environment – Setup Guide

> **⚠️ LEGAL DISCLAIMER**: This guide and associated tools are provided strictly for
> **academic research and educational purposes**. Password cracking tools should only be
> used on passwords you own or have explicit authorization to test. Unauthorized access to
> computer systems is a criminal offence under the Computer Fraud and Abuse Act (US),
> Computer Misuse Act (UK), IT Act (India), and similar legislation worldwide.
> **Never use these tools to crack passwords belonging to others without written consent.**

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installing Hashcat](#installing-hashcat)
3. [Installing John the Ripper](#installing-john-the-ripper)
4. [Using generate_hashes.py](#using-generate_hashespy)
5. [Using dictionary_attack.py](#using-dictionary_attackpy)
6. [Using pattern_attack.py](#using-pattern_attackpy)
7. [Hash Algorithm Explanations](#hash-algorithm-explanations)
8. [Interpreting Results](#interpreting-results)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement       | Minimum Version | Notes                              |
|-------------------|-----------------|------------------------------------|
| Python            | 3.9+            | Required for all scripts           |
| pip               | 21.0+           | Python package manager             |
| matplotlib        | 3.5+            | `pip install matplotlib`           |
| zxcvbn            | 4.4+            | `pip install zxcvbn`               |
| hashcat           | 6.0+            | *Optional* – for real cracking     |
| John the Ripper   | 1.9+            | *Optional* – alternative to hashcat|

### Python Dependencies

```bash
# Install all required Python packages
pip install matplotlib zxcvbn
```

### Project Structure

Ensure your project directory looks like this:

```
project_root/
├── modules/                    # Person 1's analysis modules (DO NOT MODIFY)
│   ├── __init__.py
│   ├── rules_checker.py
│   ├── entropy_calculator.py
│   ├── pattern_detector.py
│   ├── zxcvbn_analyzer.py
│   └── hybrid_metric.py
├── datasets/                   # Person 2's dataset scripts
│   ├── collect_datasets.py
│   ├── clean_datasets.py
│   ├── raw_passwords.csv       # Generated output
│   └── cleaned_passwords.csv   # Generated output
├── cracking_environment/       # Person 2's cracking scripts
│   ├── setup_guide.md          # This file
│   ├── generate_hashes.py
│   ├── dictionary_attack.py
│   └── pattern_attack.py
└── graphs/                     # Generated graphs
```

---

## Installing Hashcat

### Windows

1. **Download** the latest release from [hashcat.net](https://hashcat.net/hashcat/):
   ```
   https://hashcat.net/files/hashcat-6.2.6.7z
   ```

2. **Extract** the archive to a location like `C:\Tools\hashcat\`.

3. **Add to PATH** (optional):
   - Open System Properties → Environment Variables
   - Add `C:\Tools\hashcat\` to your `Path` variable

4. **Verify installation**:
   ```powershell
   hashcat --version
   ```

5. **GPU Drivers**: Ensure you have the latest GPU drivers installed:
   - **NVIDIA**: Install [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads)
   - **AMD**: Install [ROCm](https://rocm.docs.amd.com/) or use OpenCL
   - **Intel**: Use OpenCL runtime

### Linux (Ubuntu/Debian)

```bash
# Install from package manager
sudo apt update
sudo apt install hashcat

# Or build from source
git clone https://github.com/hashcat/hashcat.git
cd hashcat
make
sudo make install

# Verify
hashcat --version
```

### Common Hashcat Commands

```bash
# MD5 dictionary attack (hash mode 0)
hashcat -m 0 -a 0 hashes_md5.txt passwords.txt

# SHA1 dictionary attack (hash mode 100)
hashcat -m 100 -a 0 hashes_sha1.txt passwords.txt

# SHA256 dictionary attack (hash mode 1400)
hashcat -m 1400 -a 0 hashes_sha256.txt passwords.txt

# Brute force attack on MD5
hashcat -m 0 -a 3 hashes_md5.txt ?a?a?a?a?a?a?a?a

# Show cracked passwords
hashcat -m 0 --show hashes_md5.txt
```

---

## Installing John the Ripper

### Windows

1. **Download** from the [official site](https://www.openwall.com/john/):
   ```
   https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip
   ```

2. **Extract** to `C:\Tools\john\`

3. **Run from the `run` directory**:
   ```powershell
   cd C:\Tools\john\run
   .\john.exe --test
   ```

### Linux (Ubuntu/Debian)

```bash
# Install from package manager
sudo apt update
sudo apt install john

# Or install jumbo version for more hash types
sudo apt install john-data

# Verify
john --test
```

### Common John the Ripper Commands

```bash
# Crack MD5 hashes with wordlist
john --format=raw-md5 --wordlist=passwords.txt hashes_md5.txt

# Crack SHA1 hashes
john --format=raw-sha1 --wordlist=passwords.txt hashes_sha1.txt

# Crack SHA256 hashes
john --format=raw-sha256 --wordlist=passwords.txt hashes_sha256.txt

# Show cracked passwords
john --show hashes_md5.txt

# Incremental (brute force) mode
john --format=raw-md5 --incremental hashes_md5.txt
```

---

## Using generate_hashes.py

This script reads `cleaned_passwords.csv` and generates hash files for MD5, SHA1, and SHA256.

### Usage

```bash
cd project_root
python cracking_environment/generate_hashes.py
```

### Output Files

| File                 | Format            | Description                      |
|----------------------|-------------------|----------------------------------|
| `hashes_md5.txt`     | `hash:password`   | MD5 hashes with plaintext        |
| `hashes_sha1.txt`    | `hash:password`   | SHA1 hashes with plaintext       |
| `hashes_sha256.txt`  | `hash:password`   | SHA256 hashes with plaintext     |
| `passwords.txt`      | One per line       | Plain passwords (wordlist)       |

### Notes

- Hash files use the `hash:password` format for verification purposes
- The `passwords.txt` wordlist can be used directly with hashcat or John the Ripper
- All output files are written to the `cracking_environment/` directory

---

## Using dictionary_attack.py

Simulates a dictionary attack by comparing passwords against a built-in wordlist of common passwords and their variations.

### Usage

```bash
cd project_root
python cracking_environment/dictionary_attack.py
```

### What It Does

1. Loads the cleaned password dataset
2. Builds a comprehensive wordlist from common passwords, dictionary words, and variations
3. Tests each password against the wordlist (exact match + common transformations)
4. Estimates crack time based on assumed hash rates:
   - **MD5**: 10 billion hashes/second
   - **SHA1**: 5 billion hashes/second
   - **SHA256**: 2 billion hashes/second
5. Groups results by strength classification

### Output

- `cracking_environment/dictionary_attack_results.csv`
- `graphs/dictionary_attack_results.png`

---

## Using pattern_attack.py

Tests passwords specifically for keyboard pattern vulnerabilities.

### Usage

```bash
cd project_root
python cracking_environment/pattern_attack.py
```

### What It Does

1. Loads cleaned passwords and identifies those containing keyboard patterns
2. Simulates pattern-based cracking (patterned passwords are assumed crackable)
3. Compares success rates between patterned and non-patterned passwords
4. Estimates crack time for each category

### Output

- `cracking_environment/pattern_attack_results.csv`
- `graphs/pattern_attack_success_rate.png`
- `graphs/pattern_vs_nopattern.png`

---

## Hash Algorithm Explanations

### MD5 (Message Digest 5)

| Property         | Value                                          |
|------------------|------------------------------------------------|
| Output Size      | 128 bits (32 hex characters)                   |
| Speed            | ~10 billion hashes/second (GPU)                |
| Security Status  | **Broken** – collision attacks demonstrated    |
| Use Case         | Legacy systems, checksums (NOT for passwords)  |

MD5 was designed in 1991 by Ronald Rivest. It produces a 128-bit hash value and was
widely used for password storage. However, it is now considered cryptographically broken
due to collision vulnerabilities discovered in 2004. Modern GPUs can compute billions
of MD5 hashes per second, making brute-force attacks trivially easy.

### SHA-1 (Secure Hash Algorithm 1)

| Property         | Value                                          |
|------------------|------------------------------------------------|
| Output Size      | 160 bits (40 hex characters)                   |
| Speed            | ~5 billion hashes/second (GPU)                 |
| Security Status  | **Deprecated** – collision attacks practical   |
| Use Case         | Legacy compatibility only                      |

SHA-1 was designed by the NSA and published in 1995. While stronger than MD5, Google
demonstrated a practical collision attack (SHAttered) in 2017. Most browsers and
certificate authorities have deprecated SHA-1.

### SHA-256 (Secure Hash Algorithm 256)

| Property         | Value                                          |
|------------------|------------------------------------------------|
| Output Size      | 256 bits (64 hex characters)                   |
| Speed            | ~2 billion hashes/second (GPU)                 |
| Security Status  | **Secure** – no known practical attacks        |
| Use Case         | Digital signatures, blockchain, file integrity |

SHA-256 is part of the SHA-2 family, designed by the NSA and published in 2001. It
remains cryptographically secure with no known collision or preimage attacks. While
significantly slower than MD5/SHA-1, it is still too fast for direct password hashing.

### Why Not Use These for Passwords?

For actual password storage, use **adaptive hashing algorithms** that are intentionally
slow and include a salt:

- **bcrypt** – adjustable work factor, built-in salt
- **scrypt** – memory-hard, resists GPU/ASIC attacks
- **Argon2** – winner of the Password Hashing Competition (2015)

These algorithms are designed to be slow (≈100ms per hash), making brute-force attacks
impractical even with modern hardware.

---

## Interpreting Results

### Dictionary Attack Results

| Column                  | Description                                      |
|-------------------------|--------------------------------------------------|
| `password`              | The tested password                              |
| `cracked`               | Whether the password was found in the wordlist   |
| `method`                | How it was cracked (exact/variation/not_cracked)  |
| `estimated_time_seconds`| Estimated time to crack via brute force          |
| `rules_score`           | Rules-based strength score (0–100)               |
| `entropy_score`         | Entropy-based strength score (0–100)             |
| `rules_classification`  | Weak / Medium / Strong                           |
| `entropy_classification`| Weak / Medium / Strong / Very Strong             |

### Pattern Attack Results

| Column                  | Description                                      |
|-------------------------|--------------------------------------------------|
| `password`              | The tested password                              |
| `has_pattern`           | Whether keyboard patterns were detected          |
| `cracked`               | Whether the password was "cracked" in simulation |
| `patterns_found`        | List of detected patterns                        |
| `estimated_time_seconds`| Estimated time to crack                          |

### Key Metrics to Look For

- **Crack Rate**: Percentage of passwords cracked in each category
- **Correlation**: How well do rules/entropy scores predict crackability?
- **Pattern Impact**: Do patterned passwords have significantly higher crack rates?
- **Time Estimates**: How do crack times vary across strength classifications?

---

## Troubleshooting

### Common Issues

| Issue                           | Solution                                        |
|---------------------------------|-------------------------------------------------|
| `ModuleNotFoundError: modules`  | Run scripts from the project root directory     |
| `FileNotFoundError: raw_passwords.csv` | Run `collect_datasets.py` first          |
| `FileNotFoundError: cleaned_passwords.csv` | Run `clean_datasets.py` first       |
| `ImportError: zxcvbn`           | Run `pip install zxcvbn`                        |
| `ImportError: matplotlib`       | Run `pip install matplotlib`                    |
| hashcat: `No devices found`    | Install GPU drivers (CUDA/ROCm/OpenCL)          |
| John: `No password hashes loaded` | Check hash file format matches `--format`    |

### Execution Order

Scripts must be run in this order:

```
1. python datasets/collect_datasets.py          # Generate raw passwords
2. python datasets/clean_datasets.py            # Clean and compute features
3. python cracking_environment/generate_hashes.py   # Generate hash files
4. python cracking_environment/dictionary_attack.py # Run dictionary attack
5. python cracking_environment/pattern_attack.py    # Run pattern attack
```

---

## Safety & Legal Disclaimer

> **This project is for EDUCATIONAL and ACADEMIC RESEARCH purposes ONLY.**
>
> - All passwords in this project are **synthetically generated** and do not represent
>   real user credentials.
> - The cracking simulations are **software-only** and do not interact with any
>   external systems or services.
> - **Do NOT** use these tools or techniques to attempt unauthorized access to any
>   system, account, or service.
> - The authors assume **no liability** for misuse of these tools or techniques.
> - Always follow your institution's Acceptable Use Policy and applicable laws.
>
> By using these tools, you acknowledge that you understand and accept these terms.
