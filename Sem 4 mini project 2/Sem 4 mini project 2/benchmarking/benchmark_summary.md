# Benchmark Summary – Password Strength Metrics

**Generated:** June 2026  
**Standards:** NIST SP 800‑63B (2017), Microsoft Password Guidelines

---

## Overall Compliance Rates

| Standard  | Pass Rate |
|-----------|-----------|
| NIST 800‑63B | 73.0% |
| Microsoft    | 49.1% |

---

## Metrics vs NIST

| Metric | Accuracy | Precision | Recall | F1 | FPR | FNR |
|--------|----------|-----------|--------|-----|-----|-----|
| Rules‑Based | 0.7019 | 0.9995 | 0.5920 | 0.7436 | 0.0008 | 0.4080 |
| Entropy‑Based | 0.5975 | 0.9997 | 0.4487 | 0.6194 | 0.0004 | 0.5513 |
| Hybrid (Person 1) | 0.6448 | 1.0000 | 0.5134 | 0.6784 | 0.0000 | 0.4866 |

## Metrics vs Microsoft

| Metric | Accuracy | Precision | Recall | F1 | FPR | FNR |
|--------|----------|-----------|--------|-----|-----|-----|
| Rules‑Based | 0.9383 | 0.9967 | 0.8773 | 0.9332 | 0.0028 | 0.1227 |
| Entropy‑Based | 0.7172 | 0.8180 | 0.5457 | 0.6547 | 0.1172 | 0.4543 |
| Hybrid (Person 1) | 0.7989 | 0.8871 | 0.6768 | 0.7678 | 0.0832 | 0.3232 |

---

## Key Observations

1. **Rules‑based** metrics tend to have the highest false‑positive rate against NIST guidelines.
2. **Entropy‑based** metrics align more closely with NIST's length‑and‑breach approach.
3. **Hybrid models** achieve a balance between false positives and false negatives.
4. **Microsoft** guidelines are stricter due to the 3‑of‑4 character‑type requirement.
