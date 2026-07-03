# PassMetric — Password Strength Comparative Analysis

> **Research Project:** A Comparative Analysis of Password Strength Metrics:  
> Rules-Based vs. Entropy-Based Evaluation

A professional Flask web application that analyses password strength using **five distinct methodologies** and presents a side-by-side comparative dashboard.

---

## Project Structure

### Person 1: Web Application & Core Modules
```text
project/
├── app.py                          # Flask entry point
├── requirements.txt                # Python dependencies
│
├── static/
│   ├── css/style.css               # Cybersecurity dark theme
│   └── js/script.js                # Frontend controller
│
├── templates/
│   └── index.html                  # Main UI template
│
└── modules/
    ├── rules_checker.py            # Rules-based evaluation
    ├── entropy_calculator.py       # Shannon entropy analysis
    ├── pattern_detector.py         # Keyboard pattern detection
    ├── zxcvbn_analyzer.py          # zxcvbn integration
    └── hybrid_metric.py            # Weighted hybrid score
```

### Person 2: Research Data & Analysis Pipeline
```text
project/
├── run_all_analysis.py             # Master orchestration script
├── requirements_research.txt       # Data science dependencies (Pandas, Seaborn)
│
├── datasets/                       # Data Collection & Cleaning
│   ├── collect_datasets.py         # Generates 10,000 synthetic passwords
│   ├── clean_datasets.py           # Evaluates dataset against all modules
│   └── cleaned_passwords.csv       # The final "Golden Dataset"
│
├── analysis/                       # Statistical Analysis Scripts
│   ├── eda_analysis.py             # Exploratory data trends
│   ├── classification_analysis.py  # Confusion matrix & flaw detection
│   ├── ttc_analysis.py             # Time-to-Crack hacker simulations
│   └── statistical_analysis.py     # Math regression & correlation
│
└── graphs/                         # Generated Comparative Charts
    ├── confusion_matrix.png
    ├── hybrid_comparison.png
    └── ... (6 other core charts)
```

---

## Setup & Installation

### Prerequisites
- Python 3.9 or higher
- pip

### Steps

```bash
# 1. Navigate to project directory
cd "Sem 4 mini project 3"

# 2. (Recommended) Create a virtual environment
python -m venv venv

# Activate on Windows:
venv\Scripts\activate

# Activate on macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

Then open your browser to: **http://127.0.0.1:5000**

### Running the Research Pipeline
To regenerate the 10,000-password dataset, run the benchmarking tests, and generate the comparative graphs:

```bash
# 1. Install data science dependencies
pip install -r requirements_research.txt

# 2. Run the master orchestration script
python run_all_analysis.py
```
*(All generated graphs and CSV reports will be saved in the `graphs/` and `analysis/` directories)*

---

## Features

| Feature | Description |
|---|---|
| **Rules-Based** | 6-rule checklist: length, upper, lower, digits, symbols, bonus |
| **Shannon Entropy** | H = N × log₂(C) with dynamic charset detection |
| **Pattern Detection** | Keyboard walks, sequential runs, repeated chars |
| **zxcvbn** | Realistic crack-time estimation and feedback |
| **Hybrid Score** | 30% Rules + 30% Entropy + 30% zxcvbn + 10% Pattern |
| **Comparison Chart** | Dual-panel Matplotlib chart (bar + radar) |
| **Suggestions** | Targeted improvement advice |
| **Real-time** | Live analysis on every keystroke |

### Research & Analysis Capabilities
- 📊 **Automated Dataset Generation:** Synthetically generates and scores 10,000 diverse passwords.
- 📈 **Statistical Regression:** Mathematical proof correlating Shannon Entropy with Time-To-Crack estimates.
- 🕵️ **Benchmarking:** Side-by-side validation proving the Hybrid Model aligns with Dropbox's `zxcvbn`.

---

## Scoring Reference

| Score | Rules / Hybrid | Entropy |
|---|---|---|
| **Weak** | 0–40 | < 40 bits |
| **Medium** | 41–70 | 40–60 bits |
| **Strong** | 71–90 | 60–80 bits |
| **Very Strong** | 91–100 | > 80 bits |

---

## API

### `POST /analyze`

**Request Body:**
```json
{ "password": "MyP@ssw0rd123" }
```

**Response:** JSON containing `rules`, `entropy`, `pattern`, `zxcvbn`, `hybrid`, and `chart` (base64 PNG).

---

## Technologies

- **Backend:** Python, Flask, matplotlib, pandas, numpy, zxcvbn
- **Frontend:** HTML5, CSS3 (custom), Bootstrap 5, Font Awesome 6, JavaScript (ES2020)
- **Design:** Cybersecurity dark theme, JetBrains Mono, Orbitron, Inter

---

*For educational and research purposes only. Passwords are never stored.*
