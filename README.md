 Hybrid-Metric Password Analyzer

An enterprise-grade, full-stack cybersecurity web application that evaluates password strength by mathematically eliminating the "False Positives" found in traditional strength meters. Built with Python and Flask.

 Key Features

* **Hybrid Scoring Engine:** Traditional meters rely on single algorithms (like pure math or strict rules) which create severe blind spots. This engine combines 4 distinct modules to generate a highly accurate 0-100 security score.
* **Live Threat Intelligence:** Connects securely to the HaveIBeenPwned Cloud API (800M+ breached passwords) to detect zero-day leaked credentials in real-time.
* **k-Anonymity Privacy Model:** Guarantees 100% user privacy. Passwords are encrypted using SHA-1 hashing, and only a 5-character prefix is transmitted over the network—meaning the API never sees the plaintext password.
* **"Glass Box" UI Transparency:** Replaces traditional "Black Box" meters with a dynamic, educational interface that explicitly breaks down exactly why a password was penalized.

 System Architecture (The 4 Layers)

Our scoring algorithm acts as a panel of judges, combining:
1. **Shannon Entropy (Math):** Calculates the theoretical cryptographic randomness and bit-strength.
2. **Dictionary Heuristics (`zxcvbn`):** Cross-references against massive dictionaries to catch human predictability and lazy keyboard patterns.
3. **Regex Rules Engine:** Enforces character diversity (uppercase, numbers, symbols).
4. **Live Cryptographic Pipeline:** The final fail-safe that checks real-world threat databases.

Data Science Validation
This architecture was statistically validated by generating a synthetic dataset of 10,000 passwords. Utilizing Python's data science stack (`pandas`, `scikit-learn`, `matplotlib`), we generated machine-learning Confusion Matrices that mathematically proved our Hybrid Score eliminates the False Positives that fool legacy algorithms.

 Tech used
* **Backend:** Python, Flask REST API
* **Frontend:** HTML5, Vanilla JavaScript, CSS3
* **Security:** `hashlib` (SHA-1), HaveIBeenPwned API
* **Data Science:** `pandas`, `scikit-learn`, `matplotlib`

 How to Run Locally

1. Clone this repository to your local machine.
2. Open a terminal inside the project folder and create a virtual environment:
   ```bash
   python -m venv venv

   Activate the virtual environment:
Windows: .\venv\Scripts\activate
Mac/Linux: source venv/bin/activate

Install the required dependencies:
pip install flask requests zxcvbn

Run the application:
python app.py
