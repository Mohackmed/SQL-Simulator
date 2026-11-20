# SQL Injection Simulator Toolkit

A safe, local, educational simulator that mimics SQL Injection vulnerabilities without connecting to a real database or executing raw SQL. Designed for cybersecurity education, red/blue team practice, and understanding how parameterized queries prevent attacks.

## 🎯 Features
* **Zero-Risk Environment:** Uses a mock in-memory database and a custom regex-based SQL evaluator. No real database engine is exposed or at risk.
* **Vulnerable vs. Secure:** Side-by-side comparisons of raw string concatenation vs. parameterized queries.
* **Simulated Attacks:** Supports classic boolean-based, tautology (`'1'='1`), and time-based (`SLEEP`) injections.
* **Interactive Scenarios:** Built-in lab exercises with an automatic hint and solution system.
* **Multiple Interfaces:**
  * **CLI Mode:** Interactive terminal with scenario-based exercises and scoring.
  * **Web UI:** Local Flask server demonstrating vulnerable and secure login forms.
  * **Demo Mode:** Automated showcase of common SQLi payloads.

## 📦 Included Files
* `sqlsimulator.py`: The complete, full-featured toolkit with web UI, CLI, and advanced simulations.
* `sql.py`: An intermediate version using a pure Python mock DB and basic string matching. 
* `code.py`: A basic proof-of-concept demonstrating unsafe vs. safe queries using an in-memory `sqlite3` database.

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/sql-simulator.git](https://github.com/YOUR_USERNAME/sql-simulator.git)
   cd sql-simulator

   Install the required dependencies (Flask is required for the Web UI):

Bash
pip install Flask==3.0.0
(Alternatively, run pip install -r requirements.txt if you created one).

💻 Usage
Run the main toolkit script (sqlsimulator.py) using one of the following modes:

1. CLI Mode (Default)
Run the interactive terminal interface:

Bash
python sqlsimulator.py --mode cli
2. Local Web UI
Launch the local web server:

Bash
python sqlsimulator.py --mode web --host 127.0.0.1 --port 5000
Then, open http://127.0.0.1:5000 in your web browser. (Note: This server is bound to localhost for safety).

3. Demo Mode
Quickly output an automated showcase of payloads:

Bash
python sqlsimulator.py --mode demo
⚠️ Safety Warning
This tool MUST only be run locally on your own machine. It does not connect to external databases and is meant strictly for education and training in controlled environments. Never use these techniques on production systems or databases you do not own.

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
