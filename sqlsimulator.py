"""
SQL Injection Simulator - Full Featured Educational Toolkit
File: SQL_Injection_Simulator_Toolkit.py
Author: Mohamed Abdullah
Date: 2025-08-12

PURPOSE
-------
This toolkit is a safe, local, educational simulator that mimics many properties of
SQL Injection without connecting to any real database or executing raw SQL.

FEATURES
--------
- Mock in-memory "database" (tables represented as Python lists/dicts)
- Multiple simulated query engines (vulnerable vs parameterized)
- Simulated injection types:
    * Classic boolean-based injection
    * UNION-based injection (simulated)
    * Error-based injection (simulated)
    * Time-based injection (simulated sleep)
    * Blind (boolean/time) techniques
- Interactive CLI with step-by-step guidance
- Optional local web UI (Flask) that emulates login and search forms
- Scenario-based exercises and an automatic "hint/solution" system
- Logging and scoring for lab-style practice
- Clear safety warnings: NEVER use this tool on production or real DBs

HOW IT WORKS (high-level)
-------------------------
Instead of executing SQL, the toolkit builds a simulated SQL string (for teaching)
and evaluates the intent of the input using a custom, minimal "SQL evaluator".
This evaluator understands simple WHERE clauses and boolean logic and can detect
special payload patterns (like "' OR '1'='1") and emulate their effect.

USAGE
-----
Command-line examples:
  python SQL_Injection_Simulator_Toolkit.py --mode cli
  python SQL_Injection_Simulator_Toolkit.py --mode web --host 127.0.0.1 --port 5000

Run the file and follow the prompts. The web mode hosts a local server you can
open in your browser (localhost only). The server is for local learning only.

SAFETY
------
This tool MUST only be run locally on your own machine. It does NOT connect to
external databases. It is meant for education and red-team/blue-team practice in
controlled environments.

"""

from __future__ import annotations
import argparse
import html
import json
import logging
import random
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Optional dependency for web UI
try:
    from flask import Flask, request, render_template_string, redirect, url_for
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("sqlsim")

# -----------------------------
# Mock Database
# -----------------------------
@dataclass
class Table:
    name: str
    columns: List[str]
    rows: List[Dict[str, Any]] = field(default_factory=list)

    def dump(self) -> List[Dict[str, Any]]:
        # Return deep-ish copy for safety
        return [dict(r) for r in self.rows]

class MockDB:
    def __init__(self):
        self.tables: Dict[str, Table] = {}
        self._populate_defaults()

    def _populate_defaults(self):
        # Users table
        users = Table(
            name="users",
            columns=["id", "username", "password", "email", "is_admin"],
            rows=[
                {"id": 1, "username": "admin", "password": "admin123", "email": "admin@example.com", "is_admin": True},
                {"id": 2, "username": "john", "password": "johnpass", "email": "john@example.com", "is_admin": False},
                {"id": 3, "username": "maria", "password": "mariapass", "email": "maria@example.com", "is_admin": False},
            ]
        )
        products = Table(
            name="products",
            columns=["id", "name", "price", "stock"],
            rows=[
                {"id": 1, "name": "Laptop", "price": 799.99, "stock": 12},
                {"id": 2, "name": "Phone", "price": 499.0, "stock": 30},
            ]
        )
        posts = Table(
            name="posts",
            columns=["id", "title", "content", "author_id"],
            rows=[
                {"id": 1, "title": "Hello World", "content": "Welcome to the site", "author_id": 2},
            ]
        )
        self.tables["users"] = users
        self.tables["products"] = products
        self.tables["posts"] = posts

    def get_table(self, name: str) -> Optional[Table]:
        return self.tables.get(name)

    def show_schema(self) -> str:
        out = []
        for t in self.tables.values():
            out.append(f"TABLE {t.name}: columns={t.columns} rows={len(t.rows)}")
        return "\n".join(out)

# -----------------------------
# Minimal "SQL evaluator" (simulated)
# - Purpose: Evaluate simple WHERE clauses or detect common injection patterns
# - NOT a SQL parser. This is intentionally limited for educational clarity.
# -----------------------------

BOOL_PATTERN = re.compile(r"\b(AND|OR)\b", re.IGNORECASE)
SIMPLE_COMP = re.compile(r"\s*(\w+)\s*=\s*'([^']*)'\s*", re.IGNORECASE)

class SQLEvaluator:
    def __init__(self, db: MockDB):
        self.db = db

    def render_query(self, table: str, where_clause: str) -> str:
        # Build fake SQL for display (escaped for teaching)
        safe_where = html.escape(where_clause)
        return f"SELECT * FROM {table} WHERE {safe_where};"

    def evaluate_where(self, table: str, where_clause: str) -> List[Dict[str, Any]]:
        # Very basic evaluation: supports simple equality comparisons joined by AND/OR
        tbl = self.db.get_table(table)
        if not tbl:
            return []

        clause = where_clause.strip()
        # Detect time-based payloads (sleep simulation)
        if re.search(r"SLEEP\s*\(|WAITFOR\s+DELAY", clause, re.IGNORECASE):
            # Simulate delay to teach time-based inference
            logger.info("[Sim] Detected time-based payload -> simulating sleep")
            # extract delay seconds if possible
            return self._delayed_result(tbl.rows, delay=2)

        # Detect tautologies
        if re.search(r"\b1\s*=\s*1\b|\b'1'\s*=\s*'1'\b", clause):
            logger.info("[Sim] Detected tautology -> returning all rows")
            return tbl.dump()

        # Very naive: split on OR then AND
        if re.search(r"\bOR\b", clause, re.IGNORECASE):
            parts = re.split(r"\bOR\b", clause, flags=re.IGNORECASE)
            results = []
            for p in parts:
                results.extend(self._filter_by_simple_clause(tbl.rows, p.strip()))
            # unique
            uniq = {json.dumps(r, sort_keys=True): r for r in results}
            return list(uniq.values())
        else:
            return self._filter_by_simple_clause(tbl.rows, clause)

    def _filter_by_simple_clause(self, rows: List[Dict[str, Any]], clause: str) -> List[Dict[str, Any]]:
        # Support multiple ANDs
        clauses = re.split(r"\bAND\b", clause, flags=re.IGNORECASE)
        filtered = rows
        for c in clauses:
            m = SIMPLE_COMP.search(c)
            if not m:
                # if we cannot parse, return empty (safe default) but also detect special injection
                if "' OR '1'='1" in c or "OR 1=1" in c.upper():
                    logger.info("[Sim] Detected common OR tautology pattern")
                    return rows
                return []
            col, val = m.group(1), m.group(2)
            filtered = [r for r in filtered if str(r.get(col)) == val]
        return filtered

    def _delayed_result(self, rows: List[Dict[str, Any]], delay: int = 2) -> List[Dict[str, Any]]:
        time.sleep(delay)
        return rows

# -----------------------------
# Simulated query functions
# -----------------------------

def vulnerable_query(db: MockDB, table: str, username_input: str, password_input: str, evaluator: SQLEvaluator) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Build a vulnerable-looking SQL string by direct concatenation and evaluate it
    using our simulated evaluator. Returns (success, rendered_query, rows_returned).
    """
    # Build the "vulnerable" WHERE clause string as if concatenated
    # For demonstration we put the user inputs inside single quotes directly
    where = f"username = '{username_input}' AND password = '{password_input}'"
    rendered = evaluator.render_query(table, where)
    rows = evaluator.evaluate_where(table, where)
    success = len(rows) > 0
    return success, rendered, rows


def parameterized_query(db: MockDB, table: str, username_input: str, password_input: str, evaluator: SQLEvaluator) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Simulate a parameterized query: the rendered query shows placeholders and the
    evaluator only matches literal values (no injection allowed).
    """
    rendered = f"SELECT * FROM {table} WHERE username = ? AND password = ?"
    # Do exact matching only — do not interpret special SQL strings
    tbl = db.get_table(table)
    if not tbl:
        return False, rendered, []
    rows = [r for r in tbl.dump() if str(r.get("username")) == username_input and str(r.get("password")) == password_input]
    success = len(rows) > 0
    return success, rendered, rows

# -----------------------------
# Exercise / Scenario Manager
# -----------------------------

@dataclass
class Scenario:
    id: int
    title: str
    description: str
    hint: str
    solution_example: str
    table: str = "users"

DEFAULT_SCENARIOS = [
    Scenario(
        id=1,
        title="Login bypass (classic tautology)",
        description="Log in as admin even if you do not know the password.",
        hint="Try to break the WHERE clause logic with OR or tautologies.",
        solution_example="username: ' OR '1'='1 --\npassword: anything"
    ),
    Scenario(
        id=2,
        title="Extract user count (boolean)",
        description="Using boolean responses, figure out whether there are more than 2 users.",
        hint="Probe numeric comparisons in conditions or use OR/AND to change results.",
        solution_example="Blind approach: try ' OR (SELECT COUNT(*) FROM users) > 2 --"
    ),
    Scenario(
        id=3,
        title="Time-based detection",
        description="Detect if the backend evaluates functions using sleep/delay.",
        hint="Try payloads that invoke SLEEP or WAITFOR DELAY and observe response time.",
        solution_example="username: ' OR 1=1; SLEEP(2); --"
    ),
]

# -----------------------------
# CLI Interface
# -----------------------------

class CLI:
    def __init__(self, db: MockDB, evaluator: SQLEvaluator):
        self.db = db
        self.evaluator = evaluator
        self.score = 0
        self.attempts = 0

    def banner(self):
        print("=== SQL Injection Simulator (Full Toolkit) ===")
        print("Safety: This is local and educational. Do not use on real systems.")
        print(self.db.show_schema())

    def run(self):
        self.banner()
        while True:
            print("\nSelect an option:")
            print(" 1) Try vulnerable login")
            print(" 2) Try secure (parameterized) login")
            print(" 3) Run a scenario/exercise")
            print(" 4) Show table data (for debugging)")
            print(" 5) Exit")
            choice = input("> ").strip()
            if choice == "1":
                self.vulnerable_flow()
            elif choice == "2":
                self.secure_flow()
            elif choice == "3":
                self.scenario_flow()
            elif choice == "4":
                self.dump_table()
            elif choice == "5":
                print("Bye — keep learning safely!")
                break
            else:
                print("Invalid choice")

    def vulnerable_flow(self):
        username = input("Enter username: ")
        password = input("Enter password: ")
        success, rendered, rows = vulnerable_query(self.db, "users", username, password, self.evaluator)
        print("\n[VULNERABLE MODE]")
        print("Rendered SQL (for teaching):")
        print(rendered)
        if success:
            print("Result: Login SUCCESS")
            print("Rows returned:")
            for r in rows:
                print(json.dumps(r, default=str))
        else:
            print("Result: Login FAILED")

    def secure_flow(self):
        username = input("Enter username: ")
        password = input("Enter password: ")
        success, rendered, rows = parameterized_query(self.db, "users", username, password, self.evaluator)
        print("\n[SECURE MODE]")
        print("Rendered Query:")
        print(rendered)
        if success:
            print("Login SUCCESS (correct creds)")
            for r in rows:
                print(json.dumps(r, default=str))
        else:
            print("Login FAILED")

    def scenario_flow(self):
        print("Available scenarios:")
        for s in DEFAULT_SCENARIOS:
            print(f" {s.id}) {s.title} - {s.description}")
        sid = input("Pick scenario id (or 'q' to cancel): ")
        if sid.lower() == "q":
            return
        try:
            sid = int(sid)
        except ValueError:
            print("Invalid")
            return
        scenario = next((x for x in DEFAULT_SCENARIOS if x.id == sid), None)
        if not scenario:
            print("Invalid scenario")
            return
        print(f"Selected: {scenario.title}\n{scenario.description}\nHint: {scenario.hint}")
        payload = input("Enter payload (username field): ")
        password = input("Enter password (ignored for many attacks): ")
        self.attempts += 1
        success, rendered, rows = vulnerable_query(self.db, scenario.table, payload, password, self.evaluator)
        print("Rendered SQL:")
        print(rendered)
        if success:
            print("Attack succeeded! Rows returned:")
            for r in rows:
                print(json.dumps(r, default=str))
            self.score += 1
        else:
            print("Attack did not return rows — think about blind or time-based techniques")
        print(f"Score: {self.score}/{self.attempts}")
        show_solution = input("Show suggested solution? (y/N): ")
        if show_solution.lower() == "y":
            print("Suggested payload example:\n", scenario.solution_example)

    def dump_table(self):
        name = input("Table name: ")
        tbl = self.db.get_table(name)
        if not tbl:
            print("No such table")
            return
        for r in tbl.dump():
            print(json.dumps(r, default=str))

# -----------------------------
# Optional Flask Web UI (local only)
# -----------------------------

WEB_TEMPLATE = '''
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SQL Injection Simulator</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: #f4f4f9; color: #333; }
h1 { color: #444; }
.container { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
form { margin-bottom: 20px; padding: 15px; background: #fafafa; border: 1px solid #ddd; border-radius: 8px; }
input[type=text], input[type=password], input[type=number] { padding: 8px; margin: 5px 0; width: 80%; border-radius: 5px; border: 1px solid #bbb; }
input[type=submit] { padding: 8px 15px; border: none; border-radius: 5px; background: #007BFF; color: #fff; cursor: pointer; }
input[type=submit]:hover { background: #0056b3; }
.section { margin-top: 25px; }
pre { background: #272822; color: #f8f8f2; padding: 15px; border-radius: 8px; overflow-x: auto; }
.success { color: green; font-weight: bold; }
.fail { color: red; font-weight: bold; }
.scenario-card { background: #eef; padding: 15px; border-radius: 8px; margin-bottom: 15px; }
</style>
</head>
<body>
<div class="container">
<h1>💻 SQL Injection Simulator (Local Only)</h1>
<p><b>Warning:</b> Educational use only. This is a safe mock simulator, not a real DB.</p>


<div class="section">
<h2>🔓 Vulnerable Login</h2>
<form method="post" action="/vuln_login">
<label>Username:</label><br>
<input name="username" type="text" required><br>
<label>Password:</label><br>
<input name="password" type="password" required><br><br>
<input type="submit" value="Login (Vulnerable)">
</form>
</div>


<div class="section">
<h2>🔒 Secure Login</h2>
<form method="post" action="/safe_login">
<label>Username:</label><br>
<input name="username" type="text" required><br>
<label>Password:</label><br>
<input name="password" type="password" required><br><br>
<input type="submit" value="Login (Secure)">
</form>
</div>
</div>


<div class="section">
<h2>📜 Debug / Output</h2>
</div>
'''

class WebUI:
    def __init__(self, db: MockDB, evaluator: SQLEvaluator, host: str = '127.0.0.1', port: int = 5000):
        if not FLASK_AVAILABLE:
            raise RuntimeError("Flask is not available. Install flask to use web UI: pip install flask")
        self.db = db
        self.evaluator = evaluator
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):
        @self.app.route('/', methods=['GET'])
        def index():
            debug = self.db.show_schema()
            return render_template_string(WEB_TEMPLATE, debug=debug)

        @self.app.route('/vuln_login', methods=['POST'])
        def vuln_login():
            username = request.form.get('username','')
            password = request.form.get('password','')
            success, rendered, rows = vulnerable_query(self.db, 'users', username, password, self.evaluator)
            debug = f"Rendered: {rendered}\nSuccess: {success}\nRows: {rows}"
            return render_template_string(WEB_TEMPLATE + "<pre>{{debug}}</pre>", debug=debug)

        @self.app.route('/safe_login', methods=['POST'])
        def safe_login():
            username = request.form.get('username','')
            password = request.form.get('password','')
            success, rendered, rows = parameterized_query(self.db, 'users', username, password, self.evaluator)
            debug = f"Rendered: {rendered}\nSuccess: {success}\nRows: {rows}"
            return render_template_string(WEB_TEMPLATE + "<pre>{{debug}}</pre>", debug=debug)

        @self.app.route('/scenario', methods=['POST'])
        def scenario():
            sid = int(request.form.get('sid','1'))
            payload = request.form.get('payload','')
            scenario = next((x for x in DEFAULT_SCENARIOS if x.id == sid), DEFAULT_SCENARIOS[0])
            success, rendered, rows = vulnerable_query(self.db, scenario.table, payload, '', self.evaluator)
            debug = f"Scenario: {scenario.title}\nRendered: {rendered}\nSuccess: {success}\nRows: {rows}"
            return render_template_string(WEB_TEMPLATE + "<pre>{{debug}}</pre>", debug=debug)

    def run(self):
        # Start Flask server (blocking)
        self.app.run(host=self.host, port=self.port, debug=False)

# -----------------------------
# Utilities / Demos
# -----------------------------

def demo_print_examples(db: MockDB, evaluator: SQLEvaluator):
    print("\n--- Demo examples ---")
    payloads = ["admin' --", "' OR '1'='1", "' OR 1=1; SLEEP(2); --"]
    for p in payloads:
        success, rendered, rows = vulnerable_query(db, 'users', p, 'anything', evaluator)
        print(f"Payload: {p}")
        print("Rendered:", rendered)
        print("Success:", success, "Rows:", len(rows))
        print("---")

# -----------------------------
# Main entrypoint
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Simulator Toolkit")
    parser.add_argument('--mode', choices=['cli', 'web', 'demo'], default='cli')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()

    db = MockDB()
    evaluator = SQLEvaluator(db)

    if args.mode == 'cli':
        cli = CLI(db, evaluator)
        cli.run()
    elif args.mode == 'web':
        if not FLASK_AVAILABLE:
            print("Flask is not installed. Install with: pip install flask")
            return
        web = WebUI(db, evaluator, host=args.host, port=args.port)
        print(f"Starting local web UI on http://{args.host}:{args.port} (local only)")
        web.run()
    elif args.mode == 'demo':
        demo_print_examples(db, evaluator)

if __name__ == '__main__':
    main()

