#!/usr/bin/env python3
"""
SQL Injection Simulator - Full Featured Educational Toolkit
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import shutil

# -----------------------------
# Mock Database
# -----------------------------
class MockDB:
    def __init__(self):
        self.tables = {
            "users": [
                {"id": 1, "username": "admin", "password": "admin123"},
                {"id": 2, "username": "alice", "password": "password"},
                {"id": 3, "username": "bob", "password": "123456"},
            ],
            "products": [
                {"id": 1, "name": "Laptop", "price": 1000},
                {"id": 2, "name": "Phone", "price": 500},
            ],
            "posts": [
                {"id": 1, "title": "Welcome", "body": "Hello world!"},
            ],
        }

    def get_table(self, name: str):
        return self.tables.get(name, [])


# -----------------------------
# SQL Evaluator (Safe Emulator)
# -----------------------------
class SQLEvaluator:
    def __init__(self, db: MockDB):
        self.db = db

    def vulnerable_login(self, username: str, password: str) -> bool:
        # Vulnerable query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"[DEBUG] Executing Query (vulnerable): {query}")
        # naive simulation
        if "' OR '1'='1" in username or "' OR '1'='1" in password:
            return True
        for row in self.db.get_table("users"):
            if row["username"] == username and row["password"] == password:
                return True
        return False

    def safe_login(self, username: str, password: str) -> bool:
        print("[DEBUG] Executing Query (safe with parameters)")
        for row in self.db.get_table("users"):
            if row["username"] == username and row["password"] == password:
                return True
        return False


# -----------------------------
# Scenarios
# -----------------------------
SCENARIOS = [
    {
        "id": 1,
        "title": "Bypass login with tautology",
        "hint": "Try using ' OR '1'='1",
        "solution": "' OR '1'='1",
    },
    {
        "id": 2,
        "title": "Attempt UNION-based extraction",
        "hint": "Use UNION SELECT",
        "solution": "' UNION SELECT null, 'hacked', 'pwd'--",
    },
]


# -----------------------------
# CLI Mode
# -----------------------------
class CLI:
    def __init__(self, db: MockDB, evaluator: SQLEvaluator):
        self.db = db
        self.evaluator = evaluator

    def run(self):
        print("\n[Interactive CLI Mode]")
        while True:
            print("\n1. Test vulnerable login")
            print("2. Test safe login")
            print("3. Run scenario lab")
            print("0. Exit")
            choice = input("Select option: ").strip()
            if choice == "1":
                u = input("Enter username: ")
                p = input("Enter password: ")
                print("Login success?" , self.evaluator.vulnerable_login(u,p))
            elif choice == "2":
                u = input("Enter username: ")
                p = input("Enter password: ")
                print("Login success?" , self.evaluator.safe_login(u,p))
            elif choice == "3":
                self.run_scenarios()
            elif choice == "0":
                break

    def run_scenarios(self):
        for sc in SCENARIOS:
            print(f"\nScenario {sc['id']}: {sc['title']}")
            attempt = input("Enter payload: ")
            if attempt.strip() == sc["solution"]:
                print("✅ Correct! You solved it.")
            else:
                print(f"❌ Incorrect. Hint: {sc['hint']}")


# -----------------------------
# Web UI Mode (Flask)
# -----------------------------
try:
    from flask import Flask, request, render_template_string
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

class WebUI:
    def __init__(self, db: MockDB, evaluator: SQLEvaluator, host="127.0.0.1", port=5000):
        self.db = db
        self.evaluator = evaluator
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        @self.app.route("/", methods=["GET", "POST"])
        def index():
            message = ""
            if request.method == "POST":
                u = request.form.get("username", "")
                p = request.form.get("password", "")
                if request.form.get("mode") == "vulnerable":
                    result = self.evaluator.vulnerable_login(u,p)
                    message = "Login success!" if result else "Login failed."
                else:
                    result = self.evaluator.safe_login(u,p)
                    message = "Login success!" if result else "Login failed."

            template = """
            <html>
              <head>
                <title>SQL Injection Simulator</title>
                <style>
                  body { font-family: Arial, sans-serif; padding:20px; background:#f4f4f4;}
                  h1 { text-align:center; color:#333;}
                  form { margin:20px auto; padding:20px; background:#fff; border-radius:10px; width:400px; box-shadow:0 0 10px rgba(0,0,0,0.1);}
                  input { margin:5px 0; padding:8px; width:100%;}
                  button { padding:10px; margin-top:10px; width:100%; border:none; border-radius:5px; background:#333; color:#fff;}
                  .message { margin-top:20px; font-weight:bold; }
                </style>
              </head>
              <body>
                <h1>SQL Injection Simulator</h1>
                <form method="POST">
                  <input type="text" name="username" placeholder="Username" required>
                  <input type="password" name="password" placeholder="Password" required>
                  <select name="mode">
                    <option value="vulnerable">Vulnerable Login</option>
                    <option value="safe">Safe Login</option>
                  </select>
                  <button type="submit">Submit</button>
                  <div class="message">{{message}}</div>
                </form>
              </body>
            </html>
            """
            return render_template_string(template, message=message)

    def run(self):
        self.app.run(host=self.host, port=self.port)


# -----------------------------
# Demo Mode
# -----------------------------
def demo_print_examples(db: MockDB, evaluator: SQLEvaluator):
    print("\n[Demo Mode]")
    print("Trying vulnerable login with payload: admin / wrongpass")
    print("Result:", evaluator.vulnerable_login("admin", "wrongpass"))
    print("Trying vulnerable login with payload: admin / ' OR '1'='1")
    print("Result:", evaluator.vulnerable_login("admin", "' OR '1'='1"))


# -----------------------------
# Linux Terminal Banner
# -----------------------------
def print_banner():
    term_width = shutil.get_terminal_size((80, 20)).columns
    title = "SQL Injection Simulator"
    border = "=" * term_width
    centered_title = title.center(term_width)
    ascii_art = f"""
   _____  ____  
  / ____|/ __ \\
 | (___ | |  | |     ___   ___  _ __ 
  \\___ \\| |  | |    / _ \\ / _ \\| '_ \\
  ____) | |__| |   | (_) | (_) | | | |
 |_____/ \\____/     \\___/ \\___/|_| |_|
    """
    print(border)
    for line in ascii_art.splitlines():
        print(line.center(term_width))
    print(centered_title)
    print(border)


# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="SQL Injection Simulator Toolkit")
    parser.add_argument('--mode', choices=['cli', 'web', 'demo'], default='cli')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()

    print_banner()

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

