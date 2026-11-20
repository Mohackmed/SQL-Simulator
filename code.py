import sqlite3

def setup_database():
    conn = sqlite3.connect(":memory:")  # In-memory DB
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (username TEXT, password TEXT)")
    
    # Insert fake data
    cur.executemany("INSERT INTO users VALUES (?, ?)", [
        ("alice", "password123"),
        ("bob", "hunter2"),
        ("charlie", "mypassword")
    ])
    conn.commit()
    return conn

def unsafe_login(conn, username, password):
    # Vulnerable query (string concatenation)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"[DEBUG] Executing: {query}")
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()

def safe_login(conn, username, password):
    # Safe query (parameterized)
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cur = conn.cursor()
    cur.execute(query, (username, password))
    return cur.fetchall()

def main():
    conn = setup_database()
    
    print("=== SQL Injection Simulator ===")
    print("1. Unsafe Mode (Vulnerable)")
    print("2. Safe Mode (Protected)")
    choice = input("Choose mode: ")
    
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    if choice == "1":
        results = unsafe_login(conn, username, password)
    else:
        results = safe_login(conn, username, password)
    
    if results:
        print("[SUCCESS] Logged in!")
    else:
        print("[FAIL] Login failed.")

if __name__ == "__main__":
    main()

