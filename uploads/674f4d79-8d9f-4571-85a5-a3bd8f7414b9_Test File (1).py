import os
import subprocess
import sqlite3
import requests

# Hardcoded secret (Gitleaks)
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
password = "123456"

# Insecure command execution (Semgrep)
def run_command(user_input):
    command = "ls " + user_input
    os.system(command)

# SQL Injection vulnerability (Semgrep)
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    return cursor.fetchall()

# Insecure HTTP request (Semgrep)
def fetch_data():
    return requests.get("http://example.com")

# Suspicious binary pattern for YARA
def fake_malware_pattern():
    signature = "MZ\x90\x00\x03\x00\x00\x00"
    print(signature)

# Simulated credential usage
def login():
    user = "admin"
    pwd = "admin123"
    print(f"Logging in with {user}:{pwd}")

if __name__ == "__main__":
    run_command("; rm -rf /")
    get_user("' OR '1'='1")
    fetch_data()
    fake_malware_pattern()
    login()