"""
TEST FILE — contains KNOWN vulnerabilities for scanner verification
"""
import os
import sqlite3

# --- (a) Hardcoded API key ---
OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"

# --- (b) SQL injection via f-string ---
def get_user(name):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()

# --- (c) Command injection ---
def ping_host(host):
    os.system("ping -c 4 " + host)

# --- (d) Weak crypto ---
import hashlib
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
