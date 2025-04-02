import sqlite3 as sql
import html
import random
import time
import hashlib
import os
import base64

def hash_password(password, salt):
    """
    Hash the password using SHA-256 with a salt.
    Returns the salt and the hashed password in base64 format for storage.
    """
    salted_password = salt + password.encode('utf-8')
    sha256_hash = hashlib.sha256()
    sha256_hash.update(salted_password)
    hashed_password = sha256_hash.digest()
    return base64.b64encode(hashed_password).decode('utf-8')


def generate_salt():
    """
    Generate a random salt using os.urandom for better randomness.
    """
    return base64.b64encode(os.urandom(16)).decode('utf-8')

def insertUser(username, password, DoB):
    hashed_password = hash_password(password) #hash the password
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    """
    These are parametrized queries.
    Parameterized queries separate the SQL query from the user input values. 
    The user input values are passed as parameters, which are treated as literal values and checked for type and length.
    So they are not executed as part of the SQL command.
    """
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)",
        (username, hashed_password, DoB)
    )
    con.commit()
    con.close()

def retrieveUsers(username, password):
    """
    Retrieve a user by username and password.
    Combines username and password checks in a single parameterized query.
    The provided password is hashed before comparison.
    Also updates a visitor log in a secure manner.
    """
    hashed_password = hash_password(password)
    try:
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        # Combined check for username and hashed password
        cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                    (username, hashed_password)) #parametrized queries to prevent SQLi
        user = cur.fetchone()
        if user is None:
            return False

        # Update visitor log in a single file operation using r+ mode (more efficient)
        try:
            with open("visitor_log.txt", "r+") as file:
                content = file.read().strip()
                number = int(content) if content else 0
                number += 1
                file.seek(0)
                file.write(str(number))
                file.truncate()
        except Exception:
            pass
        time.sleep(random.uniform(0.08, 0.09))  # Simulated delay for testing purposes can be removed in production
        return True
    finally:
        con.close()

def insertFeedback(feedback):
    """
    Insert user feedback into the database using a parameterized query.
    The feedback is stored safely to prevent SQL injection.
    """
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,)) 
    con.commit()
    con.close()

def listFeedback():
    """
    Retrieve all feedback from the database and safely write it to an HTML partial.
    The output is escaped to prevent XSS vulnerabilities.
    """
    with sql.connect("database_files/database.db") as con, open("templates/partials/success_feedback.html", "w") as f:
        feedbacks = con.execute("SELECT feedback FROM feedback").fetchall() #parametrized queries to prevent SQLi
        f.writelines(f"<p>\n{html.escape(row[0])}\n</p>\n" for row in feedbacks) #escape feedback to prevent XSS
