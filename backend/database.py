import sqlite3
import json
from datetime import datetime


def init_db():

    conn = sqlite3.connect("fraudshield.db")
    cursor = conn.cursor()

    # SMS scan history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            risk_score INTEGER,
            status TEXT,
            detected_words TEXT,
            scan_time TEXT
        )
    """)

    # Website scan history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS website_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT,
            risk_score INTEGER,
            status TEXT,
            warnings TEXT,
            scan_time TEXT
        )
    """)

    conn.commit()
    conn.close()


# Save SMS scan
def save_scan(message, result):

    conn = sqlite3.connect("fraudshield.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans
        (message, risk_score, status, detected_words, scan_time)
        VALUES (?, ?, ?, ?, ?)
    """, (
        message,
        result["risk_score"],
        result["status"],
        json.dumps(result["detected_words"]),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# Get SMS history
def get_history():

    conn = sqlite3.connect("fraudshield.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY id DESC")

    records = cursor.fetchall()

    conn.close()

    return records


# Save website scan
def save_website_scan(url, result):

    conn = sqlite3.connect("fraudshield.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO website_scans
        (website, risk_score, status, warnings, scan_time)
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        result["risk_score"],
        result["status"],
        json.dumps(result["warnings"]),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# Get website history
def get_website_history():

    conn = sqlite3.connect("fraudshield.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM website_scans
        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    conn.close()

    return records