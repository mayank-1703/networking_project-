import sqlite3
DB_NAME = "network.db"
def initialize_database():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT,
        protocol TEXT,
        duration REAL,
        packets INTEGER,
        bytes INTEGER,
        attack_type TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat TEXT,
        confidence REAL,
        source_ip TEXT
    )
    """)
    conn.commit()
    conn.close()


def insert_traffic(data):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO traffic_logs(
        src_ip,
        protocol,
        duration,
        packets,
        bytes,
        attack_type
    )
    VALUES(?,?,?,?,?,?)
    """,
    (
        data["src_ip"],
        data["protocol"],
        data["duration"],
        data["packets"],
        data["bytes"],
        data["label"]
    ))

    conn.commit()
    conn.close()


def insert_alert(
    threat,
    confidence,
    source_ip
):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO alerts(
        threat,
        confidence,
        source_ip
    )
    VALUES(?,?,?)
    """,
    (
        threat,
        confidence,
        source_ip
    ))

    conn.commit()
    conn.close()


def get_alerts():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM alerts
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_traffic_logs():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM traffic_logs
    ORDER BY id DESC
    LIMIT 100
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


if __name__ == "__main__":

    initialize_database()

    print("Database Created")