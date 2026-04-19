import sqlite3

DB_NAME = 'cybershield.db'

def get_db_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA journal_mode=WAL;")

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        file_name TEXT,
        action TEXT,
        encryption_key TEXT DEFAULT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS phishing_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER DEFAULT NULL,
        target_url TEXT,
        score INTEGER DEFAULT 0,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    try:
        cursor.execute("ALTER TABLE file_logs ADD COLUMN encryption_key TEXT DEFAULT NULL")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE phishing_logs ADD COLUMN user_id INTEGER DEFAULT NULL")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE phishing_logs ADD COLUMN target_url TEXT")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE phishing_logs ADD COLUMN score INTEGER DEFAULT 0")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
    except:
        pass

    conn.commit()
    conn.close()