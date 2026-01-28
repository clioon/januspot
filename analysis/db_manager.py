import sqlite3

class DatabaseManager:
    def __init__(self, db_path='honeypot.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        print("[*] Creating tables (if needed)...")

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Attacker (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            country TEXT,
            as_name TEXT,
            as_domain TEXT
        );
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Session (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attacker_id INTEGER NOT NULL,
            honeypot_port INTEGER,
            client_port INTEGER,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (attacker_id) REFERENCES Attacker (id)
        );
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS LoginAttempt (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            username TEXT,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (session_id) REFERENCES Session (id)
        );
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS PasswordAttempt (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            password TEXT,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (session_id) REFERENCES Session (id)
        );
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ShellCommand (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            command TEXT,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (session_id) REFERENCES Session (id)
        );
        ''')
        self.conn.commit()
        print("[*] Tables OK.")

        

    def get_or_create_attacker(self, ip, country, as_name, as_domain):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM Attacker WHERE ip_address = ?", (ip,))
        result = cursor.fetchone()
        if result:
            return result[0]
        
        cursor.execute(
            "INSERT INTO Attacker (ip_address, country, as_name, as_domain) VALUES (?, ?, ?, ?)",
            (ip, country, as_name, as_domain)
        )
        return cursor.lastrowid

    def insert_session(self, attacker_id, hp_port, cli_port, ts):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO Session (attacker_id, honeypot_port, client_port, timestamp) VALUES (?, ?, ?, ?)",
            (attacker_id, hp_port, cli_port, ts)
        )
        return cursor.lastrowid

    def insert_detail(self, table_name, session_id, content_col, content_val, ts):
        cursor = self.conn.cursor()
        query = f"INSERT INTO {table_name} (session_id, {content_col}, timestamp) VALUES (?, ?, ?)"
        cursor.execute(query, (session_id, content_val, ts))

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()