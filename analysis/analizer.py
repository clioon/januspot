import sqlite3
import pandas as pd

DB_PATH = 'honeypot.db'

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        return conn
    except Exception as e:
        # Standardized to English
        print(f"[!!] DB connection error: {e}")
        return None

def print_report(conn):
    """Generates and prints a full report from the honeypot database."""
    print("\n\n" + "="*60)
    print(" H O N E Y P O T - S T A T I S T I C S - R E P O R T")
    print("="*60)

    try:
        # ======= Overall Stats (English) ========
        print("\n====== Overall Stats ======")
        session_count = pd.read_sql_query("SELECT COUNT(*) FROM Session", conn).iloc[0,0]
        attacker_count = pd.read_sql_query("SELECT COUNT(*) FROM Attacker", conn).iloc[0,0]
        login_count = pd.read_sql_query("SELECT COUNT(*) FROM LoginAttempt", conn).iloc[0,0]
        password_count = pd.read_sql_query("SELECT COUNT(*) FROM PasswordAttempt", conn).iloc[0,0]
        command_count = pd.read_sql_query("SELECT COUNT(*) FROM ShellCommand", conn).iloc[0,0]
        
        print(f"Total Sessions:           {session_count}")
        print(f"Total Unique Attacker IPs: {attacker_count}")
        print(f"Total Login Attempts:     {login_count}")
        print(f"Total Password Attempts:  {password_count}")
        print(f"Total Shell Commands:     {command_count}") # <-- Translated

        # ======== Stats per Port (Summary Table) ========
        print("\n====== Stats per Port (Summary) ======")
        query_ports = """
        SELECT
            S.honeypot_port,
            COUNT(DISTINCT S.id) AS total_sessions,
            COUNT(DISTINCT A.ip_address) AS total_attacker_ips,
            COUNT(DISTINCT L.id) AS total_login_attempts,
            COUNT(DISTINCT P.id) AS total_password_attempts,
            COUNT(DISTINCT C.id) AS total_shell_commands
        FROM
            Session AS S
        LEFT JOIN
            Attacker AS A ON S.attacker_id = A.id
        LEFT JOIN
            LoginAttempt AS L ON S.id = L.session_id
        LEFT JOIN
            PasswordAttempt AS P ON S.id = P.session_id
        LEFT JOIN
            ShellCommand AS C ON S.id = C.session_id
        GROUP BY
            S.honeypot_port
        ORDER BY
            total_sessions DESC;
        """
        df_ports = pd.read_sql_query(query_ports, conn, index_col='honeypot_port')
        print(df_ports.to_string())

        # ======== Global Top 10s (Countries & IPs) ========
        print("\n====== Global Top 10 Stats ======")
        
        # --- Top 10 Countries (English) ---
        print(f"\n--- Top 10 Countries (by unique IP) ---") # <-- Translated
        query_countries = """
            SELECT 
                country, 
                COUNT(*) as count
            FROM Attacker
            WHERE country IS NOT NULL AND country != ''
            GROUP BY country
            ORDER BY count DESC
            LIMIT 10
        """
        df_countries = pd.read_sql_query(query_countries, conn, index_col='country')
        print(df_countries.to_string())
        
        # --- Top 10 IPs (English) ---
        print(f"\n--- Top 10 Attacker IPs (by connection count) ---") # <-- Translated
        query_ips = """
            SELECT 
                a.ip_address, 
                a.as_name,
                a.country,
                COUNT(s.id) as connection_count
            FROM Attacker a
            JOIN Session s ON a.id = s.attacker_id
            GROUP BY a.id
            ORDER BY connection_count DESC
            LIMIT 10
        """
        df_ips = pd.read_sql_query(query_ips, conn, index_col='ip_address')
        print(df_ips.to_string())

        
        # ======== Top 10 Details per Port (NEW SECTION) ========
        print("\n\n" + "="*60)
        print(" T O P - 1 0 - D E T A I L S - P E R - P O R T")
        print("="*60)

        # Get the list of ports from the summary table we already created
        active_ports = df_ports.index

        # Define the parameterized queries
        query_users_port = """
            SELECT 
                L.username, 
                COUNT(*) as count
            FROM LoginAttempt AS L
            JOIN Session AS S ON L.session_id = S.id
            WHERE 
                S.honeypot_port = ? 
                AND L.username IS NOT NULL AND L.username != ''
            GROUP BY L.username
            ORDER BY count DESC
            LIMIT 10
        """

        query_pass_port = """
            SELECT 
                P.password, 
                COUNT(*) as count
            FROM PasswordAttempt AS P
            JOIN Session AS S ON P.session_id = S.id
            WHERE 
                S.honeypot_port = ? 
                AND P.password IS NOT NULL AND P.password != ''
            GROUP BY P.password
            ORDER BY count DESC
            LIMIT 10
        """
        
        query_cmd_port = """
            SELECT 
                C.command, 
                COUNT(*) as count
            FROM ShellCommand AS C
            JOIN Session AS S ON C.session_id = S.id
            WHERE 
                S.honeypot_port = ? 
                AND C.command IS NOT NULL AND C.command != ''
            GROUP BY C.command
            ORDER BY count DESC
            LIMIT 10
        """

        # Loop through each port and print its specific Top 10s
        for port in active_ports:
            print(f"\n\n--- Top 10 Details for Port: {port} ---")

            # --- Top 10 Usernames for this port ---
            print(f"--- Top 10 Usernames (Port {port}) ---")
            # Use 'params' to safely insert the port number into the query
            df_users = pd.read_sql_query(query_users_port, conn, 
                                         index_col='username', params=(port,))
            if df_users.empty:
                print("No username attempts recorded for this port.")
            else:
                print(df_users.to_string())

            # --- Top 10 Passwords for this port ---
            print(f"\n--- Top 10 Passwords (Port {port}) ---")
            df_pass = pd.read_sql_query(query_pass_port, conn, 
                                        index_col='password', params=(port,))
            if df_pass.empty:
                print("No password attempts recorded for this port.")
            else:
                print(df_pass.to_string())

            # --- Top 10 Commands for this port ---
            print(f"\n--- Top 10 Shell Commands (Port {port}) ---")
            df_cmd = pd.read_sql_query(query_cmd_port, conn, params=(port,))
            
            if df_cmd.empty:
                print("No shell commands recorded for this port.")
            else:
                # Truncate long commands to avoid breaking the layout
                df_cmd['command'] = df_cmd['command'].apply(lambda x: (x[:70] + '...') if len(x) > 70 else x)
                df_cmd = df_cmd.set_index('command')
                print(df_cmd.to_string())

        
        print("\n\n" + "="*60)
        print(" E N D - O F - R E P O R T") # <-- Translated
        print("="*60)

    except Exception as e:
        # Standardized to English
        print(f"[!!] Error generating report: {e}")


def main():
    conn = get_db_connection()
    if conn:
        try:
            print_report(conn)
        finally:
            conn.close()
            # print("[*] DB connection closed.") # <-- Optional

if __name__ == "__main__":
    main()