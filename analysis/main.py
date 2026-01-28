import datetime
from db_manager import DatabaseManager
from log_parser import LogParser
import pandas as pd
import os

STATE_FILE = '.last_import'

def get_last_import_time():
    try:
        with open(STATE_FILE, 'r') as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    except:
        return datetime.datetime.min

def set_last_import_time(timestamp):
    with open(STATE_FILE, 'w') as f:
        f.write(timestamp.isoformat())

def export_to_csv(db):
    output_dir = 'exports_csv'
    if not os.path.exists(output_dir): os.makedirs(output_dir)
    
    print(f"[*] Exporting csvs to '{output_dir}/'...")
    tables = ['Attacker', 'Session', 'LoginAttempt', 'PasswordAttempt', 'ShellCommand']
    for table in tables:
        df = pd.read_sql_query(f"SELECT * FROM {table}", db.conn)
        file_path = os.path.join(output_dir, f"{table.lower()}.csv")
        df.to_csv(file_path, index=False)
    print("[+] CSV export finished.")

def main():
    db = DatabaseManager()
    parser = LogParser()
    
    last_ts = get_last_import_time()
    new_events = parser.get_new_events(last_ts)

    if not new_events:
        print("[*] No new data to process.")
        return

    session_cache = {}
    latest_ts = last_ts

    print(f"[*] Processing {len(new_events)} events...")

    try:
        for ts, data in new_events:
            event_type = data['type']
            session_id = data.get('session_id')
            latest_ts = ts

            if event_type == 'CONNECTION':
                ip, cli_port = session_id.split(':')

                atk_id = db.get_or_create_attacker(
                    ip, data['country'], data['as_name'], data['as_domain']
                )

                s_id = db.insert_session(atk_id, int(data['honeypot_port']), int(cli_port), ts)
                session_cache[session_id] = s_id

            else:

                s_id = session_cache.get(session_id)
                if s_id:
                    if event_type == 'LOGIN':
                        db.insert_detail('LoginAttempt', s_id, 'username', data['user'], ts)
                    elif event_type == 'PASSWORD':
                        db.insert_detail('PasswordAttempt', s_id, 'password', data['password'], ts)
                    elif event_type == 'SHELL':
                        db.insert_detail('ShellCommand', s_id, 'command', data['command'], ts)

        db.commit()
        set_last_import_time(latest_ts)
        print("[+] Process finished successfully.")

        export_to_csv(db)

    except Exception as e:
        print(f"[!!] Erro crítico: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    main()