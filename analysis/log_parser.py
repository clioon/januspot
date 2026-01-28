import re
import os
import glob
import datetime

class LogParser:
    def __init__(self, log_dir='../logs'):
        self.log_dir = log_dir
        self.log_pattern = os.path.join(self.log_dir, 'honeypot_port_*.log')
        
        self.RE_TIMESTAMP = re.compile(r'\[([\d\- :]+)\]')
        
        self.RE_CONNECTION = re.compile(
            r'\[NEW CONNECTION\]: Port: (?P<honeypot_port>\d+) '
            r'IP: (?P<session_id>[\d\.:]+) \| '
            r'Name: (?P<as_name>[^|]+) \| '
            r'Domain: (?P<as_domain>[^|]+) \| '
            r'Country: (?P<country>[^|]+)'
        )
        
        self.RE_LOGIN = re.compile(r'\[LOGIN ATTEMPT\] From (?P<session_id>[\d\.:]+) \| User: (?P<user>.+)')
        self.RE_PASSWORD = re.compile(r'\[PASSWORD ATTEMPT\] From (?P<session_id>[\d\.:]+) \| Password: (?P<password>.+)')
        self.RE_SHELL = re.compile(
            r'\[SHELL COMMAND\] From (?P<session_id>[\d\.:]+) \| Command: (?P<command>.+)',
            re.DOTALL
        )

    def get_new_events(self, last_import_time):
        all_events = []
        log_files = glob.glob(self.log_pattern)
        
        if not log_files:
            print("[!] No log files found.")
            return []

        for log_file in log_files:
            with open(log_file, 'r', encoding='utf-8') as f:
                current_event_lines = []
                current_timestamp = None

                for line in f:
                    timestamp_match = self.RE_TIMESTAMP.search(line)
                    
                    if timestamp_match:
                        if current_timestamp and current_timestamp > last_import_time:
                            event_data = self._identify_event("".join(current_event_lines))
                            if event_data:
                                all_events.append((current_timestamp, event_data))
                        
                        current_timestamp = datetime.datetime.strptime(timestamp_match.group(1), "%Y-%m-%d %H:%M:%S")
                        current_event_lines = [line]
                    else:
                        if current_timestamp:
                            current_event_lines.append(line)

                if current_timestamp and current_timestamp > last_import_time:
                    event_data = self._identify_event("".join(current_event_lines))
                    if event_data:
                        all_events.append((current_timestamp, event_data))

        all_events.sort(key=lambda x: x[0])
        return all_events

    def _identify_event(self, event_string):
        if "[NEW CONNECTION]" in event_string:
            match = self.RE_CONNECTION.search(event_string)
            if match:
                data = match.groupdict()
                data['type'] = 'CONNECTION'
                return data
        
        elif "[LOGIN ATTEMPT]" in event_string:
            match = self.RE_LOGIN.search(event_string)
            if match:
                data = match.groupdict()
                data['type'] = 'LOGIN'
                return data

        elif "[PASSWORD ATTEMPT]" in event_string:
            match = self.RE_PASSWORD.search(event_string)
            if match:
                data = match.groupdict()
                data['type'] = 'PASSWORD'
                return data

        elif "[SHELL COMMAND]" in event_string:
            match = self.RE_SHELL.search(event_string)
            if match:
                data = match.groupdict()
                data['type'] = 'SHELL'
                return data
        
        return None