> Technical module to process raw honeypot logs into a structured SQLite database and export relational CSVs for analysis.

## Core Modules
- **log_parser.py**: Extracts data from ```../logs/*.log``` using Regex.

- **database_manager.py**: Manages SQLite schema and data persistence.

- **main.py**: Orchestrates the ETL flow and tracks state via ```.last_import```.

## How to Use
1. Install dependencies: ```pip install -r requirements.txt```

2. Process logs: ```python3 main.py```

3. Outputs:  
    - Database: ```honeypot.db```
    - CSV Exports: ```exportes_csv/```
