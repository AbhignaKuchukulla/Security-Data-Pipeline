# Security-Data-Pipeline

Reusable, modular Python pipeline that cleans, normalizes, and engineers features from raw security event logs to produce ML‑ready datasets for SIEM analytics and downstream machine learning workflows.

## Quick Start
Install dependencies and run the pipeline:
```bash
pip install -r requirements.txt
python src/pipeline.py --input data/raw_events.csv --output data/processed_events.csv
```

## Overview
Preprocessing pipeline using Python and CSVs. Cleans and normalizes raw security logs, then engineers simple analytics features and writes a single processed CSV.

## Data Challenges Handled
- Missing values
- Duplicate events
- Inconsistent timestamps (UTC)
- Noisy categorical values

## Project Structure
```
Security-Data-Pipeline/
├── data/
│   ├── raw_events.csv
│   └── processed_events.csv
├── src/
│   ├── cleaning.py
│   ├── normalization.py
│   ├── feature_engineering.py
│   └── pipeline.py
├── README.md
└── requirements.txt
```

## Processing Stages
1) Cleaning: validate columns, fill placeholders, remove duplicates.
2) Normalization: timestamps → UTC, normalize categorical values.
3) Features: `severity_score`, per‑user counts/baselines, simple sessions.
4) Orchestration: read raw CSV, apply modules, write processed CSV.

## Outputs
- Processed dataset: [data/processed_events.csv](data/processed_events.csv)
- Includes engineered columns: `severity_score`, `user_event_count_total`, `user_daily_avg_events`, `session_id`, `session_event_count`, `session_duration_seconds`

## Usage
Basic:
```bash
python src/pipeline.py --input data/raw_events.csv --output data/processed_events.csv
```
Options:
- `--session-gap-minutes <int>` (default 30)
- `--summary`
- `--validate {off|warn|strict}` (default `warn`)
- `--drop-unknown-severity`

Preview the output:
```bash
python -c "import pandas as pd; df=pd.read_csv('data/processed_events.csv'); print(df.head(10).to_string(index=False))"
```
## Notes
- Dependencies pinned in [requirements.txt](requirements.txt).
- Behavior controlled via CLI flags only.

