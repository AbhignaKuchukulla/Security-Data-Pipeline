"""
Pipeline runner for the Security-Data-Pipeline.

Loads raw CSV, applies cleaning, normalization, and feature engineering,
and writes the processed CSV.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import pandas as pd

from cleaning import validate_required_columns, remove_duplicates, handle_missing_values, validate_schema
from normalization import standardize_timestamps, normalize_categoricals
from feature_engineering import run_all as engineer_features


def run_pipeline(input_path: Path, output_path: Path, session_gap_minutes: int = 30, summary: bool = False, validate_mode: str = "warn", drop_unknown_severity: bool = False) -> None:
    print(f"[Pipeline] Reading: {input_path}")
    df = pd.read_csv(input_path)

    print("[Pipeline] Validating required columns…")
    validate_required_columns(df)

    print("[Pipeline] Cleaning (missing values, duplicates)…")
    df = handle_missing_values(df)
    df = remove_duplicates(df)

    print("[Pipeline] Normalizing timestamps and categoricals…")
    df = standardize_timestamps(df, column="timestamp", drop_invalid=True)
    df = normalize_categoricals(df)

    if drop_unknown_severity:
        print("[Pipeline] Filtering rows with unknown severity…")
        df = df[df["severity"] != "unknown"].copy()

    print("[Pipeline] Feature engineering…")
    df = engineer_features(df, gap_minutes=session_gap_minutes)

    if validate_mode and validate_mode.lower() != "off":
        print("[Pipeline] Validating schema…")
        issues = validate_schema(df)
        if issues:
            if validate_mode.lower() == "strict":
                raise ValueError(f"Schema validation failed: {issues}")
            else:
                print(f"[Pipeline] Validation warnings: {issues}")

    print(f"[Pipeline] Writing processed output: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    if summary:
        print("[Pipeline] Summary:\n" \
              f"  rows: {len(df)}\n" \
              f"  columns: {len(df.columns)}\n" \
              f"  time range: {df['timestamp'].min()} -> {df['timestamp'].max()}\n" \
              f"  users: {df['user_id'].nunique()} | event_types: {df['event_type'].nunique()}\n")
        # Null checks (top 8 for brevity)
        nulls = df.isna().sum().sort_values(ascending=False)
        if (nulls > 0).any():
            print("[Null counts]\n" + nulls.head(8).to_string())
        # Top counts for categorical signals
        print("\n[Top event_types]\n" + df['event_type'].value_counts().head(5).to_string())
        print("\n[Top status]\n" + df['status'].value_counts().head(5).to_string())
        if 'severity' in df.columns:
            print("\n[Top severity]\n" + df['severity'].value_counts().head(5).to_string())

    print("[Pipeline] Done.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Security Data Pipeline")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/raw_events.csv"),
        help="Path to input raw events CSV",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed_events.csv"),
        help="Path to output processed events CSV",
    )
    parser.add_argument(
        "--session-gap-minutes",
        type=int,
        default=30,
        help="Inactivity gap in minutes to split sessions",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a brief post-run summary to stdout",
    )
    parser.add_argument(
        "--drop-unknown-severity",
        action="store_true",
        help="Drop records where normalized severity is 'unknown'",
    )
    parser.add_argument(
        "--validate",
        choices=["off", "warn", "strict"],
        default="warn",
        help="Schema validation mode: off (skip), warn (default), or strict (fail on issues)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_pipeline(
        args.input,
        args.output,
        session_gap_minutes=args.session_gap_minutes,
        summary=args.summary,
        validate_mode=args.validate,
        drop_unknown_severity=args.drop_unknown_severity,
    )
