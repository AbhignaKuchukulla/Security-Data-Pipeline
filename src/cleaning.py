"""
Cleaning module for security event logs.

Responsibilities:
- Validate required columns
- Handle missing values
- Remove duplicates

Designed to be simple, readable, and interview-safe.
"""
from __future__ import annotations

from typing import Iterable, List
import pandas as pd
from pandas.api import types as ptypes

# Default required columns for the pipeline
REQUIRED_COLUMNS: List[str] = [
    "event_id",
    "timestamp",
    "user_id",
    "event_type",
    "status",
    "severity",
    "source_ip",
]


def validate_required_columns(df: pd.DataFrame, required_columns: Iterable[str] | None = None) -> pd.DataFrame:
    """
    Ensure the dataframe contains all required columns.

    Raises:
        ValueError: if any required column is missing.
    """
    required = list(required_columns) if required_columns is not None else REQUIRED_COLUMNS
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    return df


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove duplicate records.
    Strategy:
    - Drop fully duplicated rows first
    - Then drop duplicates by event_id, keeping the last occurrence
    """
    before = len(df)
    df = df.drop_duplicates(keep="last")
    df = df.drop_duplicates(subset=["event_id"], keep="last")
    after = len(df)
    # Note: keeping side-effects minimal; count can be logged upstream if needed
    return df


def handle_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    """
    Handle missing values with simple, explicit rules suitable for interviews:
    - If event_id is missing -> drop row (cannot de-duplicate or join reliably)
    - Fill missing user_id and event_type with 'unknown'
    - Fill missing status and severity with 'unknown'
    - Fill missing source_ip with '0.0.0.0' (explicit placeholder)

    Note: timestamp parsing and invalid timestamps are handled in normalization.
    """
    # Drop rows with missing event_id (critical identifier)
    df = df[~df["event_id"].isna()].copy()

    # Coerce text columns to string early to avoid pandas NA vs None pitfalls
    text_cols = [c for c in ["user_id", "event_type", "status", "severity", "source_ip"] if c in df.columns]
    for c in text_cols:
        df[c] = df[c].astype("string")

    # Fill with simple placeholders
    df["user_id"] = df["user_id"].fillna("unknown")
    df["event_type"] = df["event_type"].fillna("unknown")
    df["status"] = df["status"].fillna("unknown")
    df["severity"] = df["severity"].fillna("unknown")
    df["source_ip"] = df["source_ip"].fillna("0.0.0.0")

    # Strip whitespace from all object/string columns
    obj_cols = df.select_dtypes(include=["object", "string"]).columns
    for c in obj_cols:
        df[c] = df[c].str.strip()

    return df


def validate_schema(df: pd.DataFrame) -> dict:
    """
    Lightweight schema validation after normalization.
    Returns a dict of issues: {check_name: details} if any problems are found.

    Checks:
    - timestamp is datetime dtype (timezone aware or naive)
    - status in allowed set {success, failure, unknown}
    - severity in allowed set {info, low, medium, high, critical, unknown}
    """
    issues: dict = {}

    # Required columns check (rely on prior function for message consistency)
    try:
        validate_required_columns(df)
    except ValueError as e:
        issues["missing_columns"] = str(e)
        return issues

    # Timestamp dtype
    if not ptypes.is_datetime64_any_dtype(df["timestamp"]):
        issues["timestamp_dtype"] = str(df["timestamp"].dtype)
    else:
        nat_count = int(df["timestamp"].isna().sum())
        if nat_count > 0:
            issues["timestamp_NaT_count"] = nat_count

    # Allowed values
    allowed_status = {"success", "failure", "unknown"}
    allowed_severity = {"info", "low", "medium", "high", "critical", "unknown"}

    if "status" in df.columns:
        invalid_status = sorted(set(df["status"].dropna().astype("string")) - allowed_status)
        if invalid_status:
            issues["invalid_status_values"] = invalid_status

    if "severity" in df.columns:
        invalid_severity = sorted(set(df["severity"].dropna().astype("string")) - allowed_severity)
        if invalid_severity:
            issues["invalid_severity_values"] = invalid_severity

    return issues
