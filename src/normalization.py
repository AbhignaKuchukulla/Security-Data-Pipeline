"""
Normalization module for security event logs.

Responsibilities:
- Parse and standardize timestamps
- Normalize categorical values (case, whitespace, synonyms)
- Ensure consistent simple formats
"""
from __future__ import annotations

import re
from typing import Dict
import pandas as pd


def standardize_timestamps(df: pd.DataFrame, column: str = "timestamp", drop_invalid: bool = True) -> pd.DataFrame:
    """
    Parse timestamps into pandas datetime in UTC.
    - Coerce errors to NaT
    - Optionally drop rows with invalid timestamps
    """
    if column not in df.columns:
        return df

    ts = pd.to_datetime(df[column], errors="coerce", utc=True)
    df[column] = ts

    if drop_invalid:
        df = df[~df[column].isna()].copy()

    return df


def _normalize_text(s: pd.Series) -> pd.Series:
    # Lowercase and trim
    s = s.astype("string").str.strip().str.lower()
    # Replace separators with underscore and collapse repeats
    s = s.str.replace(r"[\s\-]+", "_", regex=True)
    s = s.str.replace(r"_+", "_", regex=True)
    return s


def normalize_categoricals(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize key categorical fields:
    - event_type: lowercase, underscores
    - status: map common variants to {success, failure, unknown}
    - severity: map to {info, low, medium, high, critical, unknown}
    - user_id: trim/lower for consistency (kept as string)
    - source_ip: trim; keep as-is otherwise
    """
    if "event_type" in df.columns:
        df["event_type"] = _normalize_text(df["event_type"]).fillna("unknown")

    if "status" in df.columns:
        status = _normalize_text(df["status"]).fillna("unknown")
        status_map: Dict[str, str] = {
            "ok": "success",
            "pass": "success",
            "passed": "success",
            "success": "success",
            "succeeded": "success",
            "allowed": "success",
            "grant": "success",
            "failure": "failure",
            "failed": "failure",
            "error": "failure",
            "denied": "failure",
            "deny": "failure",
            "blocked": "failure",
            "unauthorized": "failure",
            "unknown": "unknown",
            "": "unknown",
        }
        df["status"] = status.map(status_map).fillna(status)

    if "severity" in df.columns:
        sev = _normalize_text(df["severity"]).fillna("unknown")
        # common synonyms mapping
        sev_map: Dict[str, str] = {
            "informational": "info",
            "information": "info",
            "info": "info",
            "notice": "low",
            "low": "low",
            "warn": "medium",
            "warning": "medium",
            "medium": "medium",
            "med": "medium",
            "high": "high",
            "severe": "high",
            "critical": "critical",
            "crit": "critical",
            "emergency": "critical",
            "unknown": "unknown",
            "": "unknown",
        }
        df["severity"] = sev.map(sev_map).fillna(sev)

    if "user_id" in df.columns:
        df["user_id"] = _normalize_text(df["user_id"]).replace("", "unknown")

    if "source_ip" in df.columns:
        # keep string, trimmed; do not validate to keep beginner-friendly
        s = df["source_ip"].astype("string").str.strip()
        df["source_ip"] = s.where(s != "", "0.0.0.0")

    return df
