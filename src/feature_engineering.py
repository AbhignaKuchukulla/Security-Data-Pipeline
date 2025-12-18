"""
Feature engineering for security event logs.

Adds:
- user_event_count_total: count of all events per user (global)
- user_daily_avg_events: average events per day per user (baseline)
- severity_score: numeric encoding of severity
- Simple session features (30-minute inactivity gap):
  - session_id
  - session_event_count
  - session_duration_seconds
"""
from __future__ import annotations

import pandas as pd
import numpy as np


def add_severity_score(df: pd.DataFrame) -> pd.DataFrame:
    """
    Map severity strings to an ordinal score for analytics.
    Unknown severities are set to NaN (explicitly unknown).
    """
    sev_to_score = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    df["severity_score"] = df["severity"].map(sev_to_score).astype("Float64")
    return df


def add_user_event_frequency(df: pd.DataFrame) -> pd.DataFrame:
    if "user_id" not in df.columns:
        return df
    df["user_event_count_total"] = df.groupby("user_id")["event_id"].transform("count")
    return df


def add_user_activity_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute average events per day per user.
    Requires a valid datetime in df['timestamp'].
    """
    # Support both naive and timezone-aware pandas datetime dtypes
    if "timestamp" not in df.columns or not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        return df

    tmp = df[["user_id", "timestamp"]].copy()
    tmp["date"] = tmp["timestamp"].dt.floor("D")
    daily_counts = tmp.groupby(["user_id", "date"], as_index=False).size()
    avg_per_user = daily_counts.groupby("user_id", as_index=False)["size"].mean().rename(columns={"size": "user_daily_avg_events"})

    df = df.merge(avg_per_user, on="user_id", how="left")
    df["user_daily_avg_events"] = df["user_daily_avg_events"].astype("Float64")
    return df


def add_session_features(df: pd.DataFrame, gap_minutes: int = 30) -> pd.DataFrame:
    """
    Create lightweight session features based on inactivity gaps per user.
    - A new session starts if time since previous event for that user > gap_minutes
    - session_id: integer per user indicating the session number
    - session_event_count: events in that session (per row)
    - session_duration_seconds: duration of that session (per row)
    """
    if "timestamp" not in df.columns:
        return df

    df = df.sort_values(["user_id", "timestamp"]).copy()
    gap_seconds = gap_minutes * 60
    # Compute time delta within each user
    df["_time_diff_sec"] = (
        df.groupby("user_id")["timestamp"].diff().dt.total_seconds().fillna(np.inf)
    )
    # New session where gap exceeded
    new_session = df["_time_diff_sec"] > gap_seconds
    # Cumulative session id per user (vectorized, avoids groupby.apply warning)
    df["session_id"] = new_session.groupby(df["user_id"]).cumsum().astype(int)
    df = df.drop(columns=["_time_diff_sec"])

    # Aggregate per-session stats and join back
    sess_stats = (
        df.groupby(["user_id", "session_id"]).agg(
            session_event_count=("event_id", "count"),
            session_start=("timestamp", "min"),
            session_end=("timestamp", "max"),
        ).reset_index()
    )
    sess_stats["session_duration_seconds"] = (sess_stats["session_end"] - sess_stats["session_start"]).dt.total_seconds().astype("Float64")
    df = df.merge(sess_stats.drop(columns=["session_start", "session_end"]), on=["user_id", "session_id"], how="left")

    return df


def run_all(df: pd.DataFrame, gap_minutes: int = 30) -> pd.DataFrame:
    df = add_severity_score(df)
    df = add_user_event_frequency(df)
    df = add_user_activity_baseline(df)
    df = add_session_features(df, gap_minutes=gap_minutes)
    return df
