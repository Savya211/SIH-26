"""
Preprocessing pipeline for TheThirdEye ML model.
- Loads PhiUSIIL_Phishing_URL_Dataset.csv (235K rows, 52 cols)
- Drops text columns, handles missing values
- Splits 80/20 stratified, fits StandardScaler
- Saves scaler, feature columns, and training medians as model artifacts
- Also converts safe_sites.csv and unsafe_sites.csv to lookup JSON files
"""

import os
import json
import re
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

from feature_config import FEATURE_COLUMNS, TEXT_COLUMNS, TARGET_COLUMN

# Paths relative to eai/
DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "dataset")
MODELS_DIR  = os.path.join(os.path.dirname(__file__), "models")
LOOKUPS_DIR = os.path.join(os.path.dirname(__file__), "lookups")

PHISHING_CSV  = os.path.join(DATASET_DIR, "PhiUSIIL_Phishing_URL_Dataset.csv")
SAFE_CSV      = os.path.join(DATASET_DIR, "safe_sites.csv")
UNSAFE_CSV    = os.path.join(DATASET_DIR, "unsafe_sites.csv")


def load_and_preprocess():
    """Load PhiUSIIL dataset, clean, scale, and return train/test splits."""
    print(f"Loading dataset from {PHISHING_CSV} ...")
    df = pd.read_csv(PHISHING_CSV, low_memory=False)
    print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")

    # Keep only numerical feature columns + target
    available_features = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        print(f"  Warning: columns not found in dataset: {missing}")

    df = df[available_features + [TARGET_COLUMN]].copy()

    # Fill missing values with 0
    df.fillna(0, inplace=True)

    # Cast to float
    for col in available_features:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    X = df[available_features].values.astype(np.float32)
    y = df[TARGET_COLUMN].values.astype(int)

    print(f"  Class distribution — safe: {(y==1).sum():,}  phishing: {(y==0).sum():,}")

    # 80/20 stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Fit scaler on training data only
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # Compute per-feature medians (raw, before scaling) for inference-time defaults
    medians = dict(zip(available_features, np.median(X_train, axis=0).tolist()))

    # Save artifacts
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.joblib"))
    with open(os.path.join(MODELS_DIR, "feature_columns.json"), "w") as f:
        json.dump(available_features, f, indent=2)
    with open(os.path.join(MODELS_DIR, "training_medians.json"), "w") as f:
        json.dump(medians, f, indent=2)

    print(f"  Saved scaler, feature_columns.json, training_medians.json to {MODELS_DIR}")
    print(f"  Train: {len(X_train):,} rows  |  Test: {len(X_test):,} rows")

    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, available_features


def _extract_domain(url: str) -> str:
    """Extract bare domain from a URL string."""
    url = url.strip()
    # Remove protocol
    url = re.sub(r"^https?://", "", url)
    # Remove path
    url = url.split("/")[0]
    # Remove port
    url = url.split(":")[0]
    # Remove www.
    url = re.sub(r"^www\.", "", url)
    return url.lower()


def build_lookup_files():
    """Convert safe_sites.csv and unsafe_sites.csv to lookup JSON files."""
    os.makedirs(LOOKUPS_DIR, exist_ok=True)

    # safe_sites.csv: Site Name, URL, Category, Description
    print(f"Processing {SAFE_CSV} ...")
    safe_df = pd.read_csv(SAFE_CSV)
    safe_domains = {}
    for _, row in safe_df.iterrows():
        url = str(row.get("URL", "")).strip()
        if url and url != "nan":
            domain = _extract_domain(url)
            if domain:
                safe_domains[domain] = {
                    "name": str(row.get("Site Name", "")),
                    "category": str(row.get("Category", "")),
                }
    safe_path = os.path.join(LOOKUPS_DIR, "safe_domains.json")
    with open(safe_path, "w") as f:
        json.dump(safe_domains, f, indent=2)
    print(f"  Wrote {len(safe_domains)} safe domains to {safe_path}")

    # unsafe_sites.csv: Site Name, Category, Reason, Risk Level, Source
    print(f"Processing {UNSAFE_CSV} ...")
    unsafe_df = pd.read_csv(UNSAFE_CSV)
    unsafe_names = {}
    for _, row in unsafe_df.iterrows():
        name = str(row.get("Site Name", "")).strip().lower()
        if name and name != "nan":
            unsafe_names[name] = {
                "category": str(row.get("Category", "")),
                "reason": str(row.get("Reason", "")),
                "risk_level": str(row.get("Risk Level", "High")),
            }
    unsafe_path = os.path.join(LOOKUPS_DIR, "unsafe_names.json")
    with open(unsafe_path, "w") as f:
        json.dump(unsafe_names, f, indent=2)
    print(f"  Wrote {len(unsafe_names)} unsafe entries to {unsafe_path}")


if __name__ == "__main__":
    build_lookup_files()
    load_and_preprocess()
