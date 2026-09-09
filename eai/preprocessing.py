"""
Preprocessing pipeline for CyberShield ML model.
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


def _generate_synthetic_dataset():
    """Generate a realistic synthetic dataset if PhiUSIIL CSV is not locally available."""
    np.random.seed(42)
    n_samples = 4000
    n_half = n_samples // 2
    
    data = {}
    # Target label: 1 = safe, 0 = phishing
    y = np.array([1] * n_half + [0] * n_half)

    for col in FEATURE_COLUMNS:
        if col == "IsHTTPS":
            data[col] = np.concatenate([np.random.binomial(1, 0.95, n_half), np.random.binomial(1, 0.35, n_half)])
        elif col == "URLLength":
            data[col] = np.concatenate([np.random.normal(45, 10, n_half), np.random.normal(95, 25, n_half)]).clip(10, 300)
        elif col == "DomainLength":
            data[col] = np.concatenate([np.random.normal(12, 4, n_half), np.random.normal(28, 8, n_half)]).clip(3, 100)
        elif col == "IsDomainIP":
            data[col] = np.concatenate([np.random.binomial(1, 0.00, n_half), np.random.binomial(1, 0.15, n_half)])
        elif col == "NoOfSubDomain":
            data[col] = np.concatenate([np.random.poisson(1.0, n_half), np.random.poisson(3.2, n_half)])
        elif col == "HasObfuscation":
            data[col] = np.concatenate([np.random.binomial(1, 0.02, n_half), np.random.binomial(1, 0.45, n_half)])
        elif col == "ObfuscationRatio":
            data[col] = np.concatenate([np.random.exponential(0.01, n_half), np.random.exponential(0.15, n_half)]).clip(0, 1)
        elif col == "TLDLegitimateProb":
            data[col] = np.concatenate([np.random.normal(0.70, 0.1, n_half), np.random.normal(0.20, 0.1, n_half)]).clip(0, 1)
        elif col == "HasPasswordField":
            data[col] = np.concatenate([np.random.binomial(1, 0.10, n_half), np.random.binomial(1, 0.70, n_half)])
        elif col == "NoOfiFrame":
            data[col] = np.concatenate([np.zeros(n_half), np.random.poisson(1.8, n_half)])
        elif col == "NoOfJS":
            data[col] = np.concatenate([np.random.normal(5, 2, n_half), np.random.normal(14, 5, n_half)]).clip(0, 50)
        elif col == "HasSubmitButton":
            data[col] = np.concatenate([np.random.binomial(1, 0.80, n_half), np.random.binomial(1, 0.95, n_half)])
        elif col == "NoOfURLRedirect":
            data[col] = np.concatenate([np.random.poisson(0.2, n_half), np.random.poisson(2.5, n_half)])
        elif col in ["Bank", "Pay", "Crypto"]:
            data[col] = np.concatenate([np.random.binomial(1, 0.05, n_half), np.random.binomial(1, 0.45, n_half)])
        else:
            data[col] = np.concatenate([np.random.normal(5, 2, n_half), np.random.normal(10, 4, n_half)]).clip(0, 100)

    df = pd.DataFrame(data)
    df[TARGET_COLUMN] = y
    return df


def load_and_preprocess():
    """Load PhiUSIIL dataset (or synthetic fallback), clean, scale, and return train/test splits."""
    if os.path.exists(PHISHING_CSV):
        print(f"Loading dataset from {PHISHING_CSV} ...")
        df = pd.read_csv(PHISHING_CSV, low_memory=False)
        print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")
    else:
        print(f"Dataset not found at {PHISHING_CSV}. Generating benchmark synthetic training dataset...")
        df = _generate_synthetic_dataset()
        print(f"  Generated {len(df):,} synthetic samples with {len(FEATURE_COLUMNS)} features.")

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
    url = re.sub(r"^https?://", "", url)
    url = url.split("/")[0].split(":")[0]
    url = re.sub(r"^www\.", "", url)
    return url.lower()


def build_lookup_files():
    """Convert safe_sites.csv and unsafe_sites.csv to lookup JSON files."""
    os.makedirs(LOOKUPS_DIR, exist_ok=True)

    if os.path.exists(SAFE_CSV):
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
    else:
        print(f"  {SAFE_CSV} not found, using existing or default lookups.")

    if os.path.exists(UNSAFE_CSV):
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
    else:
        print(f"  {UNSAFE_CSV} not found, using existing or default lookups.")


if __name__ == "__main__":
    build_lookup_files()
    load_and_preprocess()
