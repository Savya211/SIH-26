"""
Model evaluation script for TheThirdEye phishing detection model.

Usage:
    cd eai
    python evaluate.py

Requires: models/ artifacts from train.py
"""

import os
import json
import joblib
import numpy as np
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix,
    roc_auc_score,
)

from preprocessing import load_and_preprocess

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")


def evaluate():
    # Load saved artifacts
    model_path = os.path.join(MODELS_DIR, "model.joblib")
    meta_path  = os.path.join(MODELS_DIR, "model_meta.json")

    if not os.path.exists(model_path):
        print("No trained model found. Run 'python train.py' first.")
        return

    model = joblib.load(model_path)
    with open(meta_path) as f:
        meta = json.load(f)

    print("=" * 60)
    print(f"Model: {meta['model_type']}")
    print(f"Features: {meta['n_features']}")
    print(f"Train samples: {meta['n_train_samples']:,}")
    print(f"Test samples:  {meta['n_test_samples']:,}")
    print("=" * 60)

    # Re-run preprocessing to get fresh test split (same random_state=42)
    print("Loading test data...")
    _, X_test, _, y_test, _, feature_cols = load_and_preprocess()

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc     = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm      = confusion_matrix(y_test, y_pred)

    print(f"\nAccuracy:  {acc:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print("\nConfusion Matrix:")
    print("              Predicted")
    print("              Phishing  Safe")
    print(f"Actual Phishing  {cm[0][0]:>6}  {cm[0][1]:>6}")
    print(f"Actual Safe      {cm[1][0]:>6}  {cm[1][1]:>6}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["phishing", "safe"]))

    # Feature importance (for tree-based models)
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1][:15]
        print("Top 15 Feature Importances:")
        for rank, idx in enumerate(indices, 1):
            print(f"  {rank:>2}. {feature_cols[idx]:<35} {importances[idx]:.4f}")
    elif hasattr(model, "coef_"):
        coefs = np.abs(model.coef_[0])
        indices = np.argsort(coefs)[::-1][:15]
        print("Top 15 Feature Coefficients (absolute value):")
        for rank, idx in enumerate(indices, 1):
            print(f"  {rank:>2}. {feature_cols[idx]:<35} {coefs[idx]:.4f}")


if __name__ == "__main__":
    evaluate()
