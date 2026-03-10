"""
Training script for TheThirdEye phishing detection model.

Usage:
    cd eai
    python train.py

Outputs:
    models/model.joblib         - Trained model
    models/scaler.joblib        - Fitted StandardScaler
    models/feature_columns.json - Ordered feature list
    models/training_medians.json - Per-feature medians for inference defaults
"""

import os
import json
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from preprocessing import load_and_preprocess, build_lookup_files

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")


def train():
    # Step 1: Build lookup files from safe/unsafe CSVs
    print("=" * 60)
    print("Step 1: Building lookup files from safe/unsafe datasets...")
    print("=" * 60)
    build_lookup_files()

    # Step 2: Load and preprocess PhiUSIIL dataset
    print("\n" + "=" * 60)
    print("Step 2: Loading and preprocessing PhiUSIIL dataset...")
    print("=" * 60)
    X_train, X_test, y_train, y_test, scaler, feature_cols = load_and_preprocess()

    # Step 3: Train Logistic Regression
    print("\n" + "=" * 60)
    print("Step 3: Training Logistic Regression model...")
    print("=" * 60)
    lr_model = LogisticRegression(
        max_iter=1000,
        C=1.0,
        class_weight="balanced",
        solver="lbfgs",
        n_jobs=-1,
        random_state=42,
    )
    lr_model.fit(X_train, y_train)
    lr_preds = lr_model.predict(X_test)
    lr_acc = accuracy_score(y_test, lr_preds)
    print(f"  Logistic Regression accuracy: {lr_acc:.4f}")
    print(classification_report(y_test, lr_preds, target_names=["phishing", "safe"]))

    # Step 4: Train Random Forest for comparison
    print("=" * 60)
    print("Step 4: Training Random Forest model (for comparison)...")
    print("=" * 60)
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"  Random Forest accuracy: {rf_acc:.4f}")
    print(classification_report(y_test, rf_preds, target_names=["phishing", "safe"]))

    # Step 5: Pick the better model and save
    print("=" * 60)
    if rf_acc >= lr_acc:
        best_model = rf_model
        best_name = "RandomForest"
    else:
        best_model = lr_model
        best_name = "LogisticRegression"

    print(f"Best model: {best_name} (accuracy: {max(lr_acc, rf_acc):.4f})")
    os.makedirs(MODELS_DIR, exist_ok=True)
    model_path = os.path.join(MODELS_DIR, "model.joblib")
    joblib.dump(best_model, model_path)
    print(f"Saved model to {model_path}")

    # Save model metadata
    meta = {
        "model_type": best_name,
        "accuracy": round(max(lr_acc, rf_acc), 4),
        "lr_accuracy": round(lr_acc, 4),
        "rf_accuracy": round(rf_acc, 4),
        "n_features": len(feature_cols),
        "n_train_samples": len(X_train),
        "n_test_samples": len(X_test),
    }
    with open(os.path.join(MODELS_DIR, "model_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved model metadata to {MODELS_DIR}/model_meta.json")
    print("\nTraining complete! Run 'python evaluate.py' for detailed metrics.")
    print("Run 'python serve.py' to start the prediction microservice.")


if __name__ == "__main__":
    train()
