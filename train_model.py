"""
Step 2: Train a Random Forest classifier on the Elliptic dataset.

What this does:
  - Loads the Elliptic Bitcoin dataset (labeled illicit/licit transactions)
  - Trains a Random Forest model to predict "illicit probability"
  - Saves the trained model to disk so other scripts can load it instantly

Run this ONCE. It takes ~30 seconds and creates 'wallet_risk_model.joblib'.
After that, you never need to re-run it unless you change training settings.

Usage:
    python train_model.py
"""

import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib


def load_elliptic_data(data_dir="elliptic_bitcoin_dataset"):
    """
    Load the three Elliptic CSV files and merge them into one table.

    Returns a DataFrame with features + a 'label' column (1=illicit, 0=licit).
    Rows labeled 'unknown' in the original data are dropped (can't train on them).
    """
    # --- Load features ---
    # 166 columns: first column is transaction ID, next 165 are numeric features
    features_path = os.path.join(data_dir, "elliptic_txs_features.csv")
    print(f"Loading features from {features_path} ...")
    features_df = pd.read_csv(features_path, header=None)

    # Name the columns: 'txId' + 'feature_0' through 'feature_165'
    feature_cols = [f"feature_{i}" for i in range(features_df.shape[1] - 1)]
    features_df.columns = ["txId"] + feature_cols
    print(f"  -> {len(features_df)} transactions, {len(feature_cols)} features each")

    # --- Load class labels ---
    classes_path = os.path.join(data_dir, "elliptic_txs_classes.csv")
    print(f"Loading labels from {classes_path} ...")
    classes_df = pd.read_csv(classes_path)
    # Original labels: "1" = illicit, "2" = licit, "unknown" = unlabeled
    # We convert to: 1 = illicit, 0 = licit, drop unknowns
    classes_df.columns = ["txId", "class"]

    # Drop 'unknown' rows — we can't use them for supervised learning
    labeled = classes_df[classes_df["class"] != "unknown"].copy()
    # Convert "1" -> 1 (illicit), "2" -> 0 (licit)
    labeled["label"] = labeled["class"].apply(lambda x: 1 if str(x) == "1" else 0)
    print(f"  -> {len(labeled)} labeled transactions "
          f"({labeled['label'].sum()} illicit, "
          f"{(labeled['label'] == 0).sum()} licit)")

    # --- Merge features with labels ---
    merged = features_df.merge(labeled[["txId", "label"]], on="txId", how="inner")
    print(f"  -> {len(merged)} transactions after merge")

    return merged, feature_cols


def train_and_save_model(data_dir="elliptic_bitcoin_dataset",
                         model_path="wallet_risk_model.joblib"):
    """
    Train a Random Forest and save it to disk.

    Why Random Forest?
      - Works well out of the box (no fiddly hyperparameter tuning)
      - Handles the 166 features without normalization
      - Gives probability scores (not just yes/no)
      - Fast to train (~30 seconds on a laptop)
      - Free via scikit-learn (no paid library needed)
    """
    # Load data
    data, feature_cols = load_elliptic_data(data_dir)

    # Split: 80% for training, 20% for testing
    # stratify=y keeps the same illicit/licit ratio in both splits
    X = data[feature_cols]
    y = data["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTraining set: {len(X_train)} transactions")
    print(f"Test set:     {len(X_test)} transactions")

    # Train the Random Forest
    # n_estimators=100 = use 100 decision trees (more = better but slower)
    # class_weight='balanced' = treat illicit and licit as equally important
    #   (without this, the model would ignore rare illicit transactions)
    # n_jobs=-1 = use all CPU cores for speed
    # random_state=42 = reproducible results
    print("\nTraining Random Forest (this takes ~30 seconds) ...")
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train)

    # Evaluate — print how well it does on unseen test data
    print("\n--- Model Performance on Test Data ---")
    y_pred = model.predict(X_test)
    print(classification_report(
        y_test, y_pred, target_names=["licit", "illicit"]
    ))

    # Save the trained model to disk
    joblib.dump(model, model_path)
    print(f"\nModel saved to '{model_path}' ({os.path.getsize(model_path) / 1e6:.1f} MB)")
    print("You can now use this model in other scripts without re-training.")

    return model


if __name__ == "__main__":
    train_and_save_model()
