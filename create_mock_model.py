"""
Create a mock ML model for demo purposes.

This simulates a trained Random Forest without needing the Elliptic dataset.
The mock model gives realistic predictions based on graph features.
"""

import os
import shutil
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier


def create_mock_model(model_path="wallet_risk_model.joblib"):
    """
    Create a calibrated Random Forest model trained on synthetic graph features
    representative of real-world blockchain illicit vs licit transaction typologies.

    Typologies Modeled:
      1. Money Laundering / Tumblers: High fan-out, symmetric flow, fast passthrough
      2. Ransomware Peeling Chains: Long hop chains, small single-input transfers
      3. Scam Aggregators: High in-degree, near-zero retention
      4. Exchanges & OTC Desks: High in-degree, high volume, licit
      5. Normal Personal Wallets: Low in-degree, low out-degree, licit
    """
    print("Creating calibrated graph-ML risk model...")

    # Backup existing model if present
    if os.path.exists(model_path):
        backup_path = model_path.replace(".joblib", "_backup.joblib")
        shutil.copy2(model_path, backup_path)
        print(f"  Backed up existing model to '{backup_path}'")

    np.random.seed(42)
    n_samples_per_class = 3000

    # 20 features aligned with analyze.py extract_graph_features()
    X_illicit = np.zeros((n_samples_per_class, 20))
    X_licit = np.zeros((n_samples_per_class, 20))

    # --- Illicit Samples ---
    # Feature layout (aligned with analyze.py extract_graph_features):
    #   [0] effective_in  [1] out_degree   [2] funded_btc    [3] spent_btc
    #   [4] balance_btc   [5] liq_ratio    [6] fan_ratio     [7] btc_ratio
    #   [8] avg_in_size   [9] net_flow     [10] is_passthrough [11] is_scam
    #   [12] is_mixer     [13] is_exchange  [14] taint_score  [15] clustering
    #   [16] density      [17] n_nodes     [18] n_edges      [19] tx_count

    # Typology A: Mixing / Peeling chains (1500 samples)
    n_mix = n_samples_per_class // 2
    X_illicit[:n_mix, 0] = np.random.randint(5, 30, n_mix)                          # effective_in
    X_illicit[:n_mix, 1] = np.random.randint(5, 30, n_mix)                          # out_degree (symmetric)
    X_illicit[:n_mix, 2] = np.random.uniform(0.5, 20.0, n_mix)                      # funded_btc
    X_illicit[:n_mix, 3] = X_illicit[:n_mix, 2] * np.random.uniform(0.95, 1.0, n_mix)  # spent_btc
    X_illicit[:n_mix, 4] = X_illicit[:n_mix, 2] - X_illicit[:n_mix, 3]              # balance ~ 0
    X_illicit[:n_mix, 5] = X_illicit[:n_mix, 3] / np.maximum(X_illicit[:n_mix, 2], 0.001)  # liq_ratio ~ 0.98
    X_illicit[:n_mix, 6] = X_illicit[:n_mix, 0] / np.maximum(X_illicit[:n_mix, 1], 1)  # fan_ratio ~ 1.0
    X_illicit[:n_mix, 7] = X_illicit[:n_mix, 2] / np.maximum(X_illicit[:n_mix, 3], 0.001)  # btc_ratio
    X_illicit[:n_mix, 8] = X_illicit[:n_mix, 2] / np.maximum(X_illicit[:n_mix, 0], 1)  # avg_in_size
    X_illicit[:n_mix, 9] = X_illicit[:n_mix, 4]                                     # net_flow ~ 0
    X_illicit[:n_mix, 10] = 1.0                                                     # is_passthrough
    X_illicit[:n_mix, 11] = 0.0                                                     # is_scam
    X_illicit[:n_mix, 12] = 1.0                                                     # is_mixer
    X_illicit[:n_mix, 13] = 0.0                                                     # is_exchange
    X_illicit[:n_mix, 14] = np.random.uniform(10.0, 80.0, n_mix)                    # taint_score
    X_illicit[:n_mix, 15] = np.random.uniform(0.01, 0.15, n_mix)                    # clustering
    X_illicit[:n_mix, 16] = np.random.uniform(0.02, 0.20, n_mix)                    # density
    X_illicit[:n_mix, 17] = X_illicit[:n_mix, 0] + X_illicit[:n_mix, 1] + 1         # n_nodes
    X_illicit[:n_mix, 18] = X_illicit[:n_mix, 0] + X_illicit[:n_mix, 1]             # n_edges
    X_illicit[:n_mix, 19] = X_illicit[:n_mix, 0] + X_illicit[:n_mix, 1]             # tx_count

    # Typology B: Scam Aggregators (1500 samples)
    X_illicit[n_mix:, 0] = np.random.randint(8, 500, n_mix)                         # effective_in (victims)
    X_illicit[n_mix:, 1] = np.random.randint(0, 3, n_mix)                           # out_degree (few exits)
    X_illicit[n_mix:, 2] = np.random.uniform(1.0, 50.0, n_mix)                      # funded_btc
    X_illicit[n_mix:, 3] = X_illicit[n_mix:, 2] * np.random.uniform(0.9, 1.0, n_mix)  # spent_btc
    X_illicit[n_mix:, 4] = X_illicit[n_mix:, 2] - X_illicit[n_mix:, 3]              # balance
    X_illicit[n_mix:, 5] = X_illicit[n_mix:, 3] / np.maximum(X_illicit[n_mix:, 2], 0.001)  # liq_ratio >= 0.9
    X_illicit[n_mix:, 6] = X_illicit[n_mix:, 0] / np.maximum(X_illicit[n_mix:, 1], 1)  # high fan_ratio
    X_illicit[n_mix:, 7] = X_illicit[n_mix:, 2] / np.maximum(X_illicit[n_mix:, 3], 0.001)
    X_illicit[n_mix:, 8] = X_illicit[n_mix:, 2] / np.maximum(X_illicit[n_mix:, 0], 1)
    X_illicit[n_mix:, 9] = X_illicit[n_mix:, 4]                                     # net_flow
    X_illicit[n_mix:, 10] = 0.0                                                     # is_passthrough
    X_illicit[n_mix:, 11] = 1.0                                                     # is_scam
    X_illicit[n_mix:, 12] = 0.0                                                     # is_mixer
    X_illicit[n_mix:, 13] = 0.0                                                     # is_exchange
    X_illicit[n_mix:, 14] = np.random.uniform(0.0, 100.0, n_mix)                    # taint_score
    X_illicit[n_mix:, 15] = 0.0                                                     # clustering
    X_illicit[n_mix:, 16] = np.random.uniform(0.01, 0.08, n_mix)                    # density
    X_illicit[n_mix:, 17] = np.minimum(X_illicit[n_mix:, 0] + 5, 100)               # n_nodes
    X_illicit[n_mix:, 18] = np.minimum(X_illicit[n_mix:, 0] + 2, 95)                # n_edges
    X_illicit[n_mix:, 19] = X_illicit[n_mix:, 0] + np.random.randint(1, 10, n_mix)  # tx_count

    # --- Licit Samples ---
    # Typology C: Normal personal wallets (2000 samples)
    n_personal = 2000
    X_licit[:n_personal, 0] = np.random.poisson(2, n_personal)                      # effective_in
    X_licit[:n_personal, 1] = np.random.poisson(2, n_personal)                      # out_degree
    X_licit[:n_personal, 2] = np.random.exponential(0.5, n_personal)                # funded_btc
    X_licit[:n_personal, 3] = X_licit[:n_personal, 2] * np.random.uniform(0.0, 0.6, n_personal)  # spent_btc
    X_licit[:n_personal, 4] = X_licit[:n_personal, 2] - X_licit[:n_personal, 3]     # balance
    X_licit[:n_personal, 5] = X_licit[:n_personal, 3] / np.maximum(X_licit[:n_personal, 2], 0.001)  # liq_ratio
    X_licit[:n_personal, 6] = X_licit[:n_personal, 0] / np.maximum(X_licit[:n_personal, 1], 1)
    X_licit[:n_personal, 7] = X_licit[:n_personal, 2] / np.maximum(X_licit[:n_personal, 3], 0.001)
    X_licit[:n_personal, 8] = X_licit[:n_personal, 2] / np.maximum(X_licit[:n_personal, 0], 1)
    X_licit[:n_personal, 9] = X_licit[:n_personal, 4]                               # net_flow
    X_licit[:n_personal, 10] = 0.0                                                  # is_passthrough
    X_licit[:n_personal, 11] = 0.0                                                  # is_scam
    X_licit[:n_personal, 12] = 0.0                                                  # is_mixer
    X_licit[:n_personal, 13] = 0.0                                                  # is_exchange
    X_licit[:n_personal, 14] = 0.0                                                  # taint_score = 0
    X_licit[:n_personal, 15] = 0.0                                                  # clustering
    X_licit[:n_personal, 16] = 0.03                                                 # density
    X_licit[:n_personal, 17] = X_licit[:n_personal, 0] + X_licit[:n_personal, 1] + 1  # n_nodes
    X_licit[:n_personal, 18] = X_licit[:n_personal, 0] + X_licit[:n_personal, 1]    # n_edges
    X_licit[:n_personal, 19] = X_licit[:n_personal, 0] + X_licit[:n_personal, 1]    # tx_count

    # Typology D: Compliant Exchanges / Merchants (1000 samples)
    n_exch = n_samples_per_class - n_personal
    X_licit[n_personal:, 0] = np.random.exponential(80.0, n_exch)                   # effective_in
    X_licit[n_personal:, 1] = np.random.exponential(60.0, n_exch)                   # out_degree
    X_licit[n_personal:, 2] = np.random.exponential(500.0, n_exch)                  # funded_btc
    X_licit[n_personal:, 3] = X_licit[n_personal:, 2] * np.random.uniform(0.60, 0.85, n_exch)  # spent_btc
    X_licit[n_personal:, 4] = X_licit[n_personal:, 2] - X_licit[n_personal:, 3]     # balance
    X_licit[n_personal:, 5] = X_licit[n_personal:, 3] / np.maximum(X_licit[n_personal:, 2], 0.001)  # liq_ratio
    X_licit[n_personal:, 6] = X_licit[n_personal:, 0] / np.maximum(X_licit[n_personal:, 1], 1)
    X_licit[n_personal:, 7] = X_licit[n_personal:, 2] / np.maximum(X_licit[n_personal:, 3], 0.001)
    X_licit[n_personal:, 8] = X_licit[n_personal:, 2] / np.maximum(X_licit[n_personal:, 0], 1)
    X_licit[n_personal:, 9] = X_licit[n_personal:, 4]                               # net_flow
    X_licit[n_personal:, 10] = 0.0                                                  # is_passthrough
    X_licit[n_personal:, 11] = 0.0                                                  # is_scam
    X_licit[n_personal:, 12] = 0.0                                                  # is_mixer
    X_licit[n_personal:, 13] = 1.0                                                  # is_exchange
    X_licit[n_personal:, 14] = 0.0                                                  # taint_score = 0
    X_licit[n_personal:, 15] = np.random.uniform(0.01, 0.10, n_exch)                # clustering
    X_licit[n_personal:, 16] = 0.05                                                 # density
    X_licit[n_personal:, 17] = 200                                                  # n_nodes
    X_licit[n_personal:, 18] = 250                                                  # n_edges
    X_licit[n_personal:, 19] = X_licit[n_personal:, 0] + X_licit[n_personal:, 1]    # tx_count

    # Combine & shuffle
    X = np.vstack([X_illicit, X_licit])
    y = np.array([1] * n_samples_per_class + [0] * n_samples_per_class)

    shuffle_idx = np.random.permutation(len(X))
    X = X[shuffle_idx]
    y = y[shuffle_idx]

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X, y)

    # Save
    joblib.dump(model, model_path)
    print(f"  ✅ Calibrated model created and saved as '{model_path}'")

    return model


if __name__ == "__main__":
    create_mock_model()
