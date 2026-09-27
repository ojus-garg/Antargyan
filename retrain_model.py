"""
Retrain the ML model with enhanced multi-typology blockchain features.

This enriches the Random Forest model with calibrated graph-topological
and on-chain UTXO behavioral features for 7 illicit and licit transaction typologies:
  1. Peeling chains & mixing services (high symmetry, rapid passthrough)
  2. High-volume scam & ransomware aggregators (victim consolidation, rapid liquidation)
  3. Low-volume extortion & blackmail sweeps (1-3 victim deposits, >=95% liquidation, micro-ransom tiers)
  4. High-taint laundering intermediaries (taint propagation, high throughput)
  5. Standard personal wallets (normal small transfers, balance retention)
  6. Long-term cold storage / genesis holders (0% liquidation, accumulation)
  7. Compliant exchanges & institutional liquidity hubs (high volume, bidirectional)
"""

import os
import shutil
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

from analyze import build_feature_vector


def generate_calibrated_training_data(n_samples=14000):
    """
    Generate calibrated feature vectors across 7 realistic blockchain typologies.
    Aligned with the 27 continuous graph+UTXO features extracted in analyze.py.
    """
    np.random.seed(42)
    num_features = 27
    n_per_typology = n_samples // 7

    X_list = []
    y_list = []

    # ==========================================
    # ILLICIT TYPOLOGIES (Label = 1)
    # ==========================================

    # 1. Peeling Chains & Mixers (Symmetric high fan-out, rapid passthrough, near 100% liquidation)
    X_mix = []
    for _ in range(n_per_typology):
        in_deg = np.random.randint(5, 35)
        out_deg = np.random.randint(5, 35)
        funded = np.random.uniform(1.0, 80.0)
        spent = funded * np.random.uniform(0.95, 1.0)
        bal = max(0.0, funded - spent)
        liq = spent / max(funded, 0.001)
        txs = in_deg + out_deg + np.random.randint(0, 10)
        clust = np.random.uniform(0.01, 0.15)
        dens = np.random.uniform(0.02, 0.20)
        nodes = in_deg + out_deg + 1
        edges = in_deg + out_deg
        feat = build_feature_vector(
            in_degree=in_deg, out_degree=out_deg, funded_btc=funded, spent_btc=spent,
            balance_btc=bal, liq_ratio=liq, tx_count=txs, clustering_coeff=clust,
            density=dens, n_nodes=nodes, n_edges=edges, num_features=num_features
        )
        X_mix.append(feat)
    X_list.append(np.array(X_mix))
    y_list.append(np.ones(n_per_typology, dtype=int))

    # 2. High-Volume Scam / Ransomware Aggregators (High victim in-degree, low out-degree, >75% liquidation)
    X_scam = []
    for _ in range(n_per_typology):
        in_deg = np.random.randint(8, 1500)
        out_deg = np.random.randint(0, 3)
        funded = np.random.uniform(2.0, 500.0)
        spent = funded * np.random.uniform(0.75, 1.0)
        bal = max(0.0, funded - spent)
        liq = spent / max(funded, 0.001)
        txs = in_deg + np.random.randint(1, 15)
        clust = 0.0
        dens = np.random.uniform(0.01, 0.08)
        nodes = min(in_deg + 5, 100)
        edges = min(in_deg + 2, 95)
        feat = build_feature_vector(
            in_degree=in_deg, out_degree=out_deg, funded_btc=funded, spent_btc=spent,
            balance_btc=bal, liq_ratio=liq, tx_count=txs, clustering_coeff=clust,
            density=dens, n_nodes=nodes, n_edges=edges, num_features=num_features
        )
        X_scam.append(feat)
    X_list.append(np.array(X_scam))
    y_list.append(np.ones(n_per_typology, dtype=int))

    # 3. Low-Volume Extortion & Blackmail Sweeps (e.g. 15cRqR3TXS... profile: 1-3 deposits, 100% swift sweep)
    X_extort = []
    for _ in range(n_per_typology):
        in_deg = np.random.randint(1, 4)
        out_deg = 1  # Swept to consolidation hub
        funded = np.random.uniform(0.002, 0.40)  # Standard extortion ransom tier ($150 - $25,000)
        spent = funded * np.random.uniform(0.98, 1.0)  # Immediate complete liquidation
        bal = max(0.0, funded - spent)
        liq = spent / max(funded, 0.001)
        txs = np.random.randint(2, 6)
        clust = 0.0
        dens = np.random.uniform(0.05, 0.50)
        nodes = in_deg + out_deg + 1
        edges = in_deg + out_deg
        feat = build_feature_vector(
            in_degree=in_deg, out_degree=out_deg, funded_btc=funded, spent_btc=spent,
            balance_btc=bal, liq_ratio=liq, tx_count=txs, clustering_coeff=clust,
            density=dens, n_nodes=nodes, n_edges=edges, num_features=num_features
        )
        X_extort.append(feat)
    X_list.append(np.array(X_extort))
    y_list.append(np.ones(n_per_typology, dtype=int))

    # 4. High-Taint Intermediary / Launderer (High liquidation, multi-hop transit)
    X_taint = []
    for _ in range(n_per_typology):
        in_deg = np.random.randint(2, 15)
        out_deg = np.random.randint(1, 6)
        funded = np.random.uniform(0.5, 50.0)
        spent = funded * np.random.uniform(0.85, 1.0)
        bal = max(0.0, funded - spent)
        liq = spent / max(funded, 0.001)
        txs = in_deg + out_deg
        clust = 0.0
        dens = 0.05
        nodes = in_deg + out_deg + 1
        edges = in_deg + out_deg
        feat = build_feature_vector(
            in_degree=in_deg, out_degree=out_deg, funded_btc=funded, spent_btc=spent,
            balance_btc=bal, liq_ratio=liq, tx_count=txs, clustering_coeff=clust,
            density=dens, n_nodes=nodes, n_edges=edges, num_features=num_features
        )
        X_taint.append(feat)
    X_list.append(np.array(X_taint))
    y_list.append(np.ones(n_per_typology, dtype=int))

    # ==========================================
    # LICIT TYPOLOGIES (Label = 0)
    # ==========================================

    # 5. Standard Personal Wallets (Low degree, low liquidation, small volume, retains balance)
    X_personal = []
    for _ in range(n_per_typology):
        in_deg = np.random.randint(1, 6)
        out_deg = np.random.randint(1, 6)
        funded = float(np.random.exponential(0.5)) + 0.005
        spent = funded * np.random.uniform(0.0, 0.60)  # Retains majority balance
        bal = max(0.0, funded - spent)
        liq = spent / max(funded, 0.001)
        txs = np.random.randint(2, 20)
        clust = 0.0
        dens = 0.03
        nodes = in_deg + out_deg + 1
        edges = in_deg + out_deg
        feat = build_feature_vector(
            in_degree=in_deg, out_degree=out_deg, funded_btc=funded, spent_btc=spent,
            balance_btc=bal, liq_ratio=liq, tx_count=txs, clustering_coeff=clust,
            density=dens, n_nodes=nodes, n_edges=edges, num_features=num_features
        )
        X_personal.append(feat)
    X_list.append(np.array(X_personal))
    y_list.append(np.zeros(n_per_typology, dtype=int))

    # 6. Cold Storage / Genesis / Long-term Holders (0% liquidation, accumulation, 0 out_degree)
    X_cold = []
    for _ in range(n_per_typology):
        in_deg = np.random.randint(1, 5000)
        out_deg = 0
        funded = np.random.uniform(5.0, 100000.0)
        spent = 0.0
        bal = funded
        liq = 0.0
        txs = in_deg
        clust = 0.0
        dens = 0.01
        nodes = min(in_deg + 1, 50)
        edges = min(in_deg, 50)
        feat = build_feature_vector(
            in_degree=in_deg, out_degree=out_deg, funded_btc=funded, spent_btc=spent,
            balance_btc=bal, liq_ratio=liq, tx_count=txs, clustering_coeff=clust,
            density=dens, n_nodes=nodes, n_edges=edges, num_features=num_features
        )
        X_cold.append(feat)
    X_list.append(np.array(X_cold))
    y_list.append(np.zeros(n_per_typology, dtype=int))

    # 7. Verified Exchanges & Large Custodians (Massive bidirectional flow, high volume)
    X_exch = []
    for _ in range(n_per_typology):
        in_deg = np.random.randint(50, 5000)
        out_deg = np.random.randint(30, 3000)
        funded = np.random.uniform(500.0, 1000000.0)
        spent = funded * np.random.uniform(0.60, 0.85)
        bal = max(0.0, funded - spent)
        liq = spent / max(funded, 0.001)
        txs = in_deg + out_deg + np.random.randint(50, 1000)
        clust = np.random.uniform(0.01, 0.10)
        dens = 0.05
        nodes = 200
        edges = 250
        feat = build_feature_vector(
            in_degree=in_deg, out_degree=out_deg, funded_btc=funded, spent_btc=spent,
            balance_btc=bal, liq_ratio=liq, tx_count=txs, clustering_coeff=clust,
            density=dens, n_nodes=nodes, n_edges=edges, num_features=num_features
        )
        X_exch.append(feat)
    X_list.append(np.array(X_exch))
    y_list.append(np.zeros(n_per_typology, dtype=int))

    # Combine
    X = np.vstack(X_list)
    y = np.concatenate(y_list)

    # Shuffle
    shuffle_idx = np.random.permutation(len(X))
    return X[shuffle_idx], y[shuffle_idx]


def retrain_with_known_criminals(model_path="wallet_risk_model.joblib"):
    """
    Train and save the calibrated multi-typology Random Forest model.
    """
    print("Training calibrated multi-typology ML model...")

    if os.path.exists(model_path):
        backup_path = model_path.replace(".joblib", "_backup.joblib")
        try:
            shutil.copy2(model_path, backup_path)
            print(f"  Backed up existing model to '{backup_path}'")
        except Exception as e:
            print(f"  [Warning] Backup failed: {e}")

    X, y = generate_calibrated_training_data(n_samples=14000)

    print(f"  Training on {len(X)} samples across 7 blockchain typologies (27 calibrated features)...")
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        max_depth=15,
        min_samples_split=4,
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X, y)

    joblib.dump(model, model_path)
    print(f"  ✅ Calibrated model trained and saved to '{model_path}'")
    return model


if __name__ == "__main__":
    retrain_with_known_criminals()

