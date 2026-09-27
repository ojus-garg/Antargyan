"""Quick verification that Fix #1 (20-feature ML vector) is working correctly."""

import numpy as np
import networkx as nx

# Must run from the project directory
from analyze import extract_graph_features, get_ml_probability, load_model


def test_fix1():
    passed = 0
    failed = 0

    # 1. Model expects 20 features
    model = load_model()
    print(f"[1] Model n_features_in_: {model.n_features_in_}")
    if model.n_features_in_ == 20:
        print("    PASS: model trained on 20 features")
        passed += 1
    else:
        print(f"    FAIL: model expects {model.n_features_in_} features, not 20")
        failed += 1

    # 2. extract_graph_features returns 20-dim vector
    G = nx.DiGraph()
    G.add_edge("A", "TARGET", weight=1.5)
    G.add_edge("TARGET", "B", weight=0.8)
    summary = {
        "tx_count": 5, "funded_btc": 2.0, "spent_btc": 1.0,
        "current_balance_btc": 1.0, "liquidation_ratio": 0.5,
    }
    heuristics = {
        "taint_score": 15.0, "mixer_pattern_detected": False,
        "scam_aggregator_detected": False, "exchange_confidence": 20,
    }
    features = extract_graph_features(G, "TARGET", summary=summary, heuristics=heuristics)
    print(f"\n[2] Feature vector shape: {features.shape}")
    if features.shape == (20,):
        print("    PASS: feature vector is (20,)")
        passed += 1
    else:
        print(f"    FAIL: feature vector is {features.shape}, not (20,)")
        failed += 1

    # 3. predict_proba works without crashing
    prob = get_ml_probability(model, G, "TARGET", summary=summary, heuristics=heuristics)
    print(f"\n[3] ML probability: {prob:.4f}")
    if 0.0 <= prob <= 1.0:
        print("    PASS: valid probability returned")
        passed += 1
    else:
        print(f"    FAIL: probability {prob} out of [0, 1] range")
        failed += 1

    # 4. Typology sanity: mixer should score higher than personal wallet
    G_mixer = nx.DiGraph()
    for i in range(15):
        G_mixer.add_edge(f"in_{i}", "MIXER", weight=0.5)
        G_mixer.add_edge("MIXER", f"out_{i}", weight=0.5)
    mixer_summary = {
        "tx_count": 30, "funded_btc": 7.5, "spent_btc": 7.4,
        "current_balance_btc": 0.1, "liquidation_ratio": 0.987,
    }
    mixer_heuristics = {
        "taint_score": 55.0, "mixer_pattern_detected": True,
        "scam_aggregator_detected": False, "exchange_confidence": 0,
    }
    prob_mixer = get_ml_probability(model, G_mixer, "MIXER", summary=mixer_summary, heuristics=mixer_heuristics)

    G_personal = nx.DiGraph()
    G_personal.add_edge("employer", "ME", weight=0.05)
    G_personal.add_edge("ME", "shop", weight=0.02)
    personal_summary = {
        "tx_count": 2, "funded_btc": 0.05, "spent_btc": 0.02,
        "current_balance_btc": 0.03, "liquidation_ratio": 0.4,
    }
    personal_heuristics = {
        "taint_score": 0.0, "mixer_pattern_detected": False,
        "scam_aggregator_detected": False, "exchange_confidence": 0,
    }
    prob_personal = get_ml_probability(model, G_personal, "ME", summary=personal_summary, heuristics=personal_heuristics)

    print(f"\n[4] Mixer illicit prob:    {prob_mixer:.4f}")
    print(f"    Personal illicit prob: {prob_personal:.4f}")
    if prob_mixer > prob_personal:
        print("    PASS: mixer scored higher than personal wallet")
        passed += 1
    else:
        print("    FAIL: mixer did NOT score higher than personal wallet")
        failed += 1

    # Summary
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed} checks")
    if failed == 0:
        print("ALL CHECKS PASSED")
    else:
        print("SOME CHECKS FAILED — review above")
    print(f"{'='*40}")


if __name__ == "__main__":
    test_fix1()
