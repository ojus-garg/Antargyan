"""
Verification Script for:
  1. Common-Input-Ownership Heuristic (CIOH) with DSU & CoinJoin Exemption
  2. Entity Threat Attribution via Co-Spent Inputs
  3. Autonomous Unlabeled Exchange Hot Wallet Discovery
  4. End-to-End Analysis Regression Checks
"""

import sys
import networkx as nx
from heuristics import (
    DisjointSetUnion,
    cluster_entity_wallets,
    exchange_confidence,
    compute_all_heuristics,
)
from blockchain_api import is_coinjoin_tx
from risk_classifier import classify_risk
from threat_intel import register_threat_address


def test_cioh_and_exchange():
    print("=" * 70)
    print("RUNNING VERIFICATION: CIOH CLUSTERING & AUTONOMOUS EXCHANGE DISCOVERY")
    print("=" * 70)

    passed = 0
    failed = 0

    # -------------------------------------------------------------------------
    # TEST 1: Disjoint-Set Union (DSU) Unit Test
    # -------------------------------------------------------------------------
    print("\n[Test 1] Testing Disjoint-Set Union (DSU) Data Structure...")
    dsu = DisjointSetUnion()
    dsu.union("addr_A", "addr_B")
    dsu.union("addr_B", "addr_C")
    dsu.union("addr_D", "addr_E")

    if dsu.find("addr_A") == dsu.find("addr_C") and dsu.find("addr_A") != dsu.find("addr_D"):
        print("  PASS: DSU correctly clustered {A, B, C} and separated {D, E}")
        passed += 1
    else:
        print("  FAIL: DSU clustering logic error")
        failed += 1

    # -------------------------------------------------------------------------
    # TEST 2: CoinJoin Filter Test (Wasabi / Whirlpool Collaborative Mixing)
    # -------------------------------------------------------------------------
    print("\n[Test 2] Testing CoinJoin Filter Exemption...")
    # Standard multi-input tx (should NOT be coinjoin)
    normal_tx = {
        "txid": "normal_tx_1",
        "vin": [
            {"prevout": {"scriptpubkey_address": "addr_1", "value": 100000}},
            {"prevout": {"scriptpubkey_address": "addr_2", "value": 200000}},
        ],
        "vout": [
            {"scriptpubkey_address": "recipient_1", "value": 250000},
            {"scriptpubkey_address": "addr_1", "value": 40000},
        ]
    }
    # CoinJoin tx (5 inputs, 5 equal denomination outputs of 0.01 BTC = 1,000,000 sats)
    coinjoin_tx = {
        "txid": "coinjoin_tx_1",
        "vin": [
            {"prevout": {"scriptpubkey_address": "user_a", "value": 1100000}},
            {"prevout": {"scriptpubkey_address": "user_b", "value": 1100000}},
            {"prevout": {"scriptpubkey_address": "user_c", "value": 1100000}},
            {"prevout": {"scriptpubkey_address": "user_d", "value": 1100000}},
        ],
        "vout": [
            {"scriptpubkey_address": "mix_out_1", "value": 1000000},
            {"scriptpubkey_address": "mix_out_2", "value": 1000000},
            {"scriptpubkey_address": "mix_out_3", "value": 1000000},
            {"scriptpubkey_address": "mix_out_4", "value": 1000000},
            {"scriptpubkey_address": "change_1", "value": 80000},
        ]
    }

    if not is_coinjoin_tx(normal_tx) and is_coinjoin_tx(coinjoin_tx):
        print("  PASS: Normal tx recognized as standard; CoinJoin tx accurately detected & flagged")
        passed += 1
    else:
        print("  FAIL: is_coinjoin_tx classification error")
        failed += 1

    # -------------------------------------------------------------------------
    # TEST 3: CIOH Wallet Clustering with CoinJoin Exemption
    # -------------------------------------------------------------------------
    print("\n[Test 3] Testing CIOH Multi-Input Clustering with Mixed Transactions...")
    addr_1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    addr_2 = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    innocent_user_x = "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp"
    innocent_user_y = "1dice97z5pkL2fAQLRpvV6k86J7i8cve6"

    sample_txs = [
        # Tx 1: addr_1 and addr_2 co-spent (Should cluster)
        {
            "txid": "tx_normal_cosend",
            "vin": [
                {"prevout": {"scriptpubkey_address": addr_1, "value": 500000}},
                {"prevout": {"scriptpubkey_address": addr_2, "value": 500000}},
            ],
            "vout": [{"scriptpubkey_address": "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", "value": 900000}]
        },
        # Tx 2: CoinJoin between addr_1 and innocent_user_x (Should NOT cluster)
        {
            "txid": "tx_coinjoin",
            "vin": [
                {"prevout": {"scriptpubkey_address": addr_1, "value": 1050000}},
                {"prevout": {"scriptpubkey_address": innocent_user_x, "value": 1050000}},
                {"prevout": {"scriptpubkey_address": innocent_user_y, "value": 1050000}},
            ],
            "vout": [
                {"scriptpubkey_address": "1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1", "value": 1000000},
                {"scriptpubkey_address": "1FfmbHfnpaZjKFvyi1okTjJJusN455paPH", "value": 1000000},
                {"scriptpubkey_address": "1JqDyCLBvBhGmrnMnhkWcgnS75g9ZzYp5L", "value": 1000000},
            ]
        }
    ]

    cluster_res = cluster_entity_wallets(
        txs=sample_txs,
        target_address=addr_1,
        threat_db={"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX": {"entity": "Threat", "category": "ransomware"}}
    )

    clustered_addrs = cluster_res["cluster_addresses"]
    print(f"  Clustered Wallets with addr_1: {clustered_addrs}")
    print(f"  CoinJoin Txs Filtered: {cluster_res['coinjoin_filtered_count']}")

    if addr_2 in clustered_addrs and innocent_user_x not in clustered_addrs and cluster_res["coinjoin_filtered_count"] == 1:
        print("  PASS: CIOH clustered co-spending addr_2 while protecting innocent_user_x from CoinJoin false clustering")
        passed += 1
    else:
        print("  FAIL: CIOH clustering or CoinJoin exclusion failed")
        failed += 1

    # -------------------------------------------------------------------------
    # TEST 4: Co-Spent Criminal Wallet Attribution (Guaranteed Threat Propagation)
    # -------------------------------------------------------------------------
    print("\n[Test 4] Testing Co-Spent Threat Attribution (CIOH Criminal Linking)...")
    # Register dummy threat
    criminal_wallet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    register_threat_address(
        address=criminal_wallet,
        entity="Lazarus Group DPRK Cyber Heist",
        category="state_sponsored_cybercrime",
        severity="critical",
        description="DPRK state-sponsored cyber exploitation wallet",
        source="UN Security Council Panel",
        persist=False
    )

    # User's unflagged target wallet co-spent with Lazarus in a 2-input tx
    unflagged_target = "1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1"
    syndicate_txs = [
        {
            "txid": "lazarus_heist_sweep",
            "vin": [
                {"prevout": {"scriptpubkey_address": unflagged_target, "value": 10000000}},
                {"prevout": {"scriptpubkey_address": criminal_wallet, "value": 50000000}},
            ],
            "vout": [{"scriptpubkey_address": "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", "value": 59000000}]
        }
    ]

    syndicate_cluster = cluster_entity_wallets(
        txs=syndicate_txs,
        target_address=unflagged_target
    )

    print(f"  Has Co-Spent Threat: {syndicate_cluster['has_co_spent_threat']}")
    print(f"  Co-Spent Threat Entity: {syndicate_cluster.get('co_spent_threat_entity')}")

    # Test full risk classifier integration
    dummy_heuristics = {
        "fan_in": 1,
        "fan_out": 1,
        "exchange_confidence": 0,
        "taint_score": 0.0,
        "ofac_flagged": False,
        "threat_intel_match": {"is_known": False, "is_illicit": False},
        "cioh_cluster": syndicate_cluster,
        "onchain_summary": {"tx_count": 1, "funded_btc": 0.1, "spent_btc": 0.1, "current_balance_btc": 0.0}
    }

    risk_eval = classify_risk(ml_probability=0.20, heuristic_scores=dummy_heuristics)
    print(f"  Risk Score for Co-Spent Accomplice: {risk_eval['risk_score']}")
    print(f"  Risk Category: {risk_eval['risk_category']}")

    if (
        syndicate_cluster["has_co_spent_threat"]
        and risk_eval["risk_score"] >= 95.0
        and "sanctioned entity / state-sponsored cybercrime" in risk_eval["risk_category"]
    ):
        print("  PASS: Unflagged wallet co-spent with Lazarus received 95.0+ Risk Score & State-Sponsored Cybercrime Category")
        passed += 1
    else:
        print(f"  FAIL: Co-spent threat propagation failed: {risk_eval}")
        failed += 1

    # -------------------------------------------------------------------------
    # TEST 5: Autonomous Unlabeled Exchange Hot Wallet Discovery
    # -------------------------------------------------------------------------
    print("\n[Test 5] Testing Autonomous Unlabeled Exchange Discovery...")
    # Simulate an active commercial exchange hot wallet (high fan-in, high fan-out, high velocity, high turnover)
    exchange_graph = nx.DiGraph()
    hot_wallet = "1UnlabeledExchangeHotWallet4444444"

    # Add 40 incoming deposit channels from unique users
    for i in range(40):
        user_addr = f"1DepositUser_{i}"
        exchange_graph.add_edge(user_addr, hot_wallet, weight=0.5)

    # Add 40 outgoing withdrawal channels to unique recipients
    for j in range(40):
        recipient_addr = f"1WithdrawalUser_{j}"
        exchange_graph.add_edge(hot_wallet, recipient_addr, weight=0.48)

    # Add 5 bidirectional market maker channels
    for k in range(5):
        mm_addr = f"1MarketMaker_{k}"
        exchange_graph.add_edge(mm_addr, hot_wallet, weight=2.0)
        exchange_graph.add_edge(hot_wallet, mm_addr, weight=2.0)

    exchange_summary = {
        "tx_count": 15000,
        "funded_btc": 5000.0,
        "spent_btc": 4900.0,
        "current_balance_btc": 100.0,
        "liquidation_ratio": 0.98,
        "has_mempool_activity": True,
        "mempool_tx_count": 12,
    }

    conf = exchange_confidence(
        graph=exchange_graph,
        address=hot_wallet,
        summary=exchange_summary
    )

    print(f"  Autonomous Exchange Confidence Calculated: {conf}%")

    exchange_heuristics = {
        "fan_in": 45,
        "fan_out": 45,
        "exchange_confidence": conf,
        "taint_score": 0.0,
        "ofac_flagged": False,
        "threat_intel_match": {"is_known": False, "is_illicit": False, "is_exchange": False},
        "cioh_cluster": {"has_co_spent_threat": False, "cluster_size": 1},
        "onchain_summary": exchange_summary,
        "whale_profile": {"is_whale": False}
    }

    exchange_risk = classify_risk(ml_probability=0.15, heuristic_scores=exchange_heuristics)
    print(f"  Exchange Classification Category: {exchange_risk['risk_category']}")
    print(f"  Exchange Risk Score: {exchange_risk['risk_score']}")

    if conf >= 75 and "exchange" in exchange_risk["risk_category"] and exchange_risk["risk_score"] <= 30.0:
        print("  PASS: Unlabeled hot wallet automatically discovered as Commercial Liquidity Hub / Exchange with low risk")
        passed += 1
    else:
        print(f"  FAIL: Autonomous exchange discovery failed: conf={conf}, category={exchange_risk['risk_category']}, score={exchange_risk['risk_score']}")
        failed += 1

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print(f"RESULTS: {passed} PASSED, {failed} FAILED out of {passed + failed} TESTS")
    if failed == 0:
        print(">>> ALL CIOH & AUTONOMOUS EXCHANGE DISCOVERY TESTS PASSED <<<")
    else:
        print(">>> SOME TESTS FAILED <<<")
    print(f"{'=' * 70}")

    return failed == 0


if __name__ == "__main__":
    success = test_cioh_and_exchange()
    sys.exit(0 if success else 1)
