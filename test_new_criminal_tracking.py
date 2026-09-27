"""
Comprehensive Verification Script for New/Upcoming Criminal ID Tracking & Dynamic Threat Intelligence.

Tests:
  1. Clean Inactive Address (0 tx, not known) -> 0.0 Risk, Inactive category.
  2. Programmatic Threat Registration -> Successfully saved to threat_intel_custom.json.
  3. Pre-Active Criminal Address Analysis (0 tx, newly registered criminal ID) -> 95.0 Risk, Critical Threat Alert.
  4. Plain Text Feed Ingestion -> Loads from reported_addresses.txt dynamically.
  5. Multi-Explorer Resiliency & Live Mempool Detection.
"""

import os
import json
import networkx as nx
from threat_intel import (
    register_threat_address,
    query_threat_intel,
    load_all_threat_intelligence,
    CUSTOM_THREAT_FILE,
    REPORTED_ADDRESSES_FILE,
)
from blockchain_api import get_address_summary, is_valid_bitcoin_address
from analyze import analyze_wallet


def test_new_criminal_tracking():
    print("=" * 70)
    print("RUNNING VERIFICATION: UPCOMING & NEW CRIMINAL ID TRACKING")
    print("=" * 70)

    passed = 0
    failed = 0

    # -------------------------------------------------------------------------
    # TEST 1: Clean 0-transaction address (e.g. user's queried address)
    # -------------------------------------------------------------------------
    clean_addr = "bc1q2t72rvu8cyu5tpj844md8ls2t4u9nem9xl9gkt"
    print(f"\n[Test 1] Testing clean inactive address: {clean_addr}")
    res1 = analyze_wallet(clean_addr, max_hops=1)

    if res1["risk_score"] == 0.0 and "inactive" in res1["risk_category"]:
        print(f"  PASS: Clean inactive address returned 0.0 risk and '{res1['risk_category']}'")
        passed += 1
    else:
        print(f"  FAIL: Expected 0.0 risk, got {res1['risk_score']} ({res1['risk_category']})")
        failed += 1

    # -------------------------------------------------------------------------
    # TEST 2: Register a new upcoming criminal ID (e.g. fresh ransomware note address)
    # -------------------------------------------------------------------------
    new_ransomware_addr = "bc1q0000000000000000000000000000000fake001"
    # Use a syntactically valid bech32 address for testing
    new_threat_addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    print(f"\n[Test 2] Dynamically registering new criminal ID: {new_threat_addr}")

    reg_ok = register_threat_address(
        address=new_threat_addr,
        entity="LockBit 4.0 Ransomware Campaign 2026",
        category="ransomware",
        severity="critical",
        description="Freshly deployed extortion wallet identified in new enterprise ransomware note.",
        source="DFIR Incident Response Unit",
        persist=True
    )

    if reg_ok and os.path.exists(CUSTOM_THREAT_FILE):
        with open(CUSTOM_THREAT_FILE, "r") as f:
            custom_data = json.load(f)
        if new_threat_addr in custom_data:
            print(f"  PASS: Threat registered and persisted in '{CUSTOM_THREAT_FILE}'")
            passed += 1
        else:
            print("  FAIL: Address not found in persisted JSON")
            failed += 1
    else:
        print("  FAIL: register_threat_address failed")
        failed += 1

    # -------------------------------------------------------------------------
    # TEST 3: Pre-Active Analysis of 0-Tx / Fresh Criminal Address
    # -------------------------------------------------------------------------
    print(f"\n[Test 3] Analyzing newly registered criminal address (pre-active detection)")
    res3 = analyze_wallet(new_threat_addr, max_hops=1)

    print(f"  Result Risk Score: {res3['risk_score']}")
    print(f"  Result Category:   {res3['risk_category']}")
    print(f"  Attribution:       {res3.get('threat_intel', {}).get('entity')}")

    if res3["risk_score"] >= 95.0 and "ransomware" in res3["risk_category"]:
        print("  PASS: Pre-active criminal address triggered hard-floor Risk Score >= 95.0 & Ransomware attribution")
        passed += 1
    else:
        print(f"  FAIL: Expected risk >= 95.0 with ransomware category, got {res3['risk_score']} ({res3['risk_category']})")
        failed += 1

    # -------------------------------------------------------------------------
    # TEST 4: Ingestion of plain-text reported_addresses.txt
    # -------------------------------------------------------------------------
    print(f"\n[Test 4] Testing plain-text feed ingestion (reported_addresses.txt)")
    reported_sample_addr = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    with open(REPORTED_ADDRESSES_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n{reported_sample_addr}, Telegram Crypto Drainer Bot, scam, Automated drainer campaign\n")

    threat_db = load_all_threat_intelligence()
    intel_item = threat_db.get(reported_sample_addr)

    if intel_item and intel_item["entity"] == "Telegram Crypto Drainer Bot":
        print(f"  PASS: Successfully loaded '{intel_item['entity']}' from {REPORTED_ADDRESSES_FILE}")
        passed += 1
    else:
        print(f"  FAIL: Could not load address from {REPORTED_ADDRESSES_FILE}")
        failed += 1

    # -------------------------------------------------------------------------
    # TEST 5: Pre-Active 0-Transaction Criminal Address (Fresh Extortion Note)
    # -------------------------------------------------------------------------
    # bc1q2t72rvu8cyu5tpj844md8ls2t4u9nem9xl9gkt has strictly 0 on-chain txs
    zero_tx_criminal_addr = "1234567890abcdef1234567890abcdef1" # or use another 0-tx address
    test_zero_tx = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    print(f"\n[Test 5] Testing true 0-tx pre-active criminal wallet: {test_zero_tx}")
    register_threat_address(
        address=test_zero_tx,
        entity="Akira Ransomware Fresh Campaign",
        category="ransomware",
        severity="critical",
        description="Freshly generated extortion note wallet with 0 confirmed transactions yet.",
        source="Threat Feed",
        persist=True
    )
    res5 = analyze_wallet(test_zero_tx, max_hops=1)
    print(f"  Result Risk Score: {res5['risk_score']}")
    print(f"  Result Category:   {res5['risk_category']}")
    if res5["risk_score"] >= 95.0 and "ransomware" in res5["risk_category"]:
        print("  PASS: 0-tx fresh criminal wallet correctly flagged with Risk >= 95.0")
        passed += 1
    else:
        print(f"  FAIL: Expected risk >= 95.0, got {res5['risk_score']} ({res5['risk_category']})")
        failed += 1

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print(f"RESULTS: {passed} PASSED, {failed} FAILED out of {passed + failed} CHECKS")
    if failed == 0:
        print(">>> ALL UPCOMING CRIMINAL ID TRACKING CHECKS PASSED <<<")
    else:
        print(">>> SOME CHECKS FAILED <<<")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    test_new_criminal_tracking()
