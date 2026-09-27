"""
End-to-End Verification Test for ANTARGYAN Web Application
Tests Flask routes, static assets, templates, presets, and live forensic execution.
"""

import os
import sys
import json
from app import app, PRESETS

def run_tests():
    print("\n" + "="*60)
    print("ANTARGYAN // END-TO-END SYSTEM VERIFICATION")
    print("="*60)

    client = app.test_client()
    passed = 0
    total = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name} - {details}")

    # Test 1: GET / (Dashboard UI)
    resp = client.get("/")
    assert_test(
        "GET / (Dashboard UI Render)",
        resp.status_code == 200 and b"ANTARGYAN" in resp.data and b"TOP SECRET" in resp.data,
        f"Status: {resp.status_code}"
    )

    # Test 2: GET /api/health
    resp = client.get("/api/health")
    data = json.loads(resp.data.decode("utf-8"))
    assert_test(
        "GET /api/health (System Status)",
        resp.status_code == 200 and data.get("status") == "operational",
        f"Data: {data}"
    )

    # Test 3: GET /api/presets
    resp = client.get("/api/presets")
    data = json.loads(resp.data.decode("utf-8"))
    assert_test(
        "GET /api/presets (Test Data Catalog)",
        resp.status_code == 200 and len(data.get("presets", [])) == len(PRESETS),
        f"Presets count: {len(data.get('presets', []))}"
    )

    # Test 4: POST /api/analyze - Missing Address
    resp = client.post("/api/analyze", json={})
    assert_test(
        "POST /api/analyze (Empty Payload Handling)",
        resp.status_code == 400,
        f"Status: {resp.status_code}"
    )

    # Test 5: POST /api/analyze - Foreign Blockchain (EVM address)
    resp = client.post("/api/analyze", json={
        "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "max_hops": 2,
        "max_addresses_per_hop": 3
    })
    data = json.loads(resp.data.decode("utf-8"))
    assert_test(
        "POST /api/analyze (Foreign Blockchain Detection)",
        resp.status_code == 200 and "foreign blockchain" in data.get("data", {}).get("risk_category", "").lower(),
        f"Result category: {data.get('data', {}).get('risk_category')}"
    )

    # Test 6: POST /api/analyze - Inactive/Unused Address
    resp = client.post("/api/analyze", json={
        "address": "1NcZWVGVfKSgJuEpLCQE78Kje2upvzhN9v",
        "max_hops": 1,
        "max_addresses_per_hop": 2
    })
    data = json.loads(resp.data.decode("utf-8"))
    assert_test(
        "POST /api/analyze (Inactive Address Detection)",
        resp.status_code == 200 and "inactive" in data.get("data", {}).get("risk_category", "").lower(),
        f"Result category: {data.get('data', {}).get('risk_category')}"
    )

    # Test 7: POST /api/analyze - Sanctioned Address (Lazarus Group OFAC)
    resp = client.post("/api/analyze", json={
        "address": "149w62rY42aZBox8fGcmqNsXUzSStKeq8C",
        "max_hops": 1,
        "max_addresses_per_hop": 2
    })
    data = json.loads(resp.data.decode("utf-8"))
    risk_score = data.get("data", {}).get("risk_score", 0)
    assert_test(
        "POST /api/analyze (Lazarus Group OFAC Sanctions Attribution)",
        resp.status_code == 200 and risk_score >= 95,
        f"Risk Score: {risk_score}, Category: {data.get('data', {}).get('risk_category')}"
    )

    # Test 8: Visualizations URL Translation
    vis = data.get("data", {}).get("visualizations", {})
    assert_test(
        "Visualizations Web URL Formatting",
        vis.get("graph_image") is None or vis.get("graph_image", "").startswith("/graphs/"),
        f"Vis: {vis}"
    )

    print("="*60)
    print(f"VERIFICATION SUMMARY: {passed} / {total} TESTS PASSED")
    print("="*60 + "\n")

    return passed == total

if __name__ == "__main__":
    success = run_tests()
    if not success:
        sys.exit(1)
