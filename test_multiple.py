"""
Test Multiple Bitcoin Addresses at Once

This runs the analyzer on 5 different wallets:
  - 2 criminal (sanctioned)
  - 2 clean (legitimate exchanges)
  - 1 famous (Satoshi)

Run this to see how the tool responds to different wallet types.
"""

from analyze import analyze_wallet

# Test addresses
test_cases = [
    {
        "name": "🔴 Lazarus Group (North Korea) - CRIMINAL",
        "address": "1Ai52Ber6DFGiwLUxkMoqm5SAKmN2cRab3",
        "expected": "HIGH RISK - Sanctioned"
    },
    {
        "name": "🔴 Lazarus Group Wallet 2 - CRIMINAL",
        "address": "149w62rY42aZBox8fGcmqNsXUzSStKeq8C",
        "expected": "HIGH RISK - Sanctioned"
    },
    {
        "name": "🟢 Binance Cold Storage - CLEAN",
        "address": "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
        "expected": "LOW RISK - Legitimate Exchange"
    },
    {
        "name": "🟢 Satoshi Nakamoto Genesis Address - CLEAN",
        "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "expected": "LOW RISK - Inactive/Historic"
    },
]

print("="*80)
print("TESTING BITCOIN WALLET RISK ANALYZER")
print("="*80)
print("\nTesting 4 different wallet types...\n")

results = []

for i, test in enumerate(test_cases, 1):
    print(f"\n{'─'*80}")
    print(f"TEST {i}/4: {test['name']}")
    print(f"Expected: {test['expected']}")
    print(f"{'─'*80}")

    try:
        result = analyze_wallet(test['address'], max_hops=2, max_addresses_per_hop=5)
        results.append({
            "name": test['name'],
            "address": test['address'],
            "score": result['risk_score'],
            "category": result['risk_category'],
            "ofac": result['heuristics']['ofac_flagged'],
        })
    except Exception as e:
        print(f"  ❌ Error: {e}")
        results.append({
            "name": test['name'],
            "address": test['address'],
            "score": "ERROR",
            "category": str(e),
            "ofac": False,
        })

# Summary table
print("\n" + "="*80)
print("SUMMARY TABLE")
print("="*80)
print(f"\n{'Wallet Type':<50} {'Score':<10} {'OFAC':<8} {'Category':<30}")
print("─"*80)

for r in results:
    score_str = f"{r['score']}/100" if r['score'] != "ERROR" else "ERROR"
    ofac_str = "✅ YES" if r['ofac'] else "❌ NO"
    print(f"{r['name']:<50} {score_str:<10} {ofac_str:<8} {r['category'][:28]}")

print("\n" + "="*80)
print("TEST COMPLETE")
print("="*80)
