"""
Automated Test Suite for Bitcoin Wallet Risk Analyzer.
Tests historical addresses, safe exchanges, unseen scam patterns, foreign chains, and inactive wallets.
"""

from analyze import analyze_wallet

test_cases = [
    ("Twitter 2020 Hack", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", 1),
    ("WannaCry Ransomware", "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn", 1),
    ("Binance Cold Vault", "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo", 1),
    ("Satoshi Genesis", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1),
    ("Reported Scam Wallet", "1EYitrwBYNWuTBcjZFbEUdqHppe2raLpaF", 1),
    ("Ethereum Address", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", 1),
    ("Unused / Inactive Address", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1),
]

for name, addr, hops in test_cases:
    print(f"\n=======================================================")
    print(f"RUNNING TEST: {name}")
    print(f"=======================================================")
    res = analyze_wallet(addr, max_hops=hops, max_addresses_per_hop=3)
    print(f"--> Result: Score={res['risk_score']} | Category='{res['risk_category']}'")
    print(f"--> Evidence Count: {len(res['evidence'])}")
