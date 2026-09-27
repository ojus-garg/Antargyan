"""
DEMO: Bitcoin Wallet Risk Analyzer (without ML model)

This demo shows the risk classifier working WITHOUT needing to:
  - Download the Elliptic dataset
  - Train the ML model
  - Wait for blockchain API calls

It uses a simulated transaction graph and shows all the features working.

Usage:
    python demo.py
"""

import networkx as nx
from heuristics import compute_all_heuristics
from risk_classifier import classify_risk


def create_demo_graph():
    """
    Build a fake transaction graph that simulates different wallet types.

    We'll create 4 test wallets:
      - suspicious_mixer: looks like a tumbling service
      - tainted_wallet: receives funds from a known-bad wallet
      - clean_exchange: looks like a legitimate exchange
      - ofac_sanctioned: an address on the sanctions list
    """
    graph = nx.DiGraph()

    # === Wallet 1: Suspicious Mixer ===
    # Pattern: many inputs, many outputs, roughly equal (classic tumbler)
    mixer = "1MixerABC123"
    for i in range(20):
        sender = f"sender_{i}"
        graph.add_edge(sender, mixer, weight=0.5 + i*0.1)
    for i in range(18):
        recipient = f"recipient_{i}"
        graph.add_edge(mixer, recipient, weight=0.6 + i*0.1)
    graph.nodes[mixer]["hop"] = 0

    # === Wallet 2: Tainted Wallet ===
    # Pattern: receives money from a known-bad wallet (hack proceeds)
    tainted = "1TaintedXYZ456"
    known_hack = "1HackedWallet000"
    middleman = "1Middleman111"

    graph.add_edge(known_hack, middleman, weight=5.0)
    graph.add_edge(middleman, tainted, weight=3.0)
    graph.add_edge("1CleanSource", tainted, weight=2.0)
    graph.nodes[tainted]["hop"] = 0
    graph.nodes[known_hack]["hop"] = 2
    graph.nodes[middleman]["hop"] = 1

    # === Wallet 3: Clean Exchange ===
    # Pattern: LOTS of incoming transactions (people depositing)
    exchange = "1ExchangeBinance"
    for i in range(150):
        depositor = f"depositor_{i}"
        graph.add_edge(depositor, exchange, weight=0.2 + i*0.01)
    # Few outgoing (withdrawals)
    for i in range(5):
        withdraw = f"withdraw_{i}"
        graph.add_edge(exchange, withdraw, weight=10.0)
    graph.nodes[exchange]["hop"] = 0

    # === Wallet 4: OFAC Sanctioned ===
    # This one is on the sanctions list (we added a real address in ofac_addresses.txt)
    ofac = "149w62rY42aZBox8fGcmqNsXUzSStKeq8C"  # Real Lazarus Group address
    graph.add_edge(ofac, "1Receiver999", weight=1.0)
    graph.nodes[ofac]["hop"] = 0

    return graph, {
        "mixer": mixer,
        "tainted": tainted,
        "exchange": exchange,
        "ofac": ofac,
    }, {known_hack}  # known_bad set


def analyze_demo_wallet(graph, address, known_bad, wallet_label, ml_probability=0.5):
    """Analyze one wallet and pretty-print the results."""
    print(f"\n{'='*70}")
    print(f"ANALYZING: {wallet_label}")
    print(f"Address: {address}")
    print(f"{'='*70}")

    # Compute heuristics
    heuristics = compute_all_heuristics(graph, address, known_bad)

    print("\n--- Heuristic Scores ---")
    print(f"  Exchange confidence:  {heuristics['exchange_confidence']}%")
    print(f"  Taint score:          {heuristics['taint_score']}%")
    print(f"  OFAC flagged:         {heuristics['ofac_flagged']}")
    print(f"  Mixer pattern:        {heuristics['mixer_pattern_detected']}")
    print(f"  Fan-in:               {heuristics['fan_in']}")
    print(f"  Fan-out:              {heuristics['fan_out']}")
    print(f"  Fan ratio:            {heuristics['fan_ratio']}")

    # Classify risk (using simulated ML probability)
    result = classify_risk(ml_probability, heuristics)

    print("\n--- FINAL RISK CLASSIFICATION ---")
    print(f"  Risk Score:    {result['risk_score']} / 100")
    print(f"  Risk Category: {result['risk_category']}")
    print(f"  Evidence:")
    if result['evidence']:
        for e in result['evidence']:
            print(f"    • {e}")
    else:
        print(f"    (no significant risk signals detected)")

    return result


def main():
    """Run the demo on 4 different wallet types."""
    print("="*70)
    print("BITCOIN WALLET RISK ANALYZER - DEMO")
    print("="*70)
    print("\nThis demo shows the classifier working on 4 simulated wallet types:")
    print("  1. Suspicious mixer (tumbling service)")
    print("  2. Tainted wallet (linked to hack proceeds)")
    print("  3. Clean exchange (legitimate)")
    print("  4. OFAC-sanctioned address (real Lazarus Group wallet)")

    # Build the demo graph
    graph, wallets, known_bad = create_demo_graph()

    # Analyze each wallet with realistic ML probabilities
    analyze_demo_wallet(
        graph, wallets["mixer"], known_bad,
        "Wallet 1: Suspicious Mixer",
        ml_probability=0.75  # High illicit probability
    )

    analyze_demo_wallet(
        graph, wallets["tainted"], known_bad,
        "Wallet 2: Tainted (linked to hack)",
        ml_probability=0.60  # Moderate illicit probability
    )

    analyze_demo_wallet(
        graph, wallets["exchange"], known_bad,
        "Wallet 3: Clean Exchange",
        ml_probability=0.05  # Very low illicit probability
    )

    analyze_demo_wallet(
        graph, wallets["ofac"], known_bad,
        "Wallet 4: OFAC Sanctioned (Lazarus Group)",
        ml_probability=0.90  # Very high illicit probability
    )

    # Summary
    print(f"\n{'='*70}")
    print("DEMO COMPLETE")
    print(f"{'='*70}")
    print("\nNext steps to use with real Bitcoin addresses:")
    print("  1. Download Elliptic dataset from Kaggle")
    print("  2. Run: python train_model.py")
    print("  3. Run: python analyze.py <bitcoin_address>")
    print("\nOr use the analyze_wallet() function in your own code:")
    print("  from analyze import analyze_wallet")
    print("  result = analyze_wallet('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')")


if __name__ == "__main__":
    main()
