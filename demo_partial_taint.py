"""
Demo: Wallet with PARTIAL Taint Score (between 0-100%)

This shows a realistic scenario where a wallet receives money from
BOTH clean sources AND criminal sources, resulting in a partial taint score.
"""

import networkx as nx
from heuristics import compute_all_heuristics
from risk_classifier import classify_risk


def create_partial_taint_graph():
    """
    Create a graph showing a wallet with mixed (clean + dirty) funding sources.

    Scenario:
      - Target wallet receives 3 BTC from clean sources
      - Target wallet receives 2 BTC from a criminal wallet
      - Expected taint: 2/(2+3) = 40% tainted
    """
    graph = nx.DiGraph()

    target = "1PartialTaintWallet123"

    # Clean funding sources (3 BTC total)
    graph.add_edge("clean_exchange", target, weight=2.0)
    graph.add_edge("clean_miner", target, weight=1.0)

    # Criminal funding source (2 BTC)
    criminal = "1HackedWallet999"
    graph.add_edge(criminal, target, weight=2.0)

    # Set hop levels
    graph.nodes[target]["hop"] = 0
    graph.nodes["clean_exchange"]["hop"] = 1
    graph.nodes["clean_miner"]["hop"] = 1
    graph.nodes[criminal]["hop"] = 1

    return graph, target, {criminal}


def main():
    print("="*70)
    print("PARTIAL TAINT DEMO")
    print("="*70)
    print("\nScenario: A wallet that received money from BOTH clean and criminal sources")
    print()

    graph, target, known_bad = create_partial_taint_graph()

    print("Wallet Activity:")
    print(f"  ✅ Received 2.0 BTC from clean_exchange")
    print(f"  ✅ Received 1.0 BTC from clean_miner")
    print(f"  ❌ Received 2.0 BTC from 1HackedWallet999 (known criminal)")
    print(f"  📊 Total: 5.0 BTC (3 clean + 2 dirty)")
    print()

    # Compute heuristics
    heuristics = compute_all_heuristics(graph, target, known_bad)

    print("--- Heuristic Scores ---")
    print(f"  Exchange confidence:  {heuristics['exchange_confidence']}%")
    print(f"  Taint score:          {heuristics['taint_score']}%")
    print(f"  OFAC flagged:         {heuristics['ofac_flagged']}")
    print(f"  Mixer pattern:        {heuristics['mixer_pattern_detected']}")
    print()

    # Classify with moderate ML probability
    ml_probability = 0.55  # 55% illicit probability
    result = classify_risk(ml_probability, heuristics)

    print("--- FINAL RISK CLASSIFICATION ---")
    print(f"  Risk Score:    {result['risk_score']} / 100")
    print(f"  Risk Category: {result['risk_category']}")
    print(f"  Evidence:")
    if result['evidence']:
        for e in result['evidence']:
            print(f"    • {e}")
    else:
        print(f"    (no significant risk signals detected)")

    print()
    print("="*70)
    print("INTERPRETATION")
    print("="*70)
    print(f"""
This wallet has a {heuristics['taint_score']}% taint score because:
  - It received 2 BTC from a known criminal wallet
  - It received 3 BTC from clean sources
  - Taint = (2 / 5) × 100 = 40%

This is a common real-world scenario:
  ✅ Small businesses might unknowingly accept payment from criminals
  ✅ Mixing services intentionally blend clean and dirty funds
  ✅ Exchanges process both legitimate and criminal deposits

The partial taint score (not 0%, not 100%) flags this for investigation
but doesn't automatically block it like a 100% tainted wallet would.
    """)


if __name__ == "__main__":
    main()
