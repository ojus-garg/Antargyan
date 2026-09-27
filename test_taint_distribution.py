"""
Test script to verify proportional taint propagation through the network.

This analyzes the Lazarus Group criminal wallet and shows taint percentages
for all downstream wallets in the network.
"""

from blockchain_api import build_transaction_graph
from heuristics import load_ofac_addresses, taint_score


def analyze_taint_distribution():
    """
    Analyze the Lazarus wallet and show taint distribution across the network.
    """
    criminal_wallet = "149w62rY42aZBox8fGcmqNsXUzSStKeq8C"

    print("="*70)
    print("TAINT DISTRIBUTION ANALYSIS")
    print("="*70)
    print(f"\nCriminal Seed Wallet: {criminal_wallet}")
    print("(Lazarus Group - OFAC Sanctioned)\n")

    # Build forward graph from the criminal wallet
    print("Building transaction graph (forward tracing)...")
    graph = build_transaction_graph(criminal_wallet, max_hops=3, max_addresses_per_hop=5)

    # Get OFAC addresses as known-bad seeds
    ofac_set = load_ofac_addresses()
    known_bad = {criminal_wallet} | ofac_set

    print(f"\n{'='*70}")
    print("TAINT DISTRIBUTION BY HOP")
    print(f"{'='*70}\n")

    # Analyze taint for each wallet, grouped by hop
    for hop in range(0, 4):
        hop_wallets = [n for n in graph.nodes() if graph.nodes[n].get('hop') == hop]

        if not hop_wallets:
            continue

        print(f"--- Hop {hop} ({len(hop_wallets)} wallets) ---")

        for wallet in hop_wallets[:10]:  # Show first 10 per hop
            taint = taint_score(graph, wallet, known_bad)

            # Get incoming info
            predecessors = list(graph.predecessors(wallet))
            total_in = sum(
                graph[p][wallet].get("weight", 0)
                for p in predecessors
            )

            # Get outgoing info
            successors = list(graph.successors(wallet))
            total_out = sum(
                graph[wallet][s].get("weight", 0)
                for s in successors
            )

            print(f"  {wallet[:20]}...")
            print(f"    Taint: {taint}%")
            print(f"    Received: {total_in:.6f} BTC from {len(predecessors)} sources")
            print(f"    Sent: {total_out:.6f} BTC to {len(successors)} recipients")

        print()

    print(f"{'='*70}")
    print("VALIDATION")
    print(f"{'='*70}")
    print("\n✅ Expected behavior:")
    print("  - Hop 0 (seed): 100% taint")
    print("  - Hop 1+: Proportional taint (0-100% based on funding mix)")
    print("\n✅ What we're checking:")
    print("  - Taint should NOT be only 0% or 100%")
    print("  - Taint should decrease with distance (dilution)")
    print("  - Taint = (tainted_inflow / total_inflow) × 100")


if __name__ == "__main__":
    analyze_taint_distribution()
