"""
Step 4: Comprehensive Heuristic Scoring & Entity Attribution Engine.

What this does:
  - exchange_confidence: estimates if a wallet is a legitimate exchange (0-100), with safeguards against scam aggregators
  - fan_in_out_ratio: detects mixing-service (tumbler) patterns
  - scam_aggregator_check: detects victim consolidation & rapid liquidation patterns for new/unseen scams
  - taint_score: traces continuous, proportional % of funds derived from known illicit sources,
                 incorporating multi-hop distance decay, clean coin dilution, and threat intelligence profiling
  - ofac_check: checks if a wallet is on the US sanctions list
  - threat_intelligence: queries verified threat intel database + external feeds
"""

import os
import networkx as nx
from threat_intel import (
    query_threat_intel,
    load_all_threat_intelligence,
    normalize_address,
)
from blockchain_api import (
    get_address_summary,
    get_address_txs,
    is_coinjoin_tx,
    is_valid_bitcoin_address,
)


OFAC_FILE = "ofac_addresses.txt"

# Intrinsic base taint scores for recognized threat intelligence categories
INTRINSIC_TAINT_MAP = {
    "sanctions": 100.0,
    "state_sponsored_cybercrime": 100.0,
    "sanctioned_mixer": 98.0,
    "ransomware": 95.0,
    "ransomware_laundering": 94.0,
    "exchange_hack": 92.0,
    "theft_scam": 90.0,
    "darknet_seized": 88.0,
    "darknet_market": 88.0,
    "scam_distribution": 85.0,
    "scam": 80.0,
    "verified_exchange": 0.0,
    "historical_genesis": 0.0,
}


def load_ofac_addresses(filepath=OFAC_FILE):
    """
    Load sanctioned Bitcoin addresses from the local verified OFAC file.
    Normalizes addresses (trimmed, lowercase for bech32).
    """
    addresses = set()

    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    addresses.add(normalize_address(line))
    return addresses


class DisjointSetUnion:
    """Disjoint Set Union (Union-Find) with path compression and union by rank."""
    def __init__(self):
        self.parent = {}
        self.rank = {}

    def find(self, item):
        if item not in self.parent:
            self.parent[item] = item
            self.rank[item] = 0
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, item1, item2):
        root1 = self.find(item1)
        root2 = self.find(item2)
        if root1 != root2:
            if self.rank[root1] < self.rank[root2]:
                self.parent[root1] = root2
            elif self.rank[root1] > self.rank[root2]:
                self.parent[root2] = root1
            else:
                self.parent[root2] = root1
                self.rank[root1] += 1


def cluster_entity_wallets(txs, target_address=None, ofac_set=None, threat_db=None):
    """
    Common-Input-Ownership Heuristic (CIOH) clustering engine.
    Groups Bitcoin addresses co-spent in single transactions into unified entities.
    Strictly filters out collaborative CoinJoin transactions to prevent false clustering.

    Cross-references clustered entities against verified threat intelligence to detect
    shared private-key authority with sanctioned or criminal wallets.
    """
    if ofac_set is None:
        ofac_set = load_ofac_addresses()
    if threat_db is None:
        threat_db = load_all_threat_intelligence()

    dsu = DisjointSetUnion()
    coinjoin_count = 0
    co_spent_tx_count = 0

    if not txs or not isinstance(txs, list):
        norm_target = normalize_address(target_address) if target_address else ""
        return {
            "cluster_size": 1 if norm_target else 0,
            "cluster_addresses": [norm_target] if norm_target else [],
            "co_spent_tx_count": 0,
            "coinjoin_filtered_count": 0,
            "has_co_spent_threat": False,
            "co_spent_threat_entity": None,
            "co_spent_threat_category": None,
            "co_spent_threat_address": None,
            "co_spent_threat_severity": None,
            "co_spent_threat_source": None,
        }

    for tx in txs:
        if not isinstance(tx, dict):
            continue

        # Filter CoinJoin transactions (Wasabi / Whirlpool / JoinMarket)
        if is_coinjoin_tx(tx):
            coinjoin_count += 1
            continue

        vins = tx.get("vin", [])
        input_addrs = []
        for vin in vins:
            addr = vin.get("prevout", {}).get("scriptpubkey_address")
            if addr and is_valid_bitcoin_address(addr):
                input_addrs.append(normalize_address(addr))

        unique_inputs = list(set(input_addrs))
        if len(unique_inputs) > 1:
            co_spent_tx_count += 1
            primary = unique_inputs[0]
            for other in unique_inputs[1:]:
                dsu.union(primary, other)
        elif len(unique_inputs) == 1:
            dsu.find(unique_inputs[0])

    norm_target = normalize_address(target_address) if target_address else ""
    cluster_members = []
    if norm_target:
        if norm_target in dsu.parent:
            target_root = dsu.find(norm_target)
            cluster_members = [
                addr for addr in dsu.parent
                if dsu.find(addr) == target_root
            ]
        else:
            cluster_members = [norm_target]
    else:
        cluster_members = list(dsu.parent.keys())

    # Check for threat matches in co-spent cluster
    has_threat = False
    threat_entity = None
    threat_cat = None
    threat_addr = None
    threat_sev = None
    threat_src = None

    for member in cluster_members:
        if norm_target and member == norm_target:
            continue  # Target itself is checked separately in direct threat intel query

        if member in ofac_set:
            has_threat = True
            threat_entity = "OFAC Sanctioned Entity (Co-Spent)"
            threat_cat = "sanctions"
            threat_addr = member
            threat_sev = "critical"
            threat_src = "OFAC SDN List"
            break

        if member in threat_db:
            item = threat_db[member]
            cat = item.get("category", "")
            if cat not in ["verified_exchange", "historical_genesis"]:
                has_threat = True
                threat_entity = item.get("entity", "Threat Entity")
                threat_cat = cat
                threat_addr = member
                threat_sev = item.get("severity", "high")
                threat_src = item.get("source", "Verified Threat Intel")
                break

    return {
        "cluster_size": len(cluster_members),
        "cluster_addresses": cluster_members,
        "co_spent_tx_count": co_spent_tx_count,
        "coinjoin_filtered_count": coinjoin_count,
        "has_co_spent_threat": has_threat,
        "co_spent_threat_entity": threat_entity,
        "co_spent_threat_category": threat_cat,
        "co_spent_threat_address": threat_addr,
        "co_spent_threat_severity": threat_sev,
        "co_spent_threat_source": threat_src,
    }


def exchange_confidence(graph, address, summary=None, threat_info=None):
    """
    Estimate how likely this address belongs to a legitimate exchange or custodian (0-100).
    Incorporates macro transaction velocity, counterparty diversity, and liquidity float.

    Features analyzed:
      - Bidirectional fan-in & fan-out symmetry (deposits vs withdrawals)
      - High transaction velocity & cumulative volume float
      - Continuous liquidity turnover (0.65 <= liquidation_ratio <= 0.999)
      - Safeguards against scam aggregators (victim funnels) and mixing services
    """
    if threat_info and threat_info.get("is_exchange"):
        return 95

    if threat_info and threat_info.get("is_illicit"):
        return 0

    if not summary:
        summary = {}

    tx_count = summary.get("tx_count", 0)
    funded_btc = summary.get("funded_btc", 0.0)
    liq_ratio = summary.get("liquidation_ratio", 0.0)

    # Inactive wallet cannot be an exchange
    if tx_count == 0 and (graph is None or address not in graph or graph.degree(address) == 0):
        return 0

    in_degree = graph.in_degree(address) if (graph is not None and address in graph) else 0
    out_degree = graph.out_degree(address) if (graph is not None and address in graph) else 0

    # Scam signature: high in-degree, near-zero out-degree (victim aggregator funnel)
    if in_degree >= 4 and out_degree <= 1:
        return 0

    # Mixer signature for low-volume / small burst passthrough wallets (not macro liquidity hubs)
    fan = fan_in_out_ratio(graph, address) if graph else {"is_suspicious": False}
    if fan.get("is_suspicious") and liq_ratio >= 0.85 and tx_count < 50 and funded_btc < 2.0:
        return 0

    # Macro Autonomous Discovery: High-velocity commercial exchange hot wallet profile
    # Characteristics: Hundreds/thousands of transactions, high volume, balanced liquidity turnover
    score = 0
    if tx_count >= 500 and funded_btc >= 50.0 and 0.75 <= liq_ratio <= 0.999:
        score = 90
    elif tx_count >= 100 and funded_btc >= 10.0 and 0.70 <= liq_ratio <= 0.999:
        score = 80
    elif tx_count >= 50 and funded_btc >= 2.0 and 0.65 <= liq_ratio <= 0.999:
        score = 70
    elif in_degree >= 8 and out_degree >= 4 and funded_btc >= 10.0:
        score = min(85, int(40 + (in_degree + out_degree) * 2))
    elif in_degree >= 5 and out_degree >= 2 and funded_btc >= 1.0:
        score = min(55, int(20 + in_degree * 3))
    elif in_degree >= 2:
        score = min(25, int(in_degree * 2))

    return score


def fan_in_out_ratio(graph, address):
    """
    Calculate the fan-in to fan-out ratio for mixing-service / tumbler detection.
    Tumblers typically have high symmetric fan-in and fan-out with passthrough.
    """
    if address not in graph:
        return {"fan_in": 0, "fan_out": 0, "ratio": 0.0, "is_suspicious": False}

    fan_in = graph.in_degree(address)
    fan_out = graph.out_degree(address)

    if fan_out == 0:
        ratio = float(fan_in)
    else:
        ratio = fan_in / fan_out

    # Mixer signature: High symmetric fan-in and fan-out
    is_suspicious = (fan_in >= 5 and fan_out >= 5 and 0.3 <= ratio <= 3.0)

    return {
        "fan_in": fan_in,
        "fan_out": fan_out,
        "ratio": round(ratio, 2),
        "is_suspicious": is_suspicious,
    }


def detect_scam_aggregator(graph, address, summary=None):
    """
    Generalized behavioral detector for newly generated or unseen scam/extortion wallets.

    Scam/Extortion Aggregator Patterns:
      Pattern A: Multi-victim graph consolidation (in_degree >= 3, out_degree <= 1, liq_ratio >= 0.80)
      Pattern B: On-chain high transaction victim funnel (tx_count >= 5, out_degree <= 2, liq_ratio >= 0.90, funded_btc > 0.01)
      Pattern C: Low-volume extortion / blackmail sweep (in_degree >= 1 or tx_count >= 2, out_degree <= 1, liq_ratio >= 0.95, 0.001 <= funded_btc <= 0.5, tx_count <= 8)
    """
    if (graph is None or address not in graph) and not summary:
        return False

    in_degree = graph.in_degree(address) if (graph is not None and address in graph) else 0
    out_degree = graph.out_degree(address) if (graph is not None and address in graph) else 0

    tx_count = summary.get("tx_count", 0) if summary else 0
    liq_ratio = summary.get("liquidation_ratio", 0.0) if summary else 0.0
    funded_btc = summary.get("funded_btc", 0.0) if summary else 0.0

    # Pattern A: Graph-based victim consolidation
    if in_degree >= 3 and out_degree <= 1 and liq_ratio >= 0.80:
        return True

    # Pattern B: On-chain high transaction victim funnel with high liquidation
    if tx_count >= 5 and out_degree <= 2 and liq_ratio >= 0.90 and funded_btc > 0.01:
        return True

    # Pattern C: Low-volume extortion / blackmail single-sweep pattern (e.g. sextortion, ransomware micro-tiers)
    if (in_degree >= 1 or tx_count >= 2) and out_degree <= 1 and liq_ratio >= 0.95 and (0.001 <= funded_btc <= 0.5) and tx_count <= 8:
        return True

    return False


def detect_whale_profile(graph, address, summary=None):
    """
    Detect institutional whale movements, high-value custody transits, and cold storage vaults.

    Criteria:
      - Total received >= 100.0 BTC or active holding >= 100.0 BTC
      - High liquidation (>= 90%) with low out-degree indicates an institutional transit / sweeping hop
      - Identifies top downstream destination node and percentage of funds transferred
    """
    if not summary:
        summary = {}

    funded_btc = summary.get("funded_btc", 0.0)
    spent_btc = summary.get("spent_btc", 0.0)
    current_balance = summary.get("current_balance_btc", 0.0)
    liq_ratio = summary.get("liquidation_ratio", 0.0)
    tx_count = summary.get("tx_count", 0)

    is_whale = (funded_btc >= 100.0 or current_balance >= 100.0)
    is_transit = (funded_btc >= 100.0 and liq_ratio >= 0.90 and tx_count <= 50)
    is_vault = (current_balance >= 100.0 and liq_ratio < 0.50)

    top_dest = None
    top_amount = 0.0
    top_pct = 0.0

    if graph is not None and address in graph:
        for succ in graph.successors(address):
            w = graph[address][succ].get("weight", 0.0)
            if w > top_amount:
                top_amount = w
                top_dest = succ

        if spent_btc > 0 and top_amount > 0:
            top_pct = (top_amount / spent_btc) * 100.0

    return {
        "is_whale": is_whale,
        "is_transit": is_transit,
        "is_vault": is_vault,
        "total_volume_btc": round(funded_btc, 4),
        "current_balance_btc": round(current_balance, 4),
        "top_destination": top_dest,
        "top_destination_btc": round(top_amount, 4),
        "top_destination_pct": round(top_pct, 2),
    }


def detect_dusting_attacks(graph, address, summary=None):
    """
    Detect micro-UTXO inflows (dusting attacks) used for blockchain surveillance / de-anonymization.

    Standard Bitcoin dust threshold is <= 546 satoshis (0.00000546 BTC) up to 1,000 satoshis (0.00001 BTC).
    """
    dust_txs = []
    dust_senders = []
    total_dust = 0.0

    if graph is not None and address in graph:
        for pred in graph.predecessors(address):
            w = graph[pred][address].get("weight", 0.0)
            if 0 < w <= 0.00001:  # <= 1,000 satoshis
                dust_txs.append((pred, w))
                dust_senders.append(pred)
                total_dust += w

    return {
        "dusting_detected": len(dust_txs) > 0,
        "dust_tx_count": len(dust_txs),
        "dust_senders": dust_senders,
        "total_dust_btc": round(total_dust, 8),
    }


def _get_node_intrinsic_profile(node, known_bad_set, threat_db, ofac_set, graph=None, onchain_summary=None):
    """
    Determine the intrinsic baseline taint and whether the node is a clean taint absorber.

    Returns:
        (intrinsic_taint: float, is_absorber: bool)
    """
    norm_node = normalize_address(node)

    # 1. Check OFAC Sanctions
    if norm_node in ofac_set:
        return 100.0, False

    # 2. Check Threat Intelligence Database
    if norm_node in threat_db:
        item = threat_db[norm_node]
        cat = item.get("category", "")
        if cat in ["verified_exchange", "historical_genesis"]:
            return 0.0, True  # Taint Sink / Absorber
        return INTRINSIC_TAINT_MAP.get(cat, 85.0), False

    # 3. Check Known Bad / Sanctioned Seeds
    if norm_node in known_bad_set or node in known_bad_set:
        return 100.0, False

    # 4. Behavioral heuristics if present in graph
    if graph is not None and node in graph:
        if detect_scam_aggregator(graph, node, onchain_summary if norm_node == normalize_address(node) else None):
            return 75.0, False
        if fan_in_out_ratio(graph, node)["is_suspicious"]:
            return 65.0, False

    return 0.0, False


def taint_score(
    graph,
    target_address,
    known_bad_addresses=None,
    max_iterations=15,
    decay_factor=0.88,
    onchain_summary=None,
):
    """
    Calculate continuous proportional taint score (0.0% to 100.0%) for a Bitcoin address.

    Mathematical Model:
      - Proportional UTXO Inflow Attribution (Haircut / Poison Mixture)
      - Multi-Hop Distance Attenuation (gamma = 0.88 per hop across downstream laundering chains)
      - On-Chain Lifetime Dilution against total received BTC
      - Threat Intelligence Intrinsic Profiling
      - Taint Absorbers (Regulated compliant exchanges reset taint to prevent false cascading)

    Formula for each node u across iterations:
      TaintedInflow(u) = sum_{p in Pred(u)} [ w(p, u) * T(p) * (gamma ^ delta_hop) ]
      EffectiveInflow(u) = max( sum_{p} w(p, u), funded_btc(u) )
      InflowTaint(u) = (TaintedInflow(u) / EffectiveInflow(u)) * 100.0
      Taint(u) = max( IntrinsicBaseline(u), InflowTaint(u), OutflowExposure(u) )

    Returns:
        float: Calibrated taint percentage (0.0 to 100.0) rounded to 1 decimal place.
    """
    if not target_address:
        return 0.0

    if known_bad_addresses is None:
        known_bad_addresses = set()

    # Load threat intelligence & OFAC sets
    ofac_set = load_ofac_addresses()
    threat_db = load_all_threat_intelligence()
    normalized_bad = {normalize_address(a) for a in known_bad_addresses}

    norm_target = normalize_address(target_address)

    # 1. Handle case where target address is not in the transaction graph
    if graph is None or target_address not in graph:
        intrinsic_val, is_absorber = _get_node_intrinsic_profile(
            target_address, normalized_bad, threat_db, ofac_set, graph=None, onchain_summary=onchain_summary
        )
        return round(intrinsic_val, 1)

    # 2. Extract intrinsic baselines and absorber flags for all graph nodes
    intrinsic_profiles = {}
    absorbers = set()

    for node in graph.nodes():
        node_summary = onchain_summary if normalize_address(node) == norm_target else None
        base_taint, is_absorber = _get_node_intrinsic_profile(
            node, normalized_bad, threat_db, ofac_set, graph=graph, onchain_summary=node_summary
        )
        intrinsic_profiles[node] = base_taint
        if is_absorber:
            absorbers.add(node)

    # 3. If target is a verified exchange or genesis wallet, it is a clean sink (0.0%)
    if target_address in absorbers:
        return 0.0

    # 4. Check if there are any tainted/suspicious nodes in the graph
    has_any_taint_seed = any(val > 0 for val in intrinsic_profiles.values())
    if not has_any_taint_seed:
        return 0.0

    # 5. Initialize iterative state
    taint_values = dict(intrinsic_profiles)

    # 6. Iterative relaxation across the directed graph
    for _ in range(max_iterations):
        max_delta = 0.0
        new_taint = dict(taint_values)

        for node in graph.nodes():
            # Taint Absorbers (Exchanges) always remain 0.0%
            if node in absorbers:
                new_taint[node] = 0.0
                continue

            base_taint = intrinsic_profiles.get(node, 0.0)

            # A. Calculate Incoming Taint Flow
            predecessors = list(graph.predecessors(node))
            inflow_taint = 0.0

            if predecessors:
                total_inflow = 0.0
                tainted_inflow = 0.0

                for pred in predecessors:
                    edge_weight = graph[pred][node].get("weight", 0.0)
                    w = edge_weight if edge_weight > 0 else 1.0
                    total_inflow += w

                    pred_taint = taint_values.get(pred, 0.0)

                    # Compute distance attenuation factor
                    hop_pred = graph.nodes[pred].get("hop", None)
                    hop_node = graph.nodes[node].get("hop", None)

                    if hop_pred is not None and hop_node is not None and hop_node > hop_pred and hop_pred >= 0:
                        delta_hop = max(1, hop_node - hop_pred)
                        decay = decay_factor ** delta_hop
                    else:
                        decay = 1.0

                    tainted_inflow += w * (pred_taint * decay)

                # Reconcile with lifetime funded BTC for target address to capture true dilution
                if normalize_address(node) == norm_target and onchain_summary:
                    lifetime_funded = onchain_summary.get("funded_btc", 0.0)
                    effective_denom = max(total_inflow, lifetime_funded) if lifetime_funded > 0 else total_inflow
                else:
                    effective_denom = total_inflow

                if effective_denom > 0:
                    inflow_taint = (tainted_inflow / effective_denom)

            # B. Calculate Outgoing Exposure (Counterparty Risk for Target)
            outflow_taint = 0.0
            if normalize_address(node) == norm_target:
                successors = list(graph.successors(node))
                if successors:
                    total_outflow = 0.0
                    tainted_outflow = 0.0
                    for succ in successors:
                        edge_weight = graph[node][succ].get("weight", 0.0)
                        w = edge_weight if edge_weight > 0 else 1.0
                        total_outflow += w

                        succ_base = intrinsic_profiles.get(succ, 0.0)
                        if succ_base >= 60.0:
                            tainted_outflow += w * succ_base * 0.70  # Exposure coefficient

                    if total_outflow > 0:
                        outflow_taint = (tainted_outflow / total_outflow)

            # Synthesize final node taint for this iteration
            final_node_taint = min(100.0, max(base_taint, inflow_taint, outflow_taint))

            delta = abs(final_node_taint - taint_values[node])
            if delta > max_delta:
                max_delta = delta

            new_taint[node] = final_node_taint

        taint_values = new_taint
        if max_delta < 0.01:
            break

    target_score = taint_values.get(target_address, 0.0)
    return round(max(0.0, min(100.0, float(target_score))), 1)


def ofac_check(address, ofac_set=None):
    """
    Strictly check if an address appears on the OFAC sanctions list.
    """
    if ofac_set is None:
        ofac_set = load_ofac_addresses()

    normalized_addr = normalize_address(address)
    return normalized_addr in ofac_set


def compute_all_heuristics(graph, target_address, known_bad_addresses=None, onchain_summary=None, txs=None):
    """
    Run all heuristic checks, entity attribution, and threat intelligence queries.

    Returns dict with:
      - exchange_confidence
      - fan_in, fan_out, fan_ratio, mixer_pattern_detected
      - scam_aggregator_detected
      - whale_profile, dusting_profile
      - cioh_cluster: {cluster_size, cluster_addresses, co_spent_tx_count, has_co_spent_threat, ...}
      - taint_score
      - ofac_flagged
      - threat_intel_match: {is_known, is_illicit, entity, category, severity, description, source}
      - onchain_summary: {tx_count, funded_btc, spent_btc, current_balance_btc}
    """
    if known_bad_addresses is None:
        known_bad_addresses = set()

    # 1. Load threat intelligence & sanctions
    ofac_set = load_ofac_addresses()
    threat_intel_db = load_all_threat_intelligence()

    # Add all illicit addresses from threat intel to bad seeds
    illicit_threat_addrs = {
        addr for addr, data in threat_intel_db.items()
        if data.get("category") not in ["verified_exchange", "historical_genesis"]
    }
    all_known_bad = known_bad_addresses | ofac_set | illicit_threat_addrs

    # 2. Query target address in threat intelligence
    threat_match = query_threat_intel(target_address)
    is_ofac = ofac_check(target_address, ofac_set) or (
        threat_match["is_known"] and "OFAC" in (threat_match.get("source") or "")
    )

    # 3. Fetch on-chain summary statistics if not provided
    if onchain_summary is None:
        onchain_summary = get_address_summary(target_address)

    # 4. Fetch transactions for CIOH entity clustering if not provided
    if txs is None and onchain_summary.get("tx_count", 0) > 0:
        txs = get_address_txs(target_address)

    # 5. Execute Common-Input-Ownership Heuristic (CIOH) Clustering
    cioh_cluster = cluster_entity_wallets(
        txs, target_address, ofac_set=ofac_set, threat_db=threat_intel_db
    )

    # If co-spent with an illicit threat, add cluster threat to bad seeds
    if cioh_cluster.get("has_co_spent_threat") and cioh_cluster.get("co_spent_threat_address"):
        all_known_bad.add(normalize_address(cioh_cluster["co_spent_threat_address"]))

    # 6. Graph topological & behavioral heuristics
    fan = fan_in_out_ratio(graph, target_address)
    scam_aggregator = detect_scam_aggregator(graph, target_address, onchain_summary)
    exch_conf = exchange_confidence(graph, target_address, onchain_summary, threat_match)
    whale_info = detect_whale_profile(graph, target_address, onchain_summary)
    dusting_info = detect_dusting_attacks(graph, target_address, onchain_summary)
    taint = taint_score(
        graph,
        target_address,
        all_known_bad,
        onchain_summary=onchain_summary,
    )

    # 7. Extract intel flags
    is_intel_flagged = threat_match["is_illicit"] or cioh_cluster.get("has_co_spent_threat", False)
    intel_sources = []
    if threat_match["source"]:
        intel_sources.append(threat_match["source"])
    if cioh_cluster.get("has_co_spent_threat") and cioh_cluster.get("co_spent_threat_source"):
        intel_sources.append(f"CIOH Co-Spend ({cioh_cluster['co_spent_threat_source']})")

    intel_reasons = []
    if threat_match["description"]:
        intel_reasons.append(threat_match["description"])
    if cioh_cluster.get("has_co_spent_threat"):
        intel_reasons.append(
            f"Co-spent inputs in multi-input transaction with {cioh_cluster.get('co_spent_threat_entity')}"
        )

    return {
        "exchange_confidence": exch_conf,
        "fan_in": fan["fan_in"],
        "fan_out": fan["fan_out"],
        "fan_ratio": fan["ratio"],
        "mixer_pattern_detected": fan["is_suspicious"] and exch_conf < 65 and not whale_info.get("is_whale", False),
        "scam_aggregator_detected": scam_aggregator,
        "whale_profile": whale_info,
        "dusting_profile": dusting_info,
        "cioh_cluster": cioh_cluster,
        "taint_score": taint,
        "ofac_flagged": is_ofac,
        "threat_intel_match": threat_match,
        "intel_flagged": is_intel_flagged,
        "intel_sources": intel_sources,
        "intel_reasons": intel_reasons,
        "onchain_summary": onchain_summary,
    }


if __name__ == "__main__":
    g = nx.DiGraph()
    g.add_edge("149w62rY42aZBox8fGcmqNsXUzSStKeq8C", "intermediary", weight=5.0)
    g.add_edge("intermediary", "target_wallet", weight=3.0)
    g.add_edge("clean_source", "target_wallet", weight=2.0)

    res = compute_all_heuristics(g, "target_wallet")
    print("Heuristic results for target_wallet:")
    for k, v in res.items():
        print(f"  {k}: {v}")
