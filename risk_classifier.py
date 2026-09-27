"""
Step 5: Multi-Signal Risk Classifier with Threat Intelligence & Behavioral Attribution.

What this does:
  1. Integrates ML model illicit probability (0.0 to 1.0)
  2. Integrates heuristic scores, graph topology, and on-chain UTXO statistics
  3. Integrates verified threat intelligence (OFAC, Ransomware, Hack/Theft databases)
  4. Produces a calibrated risk score (0-100) with hard-floor guarantees for verified threats
  5. Maps score + evidence into clear, actionable risk categories
  6. Generates comprehensive forensic evidence strings for investigative reporting
"""

# ---- Weight Configuration ----
WEIGHTS = {
    "ml_score": 0.35,              # 35% weight: ML model graph topology prediction
    "taint_score": 0.25,           # 25% weight: traced funds from known illicit nodes
    "ofac_penalty": 0.15,          # 15% weight: OFAC sanctions match
    "threat_intel_penalty": 0.15,  # 15% weight: verified threat intelligence / DOJ / CISA
    "mixer_aggregator_penalty": 0.10, # 10% weight: mixing or scam aggregator pattern
    "exchange_discount": 0.05,     # 5% discount: for verified/high-confidence compliant exchanges
}


# ---- Prioritized Risk Categories ----
CATEGORIES = [
    {
        "name": "linked to sanctioned entity / state-sponsored cybercrime",
        "condition": lambda score, evidence, h: (
            h.get("ofac_flagged", False)
            or h.get("threat_intel_match", {}).get("category") in ["sanctions", "state_sponsored_cybercrime"]
            or h.get("cioh_cluster", {}).get("co_spent_threat_category") in ["sanctions", "state_sponsored_cybercrime"]
        ),
        "priority": 1,
    },
    {
        "name": "verified ransomware campaign / extortion",
        "condition": lambda score, evidence, h: (
            h.get("threat_intel_match", {}).get("category") in ["ransomware", "ransomware_laundering"]
            or h.get("cioh_cluster", {}).get("co_spent_threat_category") in ["ransomware", "ransomware_laundering"]
        ),
        "priority": 2,
    },
    {
        "name": "linked to theft / hack proceeds",
        "condition": lambda score, evidence, h: (
            h.get("threat_intel_match", {}).get("category") in ["exchange_hack", "theft_scam", "darknet_seized", "darknet_market"]
            or h.get("cioh_cluster", {}).get("co_spent_threat_category") in ["exchange_hack", "theft_scam", "darknet_seized", "darknet_market"]
            or h.get("taint_score", 0) >= 30
        ),
        "priority": 3,
    },
    {
        "name": "known scam / abuse reported",
        "condition": lambda score, evidence, h: (
            h.get("threat_intel_match", {}).get("category") in ["scam", "scam_distribution"]
            or h.get("cioh_cluster", {}).get("co_spent_threat_category") in ["scam", "scam_distribution"]
            or h.get("intel_flagged", False)
        ),
        "priority": 4,
    },
    {
        "name": "scam / extortion aggregator pattern",
        "condition": lambda score, evidence, h: (
            h.get("scam_aggregator_detected", False) and score >= 50
        ),
        "priority": 5,
    },
    {
        "name": "likely money laundering / mixing service",
        "condition": lambda score, evidence, h: (
            (h.get("mixer_pattern_detected", False) or h.get("threat_intel_match", {}).get("category") == "sanctioned_mixer")
            and score >= 40
        ),
        "priority": 6,
    },
    {
        "name": "high risk suspicious activity",
        "condition": lambda score, evidence, h: score >= 65,
        "priority": 7,
    },
    {
        "name": "verified legitimate exchange / custodian",
        "condition": lambda score, evidence, h: (
            h.get("threat_intel_match", {}).get("is_exchange", False)
            or h.get("threat_intel_match", {}).get("category") == "historical_genesis"
            or (h.get("exchange_confidence", 0) >= 80 and not h.get("threat_intel_match", {}).get("is_illicit") and score < 25)
        ),
        "priority": 8,
    },
    {
        "name": "autonomous exchange hot wallet / commercial liquidity hub",
        "condition": lambda score, evidence, h: (
            h.get("exchange_confidence", 0) >= 65
            and not h.get("threat_intel_match", {}).get("is_illicit")
            and not h.get("ofac_flagged", False)
            and not h.get("cioh_cluster", {}).get("has_co_spent_threat", False)
            and h.get("taint_score", 0) < 20
            and score < 35
        ),
        "priority": 8.2,
    },
    {
        "name": "high-volume whale / institutional custody transit",
        "condition": lambda score, evidence, h: (
            h.get("whale_profile", {}).get("is_whale", False)
            and not h.get("threat_intel_match", {}).get("is_illicit")
            and not h.get("ofac_flagged", False)
            and not h.get("cioh_cluster", {}).get("has_co_spent_threat", False)
            and h.get("taint_score", 0) < 25
            and score < 40
        ),
        "priority": 8.5,
    },
    {
        "name": "inactive / unused address (no on-chain history)",
        "condition": lambda score, evidence, h: (
            h.get("onchain_summary", {}).get("tx_count", 0) == 0
            and h.get("fan_in", 0) == 0
            and h.get("fan_out", 0) == 0
            and score < 10
        ),
        "priority": 9,
    },
    {
        "name": "low risk",
        "condition": lambda score, evidence, h: score < 30,
        "priority": 10,
    },
    {
        "name": "moderate risk — inconclusive",
        "condition": lambda score, evidence, h: True,  # Fallback
        "priority": 11,
    },
]


def build_evidence_list(ml_probability, heuristics):
    """
    Generate clear, human-readable forensic evidence explanations.
    """
    evidence = []
    threat_info = heuristics.get("threat_intel_match", {})
    summary = heuristics.get("onchain_summary", {})

    # 1. Verified Threat Intelligence & Entity Attribution
    if threat_info.get("is_known"):
        entity = threat_info.get("entity", "Unknown Entity")
        cat = threat_info.get("category", "threat_intel")
        desc = threat_info.get("description", "")
        source = threat_info.get("source", "Verified Threat Intel Database")

        if threat_info.get("is_exchange") or cat == "historical_genesis":
            evidence.append(f"Entity Attribution [{source}]: {entity} — {desc}")
        else:
            evidence.append(f"THREAT INTEL MATCH [{source}]: {entity} ({cat.upper()}) — {desc}")

    # 2. OFAC Sanctions Match
    if heuristics.get("ofac_flagged", False):
        evidence.append("OFAC SANCTIONS: Address appears on the US Treasury Specially Designated Nationals (SDN) List")

    # 3. Taint Score & Proportional Fund Propagation
    taint = heuristics.get("taint_score", 0)
    if taint >= 50:
        evidence.append(f"Critical Taint: {taint:.1f}% of incoming funds directly traced back to illicit/sanctioned wallets")
    elif taint >= 5:
        evidence.append(f"Moderate Taint: {taint:.1f}% of incoming funds linked to known-bad addresses")

    # 4. Behavioral Scam Aggregator Detection (for new / unseen scams)
    if heuristics.get("scam_aggregator_detected", False):
        evidence.append(
            "Scam Aggregator Pattern Detected: Rapid fund consolidation from multiple victim wallets "
            "followed by swift sweeping/redistribution of deposited assets."
        )

    # 5. Mixer / Tumbler Signature
    if heuristics.get("mixer_pattern_detected", False):
        fan_in = heuristics.get("fan_in", 0)
        fan_out = heuristics.get("fan_out", 0)
        ratio = heuristics.get("fan_ratio", 0.0)
        evidence.append(
            f"Mixer/Tumbler Signature: High symmetric fan-in/fan-out passthrough (fan-in={fan_in}, fan-out={fan_out}, ratio={ratio:.2f})"
        )

    # 6. ML Behavioral Model Score
    if ml_probability >= 0.70:
        evidence.append(f"ML Model: Flags graph topology as {ml_probability*100:.1f}% likely illicit based on structural features")
    elif ml_probability >= 0.45:
        evidence.append(f"ML Model: Elevated illicit probability of {ml_probability*100:.1f}% based on transaction network profile")
    elif ml_probability <= 0.20 and not threat_info.get("is_illicit"):
        evidence.append(f"ML Model: Graph topology exhibits normal licit transaction behavior ({ml_probability*100:.1f}% illicit prob)")

    # 7. On-Chain Summary Statistics & Taint
    tx_count = summary.get("tx_count", 0)
    funded_btc = summary.get("funded_btc", 0.0)
    spent_btc = summary.get("spent_btc", 0.0)
    balance_btc = summary.get("current_balance_btc", 0.0)
    taint_pct = heuristics.get("taint_score", 0.0)

    # Mempool live activity note
    if summary.get("has_mempool_activity"):
        m_tx = summary.get("mempool_tx_count", 0)
        m_btc = summary.get("mempool_funded_btc", 0.0)
        evidence.append(
            f"LIVE MEMPOOL ACTIVITY: Detected {m_tx} pending/unconfirmed transaction(s) in the mempool."
        )

    if tx_count == 0:
        if heuristics.get("fan_in", 0) == 0 and heuristics.get("fan_out", 0) == 0:
            evidence.append("On-Chain Activity: 0 transactions recorded on the Bitcoin mainnet (inactive/unfunded address)")
    else:
        evidence.append(
            f"On-Chain Activity: {tx_count:,} txs | Total Received: {funded_btc:.4f} BTC | "
            f"Balance: {balance_btc:.4f} BTC | Taint: {taint_pct:.1f}%"
        )

    # 8. Whale / Institutional Custody & Vault Movement
    whale = heuristics.get("whale_profile", {})
    if whale.get("is_whale"):
        if whale.get("is_transit"):
            evidence.append(
                f"Whale / Custody Transit: High-volume movement of {whale['total_volume_btc']:,.2f} BTC with "
                f"{summary.get('liquidation_ratio', 1.0)*100:.1f}% consolidated and swept downstream."
            )
            if whale.get("top_destination"):
                evidence.append(
                    f"Destination Vault: {whale['top_destination_btc']:,.2f} BTC "
                    f"({whale['top_destination_pct']:.1f}% of volume) transferred to {whale['top_destination']}."
                )
        elif whale.get("is_vault"):
            evidence.append(
                f"Whale Vault Holding: Active custody balance of {whale['current_balance_btc']:,.2f} BTC."
            )

    # 9. Dusting Attack & Surveillance Infiltration
    dust = heuristics.get("dusting_profile", {})
    if dust.get("dusting_detected"):
        evidence.append(
            f"Dusting Attack Infiltration: Detected {dust['dust_tx_count']} micro-dust transaction(s) "
            f"(<= 0.00001 BTC / 546-1000 satoshis), indicative of de-anonymization and wallet clustering attempts."
        )

    # 10. Exchange Confidence & Autonomous Discovery
    exchange_conf = heuristics.get("exchange_confidence", 0)
    if exchange_conf >= 70 and not threat_info.get("is_illicit"):
        if threat_info.get("is_exchange"):
            evidence.append(f"Exchange Profile: High-confidence legitimate exchange infrastructure ({exchange_conf}%)")
        else:
            evidence.append(
                f"Autonomous Exchange Discovery: High-velocity commercial liquidity hub ({exchange_conf}% confidence) "
                f"with macro turnover and continuous bidirectional counterparty flows."
            )
    elif exchange_conf >= 35 and not threat_info.get("is_illicit"):
        evidence.append(f"Service Profile: Active commercial counterparty ({exchange_conf}%)")

    # 11. Common-Input-Ownership Heuristic (CIOH) Entity Attribution
    cioh = heuristics.get("cioh_cluster", {})
    if cioh.get("has_co_spent_threat"):
        evidence.append(
            f"COMMON-INPUT-OWNERSHIP (CIOH) MATCH: Wallet co-spent inputs in multi-input transaction with "
            f"{cioh.get('co_spent_threat_entity')} ({cioh.get('co_spent_threat_category', '').upper()} - {cioh.get('co_spent_threat_address')}). "
            f"Forensic proof of shared private key ownership."
        )
    elif cioh.get("cluster_size", 1) > 1 and not threat_info.get("is_illicit"):
        evidence.append(
            f"Entity Clustering (CIOH): Clustered with {cioh['cluster_size']} co-spent address(es) across "
            f"{cioh.get('co_spent_tx_count', 0)} multi-input txs ({cioh.get('coinjoin_filtered_count', 0)} CoinJoin txs filtered)."
        )

    return evidence


def compute_final_score(ml_probability, heuristics):
    """
    Combine all signals into a calibrated score (0-100) with threat intelligence hard floors.
    """
    threat_info = heuristics.get("threat_intel_match", {})
    summary = heuristics.get("onchain_summary", {})
    cioh = heuristics.get("cioh_cluster", {})

    # Safe entities (Genesis / Verified Exchange Vaults) get 0 risk
    if threat_info.get("is_exchange") or threat_info.get("category") == "historical_genesis":
        return 0.0

    # Inactive addresses with 0 transactions, no graph activity, and no threat intel match get 0 risk
    has_graph_activity = (
        heuristics.get("fan_in", 0) > 0
        or heuristics.get("fan_out", 0) > 0
        or heuristics.get("taint_score", 0) > 0
        or heuristics.get("mixer_pattern_detected", False)
        or heuristics.get("scam_aggregator_detected", False)
        or cioh.get("has_co_spent_threat", False)
    )
    if summary.get("tx_count", 0) == 0 and not has_graph_activity and not threat_info.get("is_illicit") and not heuristics.get("ofac_flagged"):
        return 0.0

    # Component calculations
    ml_comp = ml_probability * 100 * WEIGHTS["ml_score"]
    taint_comp = heuristics.get("taint_score", 0) * WEIGHTS["taint_score"]
    ofac_comp = (100 if heuristics.get("ofac_flagged", False) else 0) * WEIGHTS["ofac_penalty"]

    intel_penalty = 0
    if threat_info.get("is_illicit"):
        severity = threat_info.get("severity", "medium")
        if severity == "critical":
            intel_penalty = 100
        elif severity == "high":
            intel_penalty = 85
        else:
            intel_penalty = 65
    intel_comp = intel_penalty * WEIGHTS["threat_intel_penalty"]

    mixer_aggregator_val = 0
    if heuristics.get("mixer_pattern_detected", False):
        mixer_aggregator_val = 100
    elif heuristics.get("scam_aggregator_detected", False):
        mixer_aggregator_val = 80
    mixer_comp = mixer_aggregator_val * WEIGHTS["mixer_aggregator_penalty"]

    exchange_comp = heuristics.get("exchange_confidence", 0) * WEIGHTS["exchange_discount"]

    raw_score = ml_comp + taint_comp + ofac_comp + intel_comp + mixer_comp - exchange_comp

    # --- HARD FLOORS FOR VERIFIED THREATS & CIOH CLUSTER THREATS ---
    if heuristics.get("ofac_flagged", False) or threat_info.get("severity") == "critical":
        raw_score = max(raw_score, 95.0)
    elif threat_info.get("severity") == "high":
        raw_score = max(raw_score, 85.0)
    elif threat_info.get("is_illicit"):
        raw_score = max(raw_score, 75.0)
    elif heuristics.get("scam_aggregator_detected", False):
        raw_score = max(raw_score, 70.0)
    elif heuristics.get("mixer_pattern_detected", False) and (ml_probability >= 0.50 or heuristics.get("taint_score", 0) >= 30):
        raw_score = max(raw_score, 65.0)

    # CIOH Co-Spent Criminal Entity Hard Floors
    if cioh.get("has_co_spent_threat"):
        cioh_sev = cioh.get("co_spent_threat_severity", "high")
        if cioh_sev == "critical" or cioh.get("co_spent_threat_category") in ["sanctions", "state_sponsored_cybercrime", "ransomware"]:
            raw_score = max(raw_score, 95.0)
        elif cioh_sev == "high":
            raw_score = max(raw_score, 85.0)
        else:
            raw_score = max(raw_score, 75.0)

    return round(max(0.0, min(100.0, raw_score)), 1)


def determine_category(score, evidence, heuristics):
    """
    Determine the most specific risk category in priority order.
    """
    sorted_categories = sorted(CATEGORIES, key=lambda c: c["priority"])
    for cat in sorted_categories:
        if cat["condition"](score, evidence, heuristics):
            return cat["name"]
    return "moderate risk — inconclusive"


def classify_risk(ml_probability, heuristic_scores):
    """
    Main risk classification function.

    Args:
        ml_probability: float 0.0-1.0 from Random Forest model
        heuristic_scores: dict from heuristics.compute_all_heuristics()

    Returns:
        dict with:
          'risk_score':    float 0.0-100.0
          'risk_category': string
          'evidence':      list of explanatory strings
    """
    evidence = build_evidence_list(ml_probability, heuristic_scores)
    score = compute_final_score(ml_probability, heuristic_scores)
    category = determine_category(score, evidence, heuristic_scores)

    return {
        "risk_score": score,
        "risk_category": category,
        "evidence": evidence,
    }


if __name__ == "__main__":
    test_h = {
        "exchange_confidence": 0,
        "fan_in": 15,
        "fan_out": 1,
        "fan_ratio": 15.0,
        "mixer_pattern_detected": False,
        "scam_aggregator_detected": True,
        "taint_score": 10.0,
        "ofac_flagged": False,
        "threat_intel_match": {
            "is_known": True,
            "is_illicit": True,
            "entity": "Twitter 2020 VIP Hack",
            "category": "theft_scam",
            "severity": "critical",
            "description": "July 2020 Twitter VIP account takeover scam address",
            "source": "US DOJ / Secret Service",
        },
        "onchain_summary": {
            "tx_count": 384,
            "funded_btc": 12.86,
            "spent_btc": 12.86,
            "current_balance_btc": 0.0,
        }
    }
    res = classify_risk(0.65, test_h)
    print("Risk Classification Test:")
    print(f"  Score:    {res['risk_score']}")
    print(f"  Category: {res['risk_category']}")
    print("  Evidence:")
    for e in res["evidence"]:
        print(f"    - {e}")
