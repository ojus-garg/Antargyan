"""
ANTARGYAN — Advanced Blockchain Intelligence & Forensic Suite
Streamlit Cyber Defense & Forensic Investigation Console

A pure Python reactive frontend providing sovereign-grade blockchain intelligence,
multi-hop graph traversal, continuous taint propagation, and ML typology classification.
"""

import os
import json
import time
from datetime import datetime
import streamlit as st
import pandas as pd
from PIL import Image

# Import the core analysis engine (100% untouched)
from analyze import analyze_wallet
from threat_intel import VERIFIED_ENTITIES

# Page configuration
st.set_page_config(
    page_title="ANTARGYAN // Forensic Intelligence Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Reference intelligence catalogue for one-click investigative demonstrations
PRESETS = [
    {
        "id": "custom",
        "name": "⚙ Custom Target Investigation",
        "address": "",
        "badge": "MANUAL ENTRY",
        "severity": "neutral",
        "description": "Enter any custom Bitcoin P2PKH, P2SH, SegWit, or Taproot address."
    },
    {
        "id": "sanctions_lazarus",
        "name": "🚨 Lazarus Group (DPRK State Actors)",
        "address": "149w62rY42aZBox8fGcmqNsXUzSStKeq8C",
        "badge": "OFAC SANCTIONS",
        "severity": "critical",
        "description": "North Korean state cyber laundering node linked to Ronin & Harmony bridge exploits."
    },
    {
        "id": "ransomware_wannacry",
        "name": "💀 WannaCry Ransomware",
        "address": "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",
        "badge": "RANSOMWARE",
        "severity": "critical",
        "description": "Primary Bitcoin ransom payment address from the May 2017 global extortion campaign."
    },
    {
        "id": "scam_twitter_hack",
        "name": "🎭 Twitter 2020 VIP Hijack Scam",
        "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        "badge": "THEFT / SCAM",
        "severity": "critical",
        "description": "High-profile social engineering extortion aggregator (Obama, Musk, Apple)."
    },
    {
        "id": "theft_bitfinex",
        "name": "🔓 Bitfinex 2016 Hack Repository",
        "address": "1Cdid9KFAaatwczBwBttQcwXYCpvK8h7FK",
        "badge": "EXCHANGE HACK",
        "severity": "critical",
        "description": "119,756 BTC security breach repository seized by US Department of Justice."
    },
    {
        "id": "safe_satoshi",
        "name": "💎 Satoshi Nakamoto Genesis Vault",
        "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "badge": "GENESIS BLOCK",
        "severity": "safe",
        "description": "Block #0 coinbase reward address mined on January 3, 2009 (0% Taint)."
    },
    {
        "id": "safe_binance",
        "name": "🏦 Binance Cold Storage Vault #1",
        "address": "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
        "badge": "VERIFIED EXCHANGE",
        "severity": "safe",
        "description": "Verified Binance cold storage reserve holding institutional Bitcoin reserves."
    },
    {
        "id": "inactive_sample",
        "name": "⚪ Clean Inactive Address",
        "address": "1NcZWVGVfKSgJuEpLCQE78Kje2upvzhN9v",
        "badge": "INACTIVE / ZERO TX",
        "severity": "safe",
        "description": "Valid Bitcoin address with 0 on-chain transactions."
    },
    {
        "id": "foreign_eth",
        "name": "⚡ Vitalik Buterin (Ethereum EVM)",
        "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "badge": "FOREIGN CHAIN",
        "severity": "warning",
        "description": "Non-Bitcoin Ethereum public address to test cross-chain intelligence detection."
    }
]

# Custom CSS styling for Agency-Grade UI
st.markdown("""
<style>
    /* Global Typography & Palette */
    @import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    .stApp {
        background-color: #060911;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Top Security Banner */
    .sec-banner {
        background: linear-gradient(90deg, #b71c1c 0%, #1a0000 50%, #b71c1c 100%);
        color: #ffffff;
        text-align: center;
        padding: 6px 12px;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 2.5px;
        border-bottom: 1px solid #ff1744;
        margin-bottom: 20px;
        border-radius: 4px;
    }

    /* Header Container */
    .agency-title {
        font-family: 'Chakra Petch', sans-serif;
        color: #00e5ff;
        font-size: 2.2rem;
        font-weight: 700;
        letter-spacing: 2px;
        margin-bottom: 2px;
        text-shadow: 0 0 15px rgba(0, 229, 255, 0.4);
    }

    .agency-sub {
        color: #94a3b8;
        font-size: 0.85rem;
        letter-spacing: 1px;
        margin-bottom: 20px;
    }

    /* Threat Classification Banners */
    .banner-critical {
        background: rgba(255, 23, 68, 0.15);
        border: 1px solid #ff1744;
        border-left: 6px solid #ff1744;
        padding: 14px 18px;
        border-radius: 4px;
        color: #ff5252;
        font-weight: 700;
        margin: 15px 0;
    }

    .banner-warning {
        background: rgba(255, 171, 0, 0.15);
        border: 1px solid #ffab00;
        border-left: 6px solid #ffab00;
        padding: 14px 18px;
        border-radius: 4px;
        color: #ffd740;
        font-weight: 700;
        margin: 15px 0;
    }

    .banner-safe {
        background: rgba(0, 230, 118, 0.12);
        border: 1px solid #00e676;
        border-left: 6px solid #00e676;
        padding: 14px 18px;
        border-radius: 4px;
        color: #69f0ae;
        font-weight: 700;
        margin: 15px 0;
    }

    .banner-neutral {
        background: rgba(0, 229, 255, 0.12);
        border: 1px solid #00e5ff;
        border-left: 6px solid #00e5ff;
        padding: 14px 18px;
        border-radius: 4px;
        color: #00e5ff;
        font-weight: 700;
        margin: 15px 0;
    }

    /* Intel Box */
    .intel-box {
        background: #0d1527;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 16px;
        margin: 15px 0;
    }

    /* Badges */
    .badge-tag {
        display: inline-block;
        padding: 2px 8px;
        font-size: 0.75rem;
        font-weight: 700;
        border-radius: 3px;
        margin-right: 6px;
    }
    .badge-ofac { background: #b71c1c; color: #fff; }
    .badge-cat { background: #0288d1; color: #fff; }
</style>
""", unsafe_allow_html=True)

# Top Banner
st.markdown("""
<div class="sec-banner">
    TOP SECRET // LE-SENSITIVE // NOFORN // SPECIAL FINANCIAL CYBERCRIMES DIVISION
</div>
""", unsafe_allow_html=True)

# App Header
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown("""
    <div class="agency-title">ANTARGYAN</div>
    <div class="agency-sub">ADVANCED BLOCKCHAIN INTELLIGENCE & FORENSIC SUITE // STREAMLIT OPERATIONS CONSOLE</div>
    """, unsafe_allow_html=True)

with col_h2:
    utc_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    st.markdown(f"""
    <div style="text-align: right; color: #00e5ff; font-size: 0.8rem; padding-top: 10px;">
        <div><strong>SYSTEM:</strong> OPERATIONAL</div>
        <div><strong>NETWORK:</strong> BTC MAINNET</div>
        <div><strong>ZULU TIME:</strong> {utc_now}</div>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# ==============================================================================
# SIDEBAR: PARAMETERS & INTELLIGENCE CATALOGUE
# ==============================================================================
with st.sidebar:
    st.markdown("### 🎛️ INVESTIGATION PARAMETERS")

    # Preset Selector
    preset_names = [p["name"] for p in PRESETS]
    selected_preset_name = st.selectbox(
        "Intelligence Presets:",
        options=preset_names,
        index=1  # Default to Lazarus Group
    )

    selected_preset = next(p for p in PRESETS if p["name"] == selected_preset_name)
    if selected_preset["id"] != "custom":
        st.info(f"**{selected_preset['badge']}**\n\n{selected_preset['description']}")

    st.markdown("---")
    st.markdown("### 🔍 GRAPH TRACE DEPTH")
    max_hops = st.slider(
        "Max Hops Depth:",
        min_value=1,
        max_value=5,
        value=3,
        help="Levels of transaction counterparties to recursively trace."
    )

    max_fanout = st.slider(
        "Fan-Out Per Hop:",
        min_value=1,
        max_value=15,
        value=5,
        help="Maximum high-value transaction counterparties traced per hop."
    )

    st.markdown("---")
    st.markdown("### 📊 SYSTEM TELEMETRY")
    st.markdown(f"- **Engine Model:** RF 166-Typology")
    st.markdown(f"- **Threat Intel DB:** {len(VERIFIED_ENTITIES)} Verified Records")
    st.markdown(f"- **Taint Decay (γ):** 0.88 / Hop")
    st.markdown(f"- **API Service:** Blockstream Mainnet")

# ==============================================================================
# MAIN QUERY INPUT
# ==============================================================================
default_addr = selected_preset["address"]

with st.container():
    st.markdown("#### 🎯 TARGET INVESTIGATION QUERY")

    col_input, col_btn = st.columns([5, 2])
    with col_input:
        target_address = st.text_input(
            "Bitcoin Target Address:",
            value=default_addr,
            placeholder="Enter P2PKH ('1...'), P2SH ('3...'), SegWit ('bc1q...'), or Taproot ('bc1p...')",
            label_visibility="collapsed"
        )
    with col_btn:
        run_scan = st.button("⚡ INITIATE FORENSIC SCAN", type="primary", use_container_width=True)

# Trigger scan when button is pressed or if address is ready
if run_scan and target_address.strip():
    addr = target_address.strip()

    # Status Pipeline Telemetry
    with st.status(f"Executing Forensic Pipeline for target: `{addr}`", expanded=True) as status:
        st.write("🔍 **[Stage 1/5]** Ingesting target address & checking OFAC/CISA Threat Intel...")
        time.sleep(0.4)
        st.write("⛓ **[Stage 2/5]** Querying Bitcoin mainnet UTXOs & expanding multi-hop graph...")
        time.sleep(0.4)
        st.write("☣ **[Stage 3/5]** Calculating continuous proportional taint propagation & exchange sinks...")
        time.sleep(0.4)
        st.write("🧠 **[Stage 4/5]** Extracting 166-dim topological graph features for Random Forest ML inference...")
        time.sleep(0.4)
        st.write("📊 **[Stage 5/5]** Synthesizing risk attribution & rendering Matplotlib network visualizations...")

        # Execute core backend analysis
        result = analyze_wallet(
            address=addr,
            max_hops=max_hops,
            max_addresses_per_hop=max_fanout
        )

        status.update(label=f"Forensic Investigation Complete for `{addr}`", state="complete", expanded=False)

    # Save to session state so view persists across widget interactions
    st.session_state["latest_result"] = result
    st.session_state["scan_time"] = datetime.utcnow().isoformat() + "Z"

# ==============================================================================
# DOSSIER PRESENTATION
# ==============================================================================
if "latest_result" in st.session_state:
    data = st.session_state["latest_result"]
    scan_timestamp = st.session_state.get("scan_time", "N/A")

    st.markdown("---")

    # 1. Target Overview & Threat Classification Banner
    score = data.get("risk_score", 0.0)
    category = data.get("risk_category", "UNKNOWN").upper()

    st.markdown(f"### 📑 FORENSIC DOSSIER // `{data.get('address', '')}`")
    st.caption(f"INVESTIGATION TIMESTAMP: {scan_timestamp} | TRACE CONFIGURATION: {max_hops} HOPS / {max_fanout} FANOUT")

    # Render stylized classification banner
    if score >= 80:
        banner_class = "banner-critical"
        icon = "🚨"
    elif score >= 50:
        banner_class = "banner-warning"
        icon = "⚠"
    elif "EXCHANGE" in category or "GENESIS" in category:
        banner_class = "banner-neutral"
        icon = "🏦"
    else:
        banner_class = "banner-safe"
        icon = "🛡️"

    st.markdown(f"""
    <div class="{banner_class}">
        {icon} <strong>CLASSIFICATION:</strong> {category} &nbsp;|&nbsp; <strong>RISK SCORE:</strong> {score:.1f} / 100
    </div>
    """, unsafe_allow_html=True)

    # Threat Intel Callout
    intel = data.get("threat_intel")
    if intel:
        st.markdown(f"""
        <div class="intel-box">
            <div>
                <span class="badge-tag badge-ofac">{intel.get('source', 'THREAT INTEL').upper()}</span>
                <span class="badge-tag badge-cat">{intel.get('category', 'ILLICIT').upper()}</span>
                <span style="color: #ff5252; font-weight: 700;">{intel.get('severity', 'CRITICAL').upper()} SEVERITY</span>
            </div>
            <h4 style="color: #00e5ff; margin: 8px 0 4px 0;">{intel.get('entity', 'Unknown Entity')}</h4>
            <p style="color: #94a3b8; font-size: 0.9rem; margin: 0;">{intel.get('description', '')}</p>
        </div>
        """, unsafe_allow_html=True)

    # 2. Four Primary Telemetry Metrics
    heuristics = data.get("heuristics", {})
    onchain = heuristics.get("onchain_summary", {})

    col_m1, col_m2, col_m3, col_m4 = st.columns(4)

    with col_m1:
        st.metric(
            label="⚡ COMPOSITE RISK SCORE",
            value=f"{score:.1f} / 100",
            delta="CRITICAL THREAT" if score >= 80 else ("ELEVATED" if score >= 40 else "SAFE / NORMAL"),
            delta_color="inverse" if score >= 40 else "normal"
        )
        st.progress(min(1.0, max(0.0, score / 100.0)))

    with col_m2:
        taint = float(heuristics.get("taint_score", 0.0))
        st.metric(
            label="☣ ILLICIT TAINT FLOW",
            value=f"{taint:.1f}%",
            delta="OFAC FLAGGED" if heuristics.get("ofac_flagged") else "CLEAN FLOW",
            delta_color="inverse" if heuristics.get("ofac_flagged") else "normal"
        )
        st.progress(min(1.0, max(0.0, taint / 100.0)))

    with col_m3:
        ml_prob = float(data.get("ml_probability", 0.0)) * 100.0
        st.metric(
            label="🧠 RANDOM FOREST ML",
            value=f"{ml_prob:.1f}%",
            delta=f"166-DIM TOPOLOGY",
            delta_color="off"
        )
        st.progress(min(1.0, max(0.0, ml_prob / 100.0)))

    with col_m4:
        txs = onchain.get("tx_count", 0)
        bal = onchain.get("current_balance_btc", 0.0)
        st.metric(
            label="⛓ ON-CHAIN ACTIVITY",
            value=f"{txs:,} TXs",
            delta=f"Balance: {bal:.4f} BTC",
            delta_color="off"
        )
        liq = onchain.get("liquidation_ratio", 0.0)
        st.progress(min(1.0, max(0.0, liq)))

    # 3. Behavioral Typology Grid
    st.markdown("#### 🔬 BEHAVIORAL TYPOLOGY & COUNTERPARTY HEURISTICS")
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        is_mixer = heuristics.get("mixer_pattern_detected", False)
        st.markdown(f"**MIXER / TUMBLER:**")
        if is_mixer:
            st.error("🚨 DETECTED (Symmetric Passthrough)")
        else:
            st.success("✔ NORMAL (No Tumbler)")

    with c2:
        is_scam = heuristics.get("scam_aggregator_detected", False)
        st.markdown(f"**SCAM AGGREGATOR:**")
        if is_scam:
            st.error("🚨 DETECTED (Multi-Victim Funnel)")
        else:
            st.success("✔ NORMAL (No Extortion Sweep)")

    with c3:
        exch_conf = heuristics.get("exchange_confidence", 0)
        st.markdown(f"**EXCHANGE INDEX:**")
        if exch_conf >= 65:
            st.info(f"🏦 {exch_conf}% (Verified Custodian)")
        else:
            st.markdown(f"👤 {exch_conf}% (Non-Exchange)")

    with c4:
        fan_ratio = heuristics.get("fan_ratio", 0.0)
        st.markdown(f"**DISPERSION RATIO:**")
        st.markdown(f"`{fan_ratio:.2f}` (In: {heuristics.get('fan_in', 0)} / Out: {heuristics.get('fan_out', 0)})")

    # 4. Forensic Evidence Log
    st.markdown("#### 📋 FORENSIC EVIDENCE & AUDIT TRAIL")
    evidence = data.get("evidence", [])
    if evidence:
        for idx, item in enumerate(evidence, 1):
            if any(k in item.lower() for k in ["sanction", "lazarus", "scam", "ransomware", "taint", "critical"]):
                st.error(f"**[REF-{idx:02d}]** {item}")
            else:
                st.markdown(f"- **[REF-{idx:02d}]** {item}")
    else:
        st.info("No illicit or high-risk evidence entries identified.")

    # 5. Visual Intelligence Viewport (Tabs)
    st.markdown("#### 🌐 VISUAL FORENSIC INTELLIGENCE")
    vis = data.get("visualizations", {})
    graph_stats = data.get("graph_stats", {})

    st.caption(f"TOPOLOGY METRICS: {graph_stats.get('nodes', 0)} NODES TRACED | {graph_stats.get('edges', 0)} ON-CHAIN FLOW EDGES")

    tab_graph, tab_hops, tab_raw = st.tabs(["🌐 Transaction Topology Graph", "📊 Multi-Hop Distribution", "📑 Raw Forensic Payload"])

    with tab_graph:
        graph_path = vis.get("graph_image")
        if graph_path and os.path.exists(graph_path):
            st.image(graph_path, caption=f"Network Topology Flow Diagram for {data.get('address')}", use_container_width=True)
        else:
            st.info("No graph image generated for this query.")

    with tab_hops:
        hop_path = vis.get("hop_chart")
        if hop_path and os.path.exists(hop_path):
            st.image(hop_path, caption=f"Multi-Hop Distance Histogram for {data.get('address')}", use_container_width=True)
        else:
            st.info("No hop chart generated for this query.")

    with tab_raw:
        st.json(data)

    # 6. Export Center
    st.markdown("---")
    st.markdown("#### 📥 EXPORT INVESTIGATION DOSSIER")

    col_exp1, col_exp2 = st.columns(2)
    with col_exp1:
        json_output = json.dumps(data, indent=2)
        st.download_button(
            label="💾 Download Forensic Dossier (JSON)",
            data=json_output,
            file_name=f"ANTARGYAN_DOSSIER_{data.get('address')}_{int(time.time())}.json",
            mime="application/json",
            use_container_width=True
        )
    with col_exp2:
        # Formatted plain text case report
        report_text = f"""======================================================================
ANTARGYAN // FORENSIC INTELLIGENCE DOSSIER
======================================================================
TARGET ADDRESS:     {data.get('address')}
TIMESTAMP:          {scan_timestamp}
RISK SCORE:         {score:.1f} / 100
CLASSIFICATION:     {category}
TAINT SCORE:        {heuristics.get('taint_score', 0.0)}%
ML ILLICIT PROB:    {float(data.get('ml_probability', 0.0))*100:.1f}%

EVIDENCE AUDIT TRAIL:
""" + "\n".join([f"  • {e}" for e in evidence]) + f"""

GRAPH TOPOLOGY:     {graph_stats.get('nodes', 0)} nodes, {graph_stats.get('edges', 0)} edges
======================================================================
"""
        st.download_button(
            label="📄 Download Official Investigation Report (.txt)",
            data=report_text,
            file_name=f"ANTARGYAN_CASE_REPORT_{data.get('address')}_{int(time.time())}.txt",
            mime="text/plain",
            use_container_width=True
        )

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #64748b; font-size: 0.75rem; padding: 10px 0;">
    ANTARGYAN BLOCKCHAIN INTELLIGENCE DIVISION &bull; RESTRICTED FOR LAW ENFORCEMENT & COMPLIANCE ANALYSTS &bull; NOFORN
</div>
""", unsafe_allow_html=True)
