"""
ANTARGYAN — Advanced Blockchain Intelligence & Forensic Suite
Flask Web Application & REST API Server

Wraps the core forensic engine (analyze_wallet) without modifying any underlying backend code.
Provides classified-grade web console and JSON APIs for on-chain intelligence investigations.
"""

import os
import sys
import traceback
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory

# Import the existing analysis engine (completely untouched)
from analyze import analyze_wallet
from threat_intel import VERIFIED_ENTITIES

# Resolve the React production build directory
REACT_DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "dist")
REACT_ASSETS = os.path.join(REACT_DIST, "assets")

app = Flask(
    __name__,
    static_folder=REACT_ASSETS,
    static_url_path="/assets",
)

# Ensure graphs directory exists
GRAPHS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "graphs")
if not os.path.exists(GRAPHS_DIR):
    os.makedirs(GRAPHS_DIR)

# Curated reference intelligence presets for one-click investigative demonstrations
PRESETS = [
    {
        "id": "sanctions_lazarus",
        "name": "Lazarus Group (DPRK State Actors)",
        "address": "149w62rY42aZBox8fGcmqNsXUzSStKeq8C",
        "badge": "OFAC SANCTIONS",
        "severity": "critical",
        "typology": "State Cyber Warfare / Heist Laundering",
        "description": "North Korean state-sponsored cyber laundering node associated with Ronin & Harmony bridge exploits."
    },
    {
        "id": "ransomware_wannacry",
        "name": "WannaCry Ransomware",
        "address": "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",
        "badge": "RANSOMWARE",
        "severity": "critical",
        "typology": "Global Extortion Campaign",
        "description": "Primary Bitcoin ransom payment address from the May 2017 global cyber outbreak."
    },
    {
        "id": "scam_twitter_hack",
        "name": "Twitter 2020 VIP Hijack Scam",
        "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        "badge": "THEFT / SCAM",
        "severity": "critical",
        "typology": "Social Engineering Aggregator",
        "description": "High-profile account takeover extortion aggregator (Obama, Musk, Apple)."
    },
    {
        "id": "extortion_blackmail_zeroday",
        "name": "Zero-Day Extortion / Blackmail Sweep",
        "address": "15cRqR3TXS1JehBGWERuxFE8NhWZzfoeeU",
        "badge": "NOVEL EXTORTION",
        "severity": "high",
        "typology": "Autonomous Behavioral ML Extortion Detection",
        "description": "Unlisted novel extortion wallet detected purely through graph topology, micro-deposit ransom tier, and 100% single-sweep liquidation."
    },
    {
        "id": "theft_bitfinex",
        "name": "Bitfinex 2016 Hack Repository",
        "address": "1Cdid9KFAaatwczBwBttQcwXYCpvK8h7FK",
        "badge": "EXCHANGE HACK",
        "severity": "critical",
        "typology": "Exchange Intrusion & Theft",
        "description": "119,756 BTC security breach repository seized by US Department of Justice."
    },
    {
        "id": "safe_satoshi",
        "name": "Satoshi Nakamoto Genesis Vault",
        "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "badge": "GENESIS BLOCK",
        "severity": "safe",
        "typology": "Historical Genesis / 0% Taint",
        "description": "Block #0 coinbase reward address mined on January 3, 2009."
    },
    {
        "id": "safe_binance",
        "name": "Binance Cold Storage Vault #1",
        "address": "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
        "badge": "VERIFIED EXCHANGE",
        "severity": "safe",
        "typology": "Regulated Institutional Custodian",
        "description": "Verified Binance cold storage reserve holding institutional Bitcoin reserves."
    },
    {
        "id": "inactive_sample",
        "name": "Clean Inactive Address",
        "address": "1NcZWVGVfKSgJuEpLCQE78Kje2upvzhN9v",
        "badge": "INACTIVE / ZERO TX",
        "severity": "safe",
        "typology": "Unused Keypair",
        "description": "Valid Bitcoin address with 0 on-chain transactions."
    },
    {
        "id": "foreign_eth",
        "name": "Vitalik Buterin (Ethereum EVM)",
        "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "badge": "FOREIGN CHAIN",
        "severity": "warning",
        "typology": "Ethereum EVM Address",
        "description": "Non-Bitcoin Ethereum public address to test cross-chain intelligence detection."
    }
]


def format_visualization_urls(visualizations):
    """Convert local filesystem paths into web-accessible URL paths."""
    if not isinstance(visualizations, dict):
        return {"graph_image": None, "hop_chart": None}

    urls = {}
    for key, path in visualizations.items():
        if path and isinstance(path, str):
            # Extract just the filename from the path
            filename = os.path.basename(path)
            urls[key] = f"/graphs/{filename}"
        else:
            urls[key] = None
    return urls


@app.route("/")
def index():
    """Serve the React production build."""
    return send_from_directory(REACT_DIST, "index.html")


@app.route("/api/presets", methods=["GET"])
def get_presets():
    """Return curated intelligence test cases."""
    return jsonify({
        "status": "success",
        "presets": PRESETS
    })


@app.route("/api/analyze", methods=["POST"])
def run_analysis():
    """
    Execute Bitcoin forensic risk analysis pipeline.
    Accepts JSON: { address: str, max_hops: int, max_addresses_per_hop: int }
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        address = data.get("address", "").strip()

        if not address:
            return jsonify({
                "status": "error",
                "message": "Target Bitcoin address or account identifier is required."
            }), 400

        # Parse and sanitize tracing depth & width
        try:
            max_hops = int(data.get("max_hops", 3))
            max_hops = max(1, min(max_hops, 5))
        except (ValueError, TypeError):
            max_hops = 3

        try:
            max_per_hop = int(data.get("max_addresses_per_hop", 5))
            max_per_hop = max(1, min(max_per_hop, 15))
        except (ValueError, TypeError):
            max_per_hop = 5

        # Execute analysis using existing core pipeline
        result = analyze_wallet(
            address=address,
            max_hops=max_hops,
            max_addresses_per_hop=max_per_hop
        )

        # Format local visualization image paths into web endpoints
        if "visualizations" in result:
            result["visualizations"] = format_visualization_urls(result["visualizations"])

        # Attach metadata for audit trail
        response_payload = {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "execution_params": {
                "max_hops": max_hops,
                "max_addresses_per_hop": max_per_hop
            },
            "data": result
        }

        return jsonify(response_payload)

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": f"Forensic analysis failed: {str(e)}"
        }), 500


@app.route("/graphs/<path:filename>")
def serve_graph(filename):
    """Serve dynamically generated forensic graph images."""
    return send_from_directory(GRAPHS_DIR, filename)


@app.route("/api/health", methods=["GET"])
def health_check():
    """System telemetry check."""
    return jsonify({
        "status": "operational",
        "system": "ANTARGYAN BLOCKCHAIN INTELLIGENCE ENGINE",
        "version": "4.2.0-DEFCON-SENSITIVE",
        "threat_intel_records": len(VERIFIED_ENTITIES),
        "graphs_dir": os.path.exists(GRAPHS_DIR)
    })


@app.route("/<path:filename>")
def serve_react_static(filename):
    """Serve root-level files from the React build (favicon.svg, icons.svg, etc.).
    This catch-all runs AFTER all explicit routes, so /api/* and /graphs/* are unaffected."""
    filepath = os.path.join(REACT_DIST, filename)
    if os.path.isfile(filepath):
        return send_from_directory(REACT_DIST, filename)
    # For any unknown path, return index.html (supports client-side routing)
    return send_from_directory(REACT_DIST, "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n" + "="*70)
    print(f"  ANTARGYAN // ADVANCED BLOCKCHAIN FORENSIC INTELLIGENCE SUITE")
    print(f"  SYSTEM STATUS: ONLINE & READY")
    print(f"  DASHBOARD URL: http://127.0.0.1:{port}")
    print(f"="*70 + "\n")
    app.run(host="127.0.0.1", port=port, debug=False)
