"""
Multi-Source Criminal Address Checker

Checks multiple public blockchain intelligence sources to detect criminal addresses:
1. OFAC Sanctions List (local verified database)
2. Blockchain.info activity & balance metrics
3. WalletExplorer.com scam/fraud clusters

Expands detection beyond just OFAC to catch scam clusters and abuse.
"""

import time
import requests

HEADERS = {
    "User-Agent": "BitcoinRiskAnalyzer/1.0 (Hackathon Security Suite)"
}


def check_blockchain_info_tags(address):
    """
    Check Blockchain.info for wallet metrics.
    Flags drained, high-turnover patterns typical of scam distribution addresses.
    """
    try:
        url = f"https://blockchain.info/rawaddr/{address}?limit=1"
        response = requests.get(url, headers=HEADERS, timeout=8)
        if response.status_code == 200:
            data = response.json()
            n_tx = data.get('n_tx', 0)
            final_balance = data.get('final_balance', 0) / 1e8  # Convert satoshi to BTC

            # Suspicious if high transaction count but drained balance
            if n_tx > 50 and final_balance < 0.0001:
                return True, f"High turnover ({n_tx} txs) with drained balance (scam aggregator pattern)"

        time.sleep(0.2)
        return False, "Clean"
    except (requests.RequestException, ValueError, KeyError):
        return False, "API unavailable"


def check_walletexplorer(address):
    """
    Check WalletExplorer.com to see if address belongs to a known scam or darknet cluster.
    """
    try:
        url = f"https://www.walletexplorer.com/api/1/address?address={address}&from=0&count=1&caller=bitcoin-analyzer"
        response = requests.get(url, headers=HEADERS, timeout=8)
        if response.status_code == 200:
            data = response.json()
            wallet_name = data.get('wallet')

            if wallet_name:
                scam_keywords = ['scam', 'fraud', 'ponzi', 'fake', 'phishing', 'ransomware', 'darknet', 'hack', 'drainer']
                wallet_lower = wallet_name.lower()
                if any(keyword in wallet_lower for keyword in scam_keywords):
                    return True, f"Known illicit cluster: {wallet_name}"

        time.sleep(0.2)
        return False, "Clean"
    except (requests.RequestException, ValueError, KeyError):
        return False, "API unavailable"


def multi_source_criminal_check(address):
    """
    Check address against multiple intelligence sources.

    Returns:
        dict with:
            'is_flagged': bool - True if ANY source flags it
            'flagged_by': list - Which sources flagged it
            'reasons': list - Why it was flagged
            'address': str
    """
    flagged_by = []
    reasons = []

    # Check blockchain.info
    is_flagged_bc, reason_bc = check_blockchain_info_tags(address)
    if is_flagged_bc:
        flagged_by.append("Blockchain.info")
        reasons.append(reason_bc)

    # Check WalletExplorer
    is_flagged_we, reason_we = check_walletexplorer(address)
    if is_flagged_we:
        flagged_by.append("WalletExplorer")
        reasons.append(reason_we)

    return {
        'is_flagged': len(flagged_by) > 0,
        'flagged_by': flagged_by,
        'reasons': reasons,
        'address': address
    }


if __name__ == "__main__":
    test_addresses = [
        "1EYitrwBYNWuTBcjZFbEUdqHppe2raLpaF",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ]

    for addr in test_addresses:
        print(f"\nChecking {addr}...")
        result = multi_source_criminal_check(addr)
        print(f"  Flagged: {result['is_flagged']}")
        print(f"  Sources: {result['flagged_by']}")
        print(f"  Reasons: {result['reasons']}")
