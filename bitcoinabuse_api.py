"""
BitcoinAbuse API Integration

Crowdsourced database of reported Bitcoin scam, ransomware, and fraud addresses.
Checks if an address has been reported on BitcoinAbuse.com.

API Docs: https://www.bitcoinabuse.com/api-docs
"""

import requests
import time


BITCOINABUSE_API = "https://www.bitcoinabuse.com/api/reports/check"
REQUEST_DELAY = 0.3
HEADERS = {
    "User-Agent": "BitcoinRiskAnalyzer/1.0 (Hackathon Security Suite)"
}


def check_bitcoinabuse(address, api_token=None):
    """
    Check if a Bitcoin address has been reported to BitcoinAbuse.com.

    Returns:
        dict with:
            'is_reported': bool - True if address has abuse reports
            'report_count': int - Number of times reported
            'address': str
    """
    params = {'address': address}
    if api_token:
        params['api_token'] = api_token

    try:
        response = requests.get(
            BITCOINABUSE_API,
            params=params,
            headers=HEADERS,
            timeout=8
        )
        time.sleep(REQUEST_DELAY)

        if response.status_code == 200:
            data = response.json()
            report_count = data.get('count', 0)
            return {
                'is_reported': report_count > 0,
                'report_count': report_count,
                'address': address
            }
        else:
            return {'is_reported': False, 'report_count': 0, 'address': address}

    except (requests.RequestException, ValueError, KeyError):
        return {'is_reported': False, 'report_count': 0, 'address': address}


def is_reported_criminal(address):
    """
    Simple boolean check: Has this address been reported for criminal activity?
    """
    result = check_bitcoinabuse(address)
    return result['is_reported']


if __name__ == "__main__":
    test_address = "1EYitrwBYNWuTBcjZFbEUdqHppe2raLpaF"
    print(f"Checking {test_address} on BitcoinAbuse.com...")
    res = check_bitcoinabuse(test_address)
    print(f"Result: {res}")
