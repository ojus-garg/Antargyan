# Antargyan

**Real-Time Identification of Fraud-Linked Cryptocurrency Exchanges from Victim-Reported Suspect Wallet Addresses through Automated Blockchain Analytics**

Built for Smart India Hackathon 2026 — Problem Statement **SIH26183** (Software category).

## Overview

Antargyan is a blockchain forensic intelligence suite that traces suspect cryptocurrency wallet addresses across the blockchain graph, scores their risk, and flags links to known fraud, ransomware, and sanctioned entities — helping identify fraud-linked exchanges from victim-reported wallet addresses.

## Features

- Wallet risk classification using a trained ML model (`risk_classifier.py`, `wallet_risk_model.joblib`)
- Blockchain graph analysis and multi-hop transaction tracing (`blockchain_api.py`, `visualize_graph.py`)
- Threat intelligence matching against known malicious addresses (OFAC sanctions list, reported scam/ransomware wallets)
- Curated preset investigations (e.g. Lazarus Group, WannaCry ransomware, Twitter 2020 hijack scam) for quick demonstration
- Flask REST API backend serving a React frontend
- Standalone Streamlit dashboard for exploratory analysis

## Tech Stack

- **Backend:** Flask, scikit-learn, NetworkX, pandas, joblib
- **Analysis:** Custom heuristics engine + trained risk classifier
- **Frontend:** React (production build served via Flask)
- **Alt UI:** Streamlit app for quick analysis (`streamlit_app.py`)

## Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/ojus-garg/Antargyan.git
cd Antargyan
pip install -r requirements.txt
```

### Running the app

```bash
python app.py
```
or use the startup script:
```bash
./start.sh
```

For the Streamlit dashboard instead:
```bash
streamlit run streamlit_app.py
```

## Project Structure

```
app.py                  # Flask server & REST API
analyze.py              # Core wallet analysis engine
blockchain_api.py        # Blockchain data fetching
heuristics.py            # Rule-based risk heuristics
risk_classifier.py       # ML-based risk scoring
threat_intel.py          # Known threat entity matching
train_model.py            # Model training pipeline
streamlit_app.py         # Standalone Streamlit UI
graphs/                  # Generated transaction graph visualizations
```

## Team — Antargyan

- Ojus Garg
- Aaryan Pawar
- Arya Pathardikar
- Aradhya Gupta
- Nakul Vikas Dhoot
- Akshit Joglekar

**Mentor:** Dr. Amol Kamble

## Disclaimer

This project is a prototype built for SIH 2026 and is intended for educational/demonstration purposes. Wallet addresses used in presets are drawn from publicly reported cases.
