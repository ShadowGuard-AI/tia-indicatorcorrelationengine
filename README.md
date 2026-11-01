# tia-IndicatorCorrelationEngine
Identifies and correlates related threat indicators across different sources to enhance confidence and provide contextual information. - Focused on Collects and aggregates threat intelligence from various open-source feeds and APIs (e.g., VirusTotal, AlienVault OTX) to provide a consolidated view of potential threats. Allows filtering and correlation based on indicators such as IP addresses, domains, and file hashes.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-indicatorcorrelationengine`

## Setup
Set both API keys in the environment before running. Keys are sent in request headers only and are never read from source files.
- `VT_API_KEY`: VirusTotal API key
- `OTX_API_KEY`: AlienVault OTX API key

If a key is not set, that source is skipped with a stated reason and the run is reported as partial. If neither source returns data, the run exits non-zero and prints no correlation result.

## Usage
`python main.py <file_hash>`

## Parameters
- `file_hash` (required, positional): The MD5, SHA1, or SHA256 hash of the file to correlate (32, 40, or 64 hex characters). An empty or invalid hash is rejected with a non-zero exit.
- `-h`: Show help message and exit

## License
Copyright (c) ShadowGuard-AI
