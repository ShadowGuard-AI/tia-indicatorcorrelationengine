import argparse
import logging
import requests
import json
from datetime import datetime, timezone
from dateutil import parser

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define API endpoints (replace with actual API keys and URLs)
VT_API_URL = "https://www.virustotal.com/api/v3/files/{}/relationships/behaviours"  # Example: VirusTotal file behaviors API
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your VirusTotal API key
OTX_API_URL = "https://otx.alienvault.com/api/v1/indicator/file/{}"  # Example: AlienVault OTX file indicator API
OTX_API_KEY = "YOUR_OTX_API_KEY" # Replace with your AlienVault OTX API Key

# Error handling decorator
def handle_errors(func):
    """Decorator for handling exceptions within functions."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            return None
    return wrapper

@handle_errors
def fetch_virustotal_data(file_hash):
    """Fetches data from VirusTotal for a given file hash.

    Args:
        file_hash (str): The MD5, SHA1, or SHA256 hash of the file.

    Returns:
        dict: A dictionary containing the VirusTotal data, or None on error.
    """
    headers = {"x-apikey": VT_API_KEY}
    url = VT_API_URL.format(file_hash)
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from VirusTotal: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from VirusTotal: {e}")
        return None

@handle_errors
def fetch_otx_data(file_hash):
    """Fetches data from AlienVault OTX for a given file hash.

    Args:
        file_hash (str): The MD5, SHA1, or SHA256 hash of the file.

    Returns:
        dict: A dictionary containing the OTX data, or None on error.
    """
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = OTX_API_URL.format(file_hash)
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from OTX: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from OTX: {e}")
        return None

@handle_errors
def correlate_indicators(vt_data, otx_data):
    """Correlates threat indicators from VirusTotal and AlienVault OTX.

    Args:
        vt_data (dict): The VirusTotal data.
        otx_data (dict): The AlienVault OTX data.

    Returns:
        dict: A dictionary containing the correlated indicators.
    """
    correlated_data = {}

    # Example: Correlate domains contacted
    vt_domains = set()
    if vt_data and 'data' in vt_data:
      for item in vt_data['data']:
        if item['type'] == 'analysis':
          if 'attributes' in item and 'domains' in item['attributes']:
              vt_domains.update(item['attributes']['domains'])

    otx_domains = set()
    if otx_data and 'General' in otx_data and 'domain' in otx_data['General']:
        otx_domains = set(otx_data['General']['domain'])

    common_domains = vt_domains.intersection(otx_domains)
    if common_domains:
        correlated_data["common_domains"] = list(common_domains)

    # Example: Correlate IPs
    vt_ips = set()
    if vt_data and 'data' in vt_data:
      for item in vt_data['data']:
        if item['type'] == 'analysis':
          if 'attributes' in item and 'ip_addresses' in item['attributes']:
              vt_ips.update(item['attributes']['ip_addresses'])

    otx_ips = set()
    if otx_data and 'General' in otx_data and 'pulse_info' in otx_data and 'related' in otx_data['General']['pulse_info']:
        for pulse in otx_data['General']['pulse_info']['related']:
            if 'indicators' in pulse:
                for indicator in pulse['indicators']:
                    if indicator['type'] == 'IPv4':
                        otx_ips.add(indicator['indicator'])

    common_ips = vt_ips.intersection(otx_ips)
    if common_ips:
        correlated_data["common_ips"] = list(common_ips)

    return correlated_data

def setup_argparse():
    """Sets up the argparse for the command-line interface."""
    parser = argparse.ArgumentParser(description="Correlates threat indicators from VirusTotal and AlienVault OTX.")
    parser.add_argument("file_hash", help="The MD5, SHA1, or SHA256 hash of the file.")
    return parser.parse_args()

def main():
    """Main function to execute the threat intelligence correlation."""
    args = setup_argparse()
    file_hash = args.file_hash

    # Input Validation
    if not isinstance(file_hash, str) or not file_hash:
        logging.error("Invalid file hash provided.")
        return

    logging.info(f"Analyzing file hash: {file_hash}")

    # Fetch data from VirusTotal and AlienVault OTX
    vt_data = fetch_virustotal_data(file_hash)
    otx_data = fetch_otx_data(file_hash)

    if vt_data:
        logging.info("VirusTotal data fetched successfully.")
    else:
        logging.warning("Failed to fetch VirusTotal data.")

    if otx_data:
        logging.info("OTX data fetched successfully.")
    else:
        logging.warning("Failed to fetch OTX data.")

    # Correlate indicators
    if vt_data or otx_data:
        correlated_data = correlate_indicators(vt_data, otx_data)

        if correlated_data:
            print("Correlated Threat Indicators:")
            print(json.dumps(correlated_data, indent=4))
        else:
            print("No correlated indicators found.")
    else:
        print("No data fetched from VirusTotal or OTX.  Cannot correlate.")

if __name__ == "__main__":
    # Example Usage:
    # python main.py <file_hash>
    # (Replace <file_hash> with a real file hash)
    main()