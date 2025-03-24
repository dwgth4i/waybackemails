import requests
import sys
import re
import json
import csv
from concurrent.futures import ThreadPoolExecutor

# Subdomain Enumeration
def get_crtsh_subdomains(domain):
    """Fetch subdomains from crt.sh"""
    url = f"https://crt.sh/json?q={domain}"
    try:
        r = requests.get(url, timeout=10)
        data = json.loads(r.text)
        subdomains = {entry["name_value"] for entry in data}
        return subdomains
    except requests.RequestException:
        return set()

def get_rapiddns_subdomains(domain):
    """Fetch subdomains from RapidDNS"""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        r = requests.get(url, timeout=10)
        return set(re.findall(r">([\w.-]+\." + re.escape(domain) + r")<", r.text))
    except requests.RequestException:
        return set()

def get_alienvault_subdomains(domain):
    """Fetch subdomains from AlienVault OTX"""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = requests.get(url, timeout=10)
        data = r.json()
        subdomains = {entry["hostname"] for entry in data["passive_dns"] if "hostname" in entry}
        return subdomains
    except requests.RequestException:
        return set()


# Wayback Machine Scraper
def waybackurls(domain):
    """Fetch URLs from Wayback Machine"""
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        r = requests.get(url, timeout=10)
        results = r.json()
        return {entry[0] for entry in results[1:]}
    except (requests.RequestException, IndexError, json.JSONDecodeError):
        return set()


# Extract Domains from URLs
def extract_domain(url):
    """Extracts the main domain and subdomains, removing ports"""
    match = re.search(r"https?://([^/:]+)", url)  # Extract domain including subdomains
    if match:
        domain = match.group(1)
        domain = re.sub(r":\d+$", "", domain)  # Remove ports like :80, :443
        return domain.lower()  # Normalize to lowercase
    return None

from email_collector import *
import time
import argparse

def main():
    if len(sys.argv) == 1:
        print("Usage: python3 waybackemails.py -d <domain>")
        sys.exit()

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="domain", required=True)
    parser.add_argument("-e", "--extract-email", dest="extract", required=False, action="store_true")

    args = parser.parse_args()
    domain = args.domain

    print("[*] Fetching subdomains...")
    subdomains = get_crtsh_subdomains(domain) | get_rapiddns_subdomains(domain) | get_alienvault_subdomains(domain)
    subdomains.add(domain)  # Ensure main domain is included

    print(f"[*] Found {len(subdomains)} subdomains.")

    # Step 2: Fetch Wayback URLs for each subdomain
    unique_urls = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(waybackurls, subdomains)

    for urls in results:
        unique_urls.update(urls)

    print(f"[*] Extracted {len(unique_urls)} URLs from Wayback Machine.")

    # Step 3: Extract unique domains from URLs
    unique_domains = set(filter(None, (extract_domain(url) for url in unique_urls)))

    # Step 4: Save Results
    filename = f"./{domain}-wayback.txt"
    with open(filename, "w") as f:
        f.write("\n".join(sorted(unique_domains)))

    print(f"[*] Saved {len(unique_domains)} unique domains to {filename}")

    # Extract email
    time.sleep(5)
    print("[*] Wait for 5 seconds.")

    with open(f"./{domain}-wayback.txt") as f:
        domains = [line.strip() for line in f if line.strip()]

    with open("./info.txt", "w") as p, open("./emails.csv", "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Email", "Domain"])  # Write CSV header

        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(lambda d: process_domain(d, csv_writer), domains)

        for result in results:
            if result:
                p.write(result)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[-] Abort ...")

print(f"[+] All findings are write into info.txt")
print(f"[+] Extracted emails saved to emails.csv")


