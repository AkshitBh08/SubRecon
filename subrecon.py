import asyncio
import httpx
import json
import sys
import time
import urllib3
import requests
import re
from urllib.parse import urlparse
import subprocess

# Disable SSL warnings for specific cases
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to fetch subdomains from Subfinder
async def from_subfinder(domain):
    try:
        print("[*] Fetching from Subfinder...")
        result = await asyncio.to_thread(subprocess.run, ['subfinder', '-d', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            subdomains = result.stdout.decode().splitlines()
            return subdomains
        else:
            print(f"[!] Subfinder error: {result.stderr.decode()}")
            return []
    except Exception as e:
        print(f"[!] Subfinder error: {e}")
        return []

# Function to fetch subdomains from Sublist3r
async def from_sublist3r(domain):
    try:
        print("[*] Fetching from Sublist3r...")
        result = await asyncio.to_thread(subprocess.run, ['sublist3r', '-d', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            subdomains = result.stdout.decode().splitlines()
            return subdomains
        else:
            print(f"[!] Sublist3r error: {result.stderr.decode()}")
            return []
    except Exception as e:
        print(f"[!] Sublist3r error: {e}")
        return []

# Function to fetch subdomains from crt.sh
async def from_crtsh(domain):
    try:
        print("[*] Fetching from crt.sh...")
        url = f"https://crt.sh/?q={domain}&output=json"
        async with httpx.AsyncClient() as client:
            r = await client.get(url, timeout=30)
        r.raise_for_status()
        subdomains = set()
        for entry in r.json():
            subdomains.add(entry["name_value"])
        return list(subdomains)
    except httpx.RequestError as e:
        print(f"[!] crt.sh error: {e}")
        return []

# Function to fetch subdomains from AlienVault OTX
async def from_otx(domain):
    try:
        print("[*] Fetching from AlienVault OTX...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"X-OTX-API-Key": "your_otx_api_key_here"}  # Replace with your AlienVault API key
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        subdomains = set()
        for entry in r.json().get("passive_dns", []):
            subdomains.add(entry["hostname"])
        return list(subdomains)
    except httpx.RequestError as e:
        print(f"[!] OTX error: {e}")
        return []

# Function to fetch subdomains from ThreatCrowd
# async def from_threatcrowd(domain):
#     try:
#         print("[*] Fetching from ThreatCrowd...")
#         url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
#         async with httpx.AsyncClient() as client:
#             r = await client.get(url, timeout=30)
#         r.raise_for_status()
#         return r.json().get('subdomains', [])
#     except httpx.RequestError as e:
#         print(f"[!] ThreatCrowd error: {e}")
#         return []

# Function to fetch subdomains from VirusTotal
# async def from_virustotal(domain):
#     try:
#         print("[*] Fetching from VirusTotal...")
#         url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
#         headers = {"x-apikey": "your_virustotal_api_key_here"}  # Replace with your VirusTotal API key
#         async with httpx.AsyncClient() as client:
#             r = await client.get(url, headers=headers, timeout=30)
#         r.raise_for_status()
#         subdomains = set()
#         for entry in r.json().get('data', []):
#             subdomains.add(entry['id'])
#         return list(subdomains)
#     except httpx.RequestError as e:
#         print(f"[!] VirusTotal error: {e}")
#         return []

# Function to fetch subdomains from PassiveTotal
# async def from_passivetotal(domain):
#     try:
#         print("[*] Fetching from PassiveTotal...")
#         url = f"https://api.passivetotal.org/v2/enrichment/subdomains?identifier={domain}"
#         headers = {
#             "Authorization": "Bearer your_passivetotal_api_key_here"  # Replace with your API key
#         }
#         r = requests.get(url, headers=headers, timeout=30, verify=False)  # Disable SSL verification
#         r.raise_for_status()
#         subdomains = set()
#         for entry in r.json().get("results", []):
#             subdomains.add(entry["subdomain"])
#         return list(subdomains)
#     except requests.exceptions.RequestException as e:
#         print(f"[!] PassiveTotal error: {e}")
#         return []


# Function to export subdomains to a file
def export_to_file(subdomains, domain, live_subdomains=None):
    choice = input(f"Do you want to export the subdomains of {domain} to a file? (y/n): ").lower()
    if choice == 'y':
        filename = f"{domain}_subdomains.txt"
        with open(filename, 'w') as file:
            for sub in subdomains:
                file.write(sub + '\n')
            if live_subdomains:
                file.write("\n[+] Live Subdomains:\n")
                for sub in live_subdomains:
                    file.write(sub + '\n')
        print(f"Subdomains have been exported to {filename}")
        return filename
    return None

def export_live_hosts_to_file(live_hosts, domain):
    if live_hosts:
        choice = input(f"Do you want to export the live hosts of {domain} to a file? (y/n): ").lower()
        if choice == 'y':
            filename = f"{domain}_live_hosts.txt"
            with open(filename, 'w') as file:
                for host in live_hosts:
                    file.write(host + '\n')
            print(f"Live hosts have been exported to {filename}")
            return filename
    return None

# Function to sanitize subdomain URLs
def sanitize_subdomain(subdomain):
    subdomain = ''.join(char for char in subdomain if char.isprintable())
    subdomain = re.sub(r'\[.*?\]', '', subdomain)
    subdomain = subdomain.replace('Google probably now is blocking our requests', '')
    if not subdomain.startswith("http"):
        subdomain = f"http://{subdomain}"
    try:
        parsed_url = urlparse(subdomain)
        if not parsed_url.netloc or not re.match(r"^(https?://)?([a-zA-Z0-9.-]+)$", parsed_url.netloc):
            print(f"[INFO] Invalid subdomain URL detected and skipped: {subdomain}")
            return None
    except Exception as e:
        print(f"[INFO] Error validating subdomain URL: {subdomain}, Error: {e}")
        return None
    return subdomain

# Function to test live hosts asynchronously
async def test_live_hosts(subdomains, domain):
    choice = input(f"Do you want to test the live hosts for the subdomains of {domain}? (y/n): ").lower()
    live_hosts = []
    if choice == 'y':
        print("Testing live hosts asynchronously... This might take a while.")
        async with httpx.AsyncClient() as client:
            tasks = []
            for subdomain in subdomains:
                subdomain = subdomain.strip()
                if not subdomain or '*' in subdomain:
                    print(f"[INFO] Skipping subdomain: {subdomain}")
                    continue
                sanitized_subdomain = sanitize_subdomain(subdomain)
                if not sanitized_subdomain:
                    continue
                tasks.append(test_single_live_host(client, sanitized_subdomain, live_hosts))
            await asyncio.gather(*tasks)
        
        print(f"\nLive hosts found: {len(live_hosts)}")
        if live_hosts:
            print("\nLive subdomains:")
            for host in live_hosts:
                print(host)
        
        export_live_hosts_to_file(live_hosts, domain)
    return live_hosts

# Helper function to check single subdomain live status
async def test_single_live_host(client, subdomain, live_hosts):
    try:
        response = await client.get(subdomain, timeout=5)
        if response.status_code == 200:
            print(f"[LIVE] {subdomain} - HTTP Status: {response.status_code}")
            live_hosts.append(subdomain)
    except httpx.RequestError as e:
        print(f"[FAILED] {subdomain}: {e}")

# Main function to gather subdomains concurrently
async def gather_subdomains(domain):
    subdomains = set()
    sources = [
        from_subfinder,
        from_sublist3r,
        from_crtsh,
        from_otx,
        # from_threatcrowd,
        # from_virustotal,
        # from_passivetotal
    ]
    tasks = [source(domain) for source in sources]
    results = await asyncio.gather(*tasks)
    for result in results:
        subdomains.update(result)
    return sorted(list(subdomains))

# Main execution
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 subrecon.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    print(f"\n[*] Starting subdomain enumeration for {domain}\n")

    subdomains = asyncio.run(gather_subdomains(domain))

    if subdomains:
        print(f"\n[+] Found {len(subdomains)} subdomains for {domain}:\n")
        for subdomain in subdomains:
            print(f" - {subdomain}")

        live_subdomains = asyncio.run(test_live_hosts(subdomains, domain))
        export_to_file(subdomains, domain, live_subdomains)
    else:
        print(f"\n[!] No subdomains found for {domain}")
