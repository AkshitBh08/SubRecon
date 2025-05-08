# SubRecon 🔍

**SubRecon** is a powerful and asynchronous subdomain enumeration and live host detection tool designed for red teamers, penetration testers, and OSINT professionals. It aggregates data from multiple public and commercial sources to provide a comprehensive list of discovered subdomains — along with the ability to test which are live.

## ✨ Features

- 🔎 **Multi-source Subdomain Enumeration**  
  Integrates **Subfinder**, **Sublist3r**, **crt.sh**, **AlienVault OTX**, **ThreatCrowd**, **VirusTotal**, and **PassiveTotal**.

- ⚡ **Asynchronous Performance**  
  Uses Python's `asyncio` and `httpx` for fast parallelized requests.

- 🌐 **Live Host Detection**  
  Optional HTTP-based live host detection for identified subdomains.

- 🧼 **Subdomain Validation & Sanitization**  
  Filters out malformed or invalid entries.

- 📝 **Export Capabilities**  
  Save results to clean `.txt` files, including both all subdomains and live hosts.

---

## 📦 Installation

```bash
git clone https://github.com/AkshitBh08/SubRecon.git
cd SubRecon
chmod +x install.sh
bash install.sh

This will:

Set up a Python virtual environment

Install Python dependencies from requirements.txt

Check for required tools (subfinder, sublist3r)

Usage
To run SubRecon, simply execute the following command:

bash
Copy
Edit
python3 subrecon.py <domain>
For example, to enumerate subdomains for example.com:

bash
Copy
Edit
python3 subrecon.py example.com
What Happens Next:
SubRecon will collect subdomains from the following sources:

Subfinder

Sublist3r

crt.sh

AlienVault OTX

ThreatCrowd

VirusTotal

PassiveTotal

The tool will then test the live status of the subdomains (i.e., check if they respond with HTTP status 200).

You'll be prompted whether you want to export the results (subdomains and live hosts) to files. The files will be saved with the following names:

example.com_subdomains.txt

example.com_live_hosts.txt

Configuration
To use sources like AlienVault OTX, VirusTotal, and PassiveTotal, you'll need to provide your API keys.

AlienVault OTX:

Obtain an API key from AlienVault OTX.

Add the key to the code:

python
Copy
Edit
headers = {"X-OTX-API-Key": "your_otx_api_key_here"}
VirusTotal:

Obtain an API key from VirusTotal.

Add the key to the code:

python
Copy
Edit
headers = {"x-apikey": "your_virustotal_api_key_here"}
PassiveTotal:

Obtain an API key from PassiveTotal.

Add the key to the code:

python
Copy
Edit
headers = {"Authorization": "Bearer your_passivetotal_api_key_here"}
Important Notes
API keys: Some services require API keys for querying their APIs (e.g., VirusTotal, PassiveTotal, AlienVault OTX). You can sign up on the respective platforms to get API keys and replace the placeholders in the script.

SSL Warnings: The script disables SSL verification for certain requests. Please be cautious if you're running the tool in a production environment.

Contributing
Feel free to contribute to this project by submitting pull requests or reporting issues. Contributions are always welcome!

How to Contribute:
Fork the repository.

Create a new branch (git checkout -b feature-branch).

Make your changes and commit them (git commit -m 'Add new feature').

Push to the branch (git push origin feature-branch).

Open a pull request.