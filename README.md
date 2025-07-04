# ⚔️ Chanakya: Offensive Security Recon & SQLi Automation Tool

**Chanakya** is a powerful Python-based offensive security tool that combines reconnaissance, API-based dorking (SerpAPI, ScrapingAnt, Google CSE), SQL injection scanning, and live port/service analysis into a unified command-line interface.

Inspired by the ancient strategist Chanakya, this tool is designed to help penetration testers, bug bounty hunters, and cybersecurity professionals automate common tasks in vulnerability discovery.

![banner](https://img.shields.io/badge/Built%20With-Python3-blue?style=flat-square) ![MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)  

> “Know your enemy before the battle.” – Chanakya

## 📸 Screenshot
![Chanakya](/img/image.png "Chanakya's-Terminal look").

## ⚠️ Disclaimer
This tool is intended only for authorized security testing and educational purposes.
Any misuse of this tool for attacking systems without permission is strictly prohibited.
By using this software, you agree to take full responsibility for your actions.

**Author:** VirusZzWarning · Twitter: [@hrisikesh_pal](https://twitter.com/hrisikesh_pal)

---

## 🧠 Features

```text
1. Port scanning                - Scan live ports of a target IP/domain using Nmap.
2. Service scanning             - Basic service detection across 1-65535 ports.
3. SQL injection testing        - Manual URL testing using sqlmap with custom options.
4. Auto Dorking + SQLi Enum     - API-based dorking via SerpAPI, ScrapingAnt, Google CSE + SQLi detection.
5. Fetch & Save Valid Proxies  - Multi-threaded proxy fetcher and validator.
6. Exit                        - Exit the tool gracefully.
```

## 🧰 Modules Used

- nmap – Port scanning
- requests, urllib3 – Web requests
- dotenv – Loads API keys securely from .env file
- Google CSE API, SerpAPI, ScrapingAnt – For official search engine scraping
- subprocess – For executing sqlmap from within tool
- concurrent.futures – Multithreaded proxy validation
- sqlmap – SQL injection automation (must be installed)
- socket – Basic TCP service probing
- colorama or ANSI escape sequences – Console coloring

## 🛠️ Installation
🔗 Prerequisites
- Python 3.8+
- sqlmap installed and in PATH
- nmap installed (for port scan)
- Internet connection for dorking and proxy

📦 Clone and Setup
```bash
git clone https://github.com/VirusZzHkP/chanakya.git
cd chanakya
pip install -r requirements.txt
```

## 📄 Required Files
Ensure these files are in the root directory:
- dorks.txt – Your list of dorks (one per line)
- valid_proxies.txt – (Optional) Used by the tool, auto-populated if proxies are fetched
- .env – Store your API keys securely (see format below)

## 🔐 API Key Configuration (.env)
Before using Auto Dorking, create a `.env` file in the root directory:
```text
SERPAPI_KEY=your_key_here
SCRAPINGANT_KEY=your_key_here
GOOGLE_CSE_API_KEY=your_key_here
GOOGLE_CSE_CX=your_custom_search_engine_id
```
These are used for querying official search engine APIs.


## 🚀 Usage
```bash
python3 chanakya.py
```
Follow the on-screen menu. For auto-dorking, ensure dorks.txt is populated.


## 📁 Directory Structure
```text
chanakya/
├── chanakya.py
├── dorks.txt
├── valid_proxies.txt
├── scanned_dork_links.txt
├── requirements.txt
└── README.md
```
## 📜 License
<b>Chanakya</b> is licensed under the [MIT License](LICENSE). 


## 🙋‍♂️ Developer & Contact
@VirusZzWarning

Connect with me:
- Twitter: [@hrisikesh_pal](https://twitter.com/hrisikesh_pal)
- Instagram: [viruszzwarning](https://www.instagram.com/viruszzwarning)
- YouTube: [JustHack_IT](https://www.youtube.com/@JustHack_IT)
- Discord: [JustHack_IT](https://discord.com/invite/PUzR6YhXgR)


> Copyright © 2025, VirusZzWarning
