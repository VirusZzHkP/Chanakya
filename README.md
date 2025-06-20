# ⚔️ Chanakya: Offensive Security Recon & SQLi Automation Tool

**Chanakya** is a powerful Python-based offensive security tool that combines reconnaissance, automated Google dorking, SQL injection scanning, and live port/service analysis into a unified command-line interface.

Inspired by the ancient strategist Chanakya, this tool is designed to help penetration testers, bug bounty hunters, and cybersecurity professionals automate common tasks in vulnerability discovery.

![banner](https://img.shields.io/badge/Built%20With-Python3-blue?style=flat-square) ![MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)  
**Author:** VirusZzWarning · Twitter: [@VirusZzWarning](https://twitter.com/hrisikesh_pal)

---

## 🧠 Features

```text
1. Port scanning                - Scan live ports of a target IP/domain using Nmap.
2. Service scanning             - Basic service detection across 1-65535 ports.
3. SQL injection testing        - Manual URL testing using sqlmap with custom options.
4. Auto Dorking + SQLi Enum     - Google dork automation + SQLi detection + sqlmap enum.
5. Fetch & Save Valid Proxies  - Multi-threaded proxy fetcher and validator.
6. Exit                        - Exit the tool gracefully.
```

## 🧰 Modules Used

- nmap – Port scanning
- requests, urllib3 – Web requests
- BeautifulSoup4 – DuckDuckGo result parsing
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

## 🚀 Usage
```bash
python3 chanakya.py
```
Follow the on-screen menu. For auto-dorking, ensure dorks.txt is populated.

## 📸 Screenshot

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

> “Know your enemy before the battle.” – Chanakya


## ⚠️ Disclaimer
This tool is intended only for authorized security testing and educational purposes.
Any misuse of this tool for attacking systems without permission is strictly prohibited.
By using this software, you agree to take full responsibility for your actions.

> Copyright © 2025, VirusZzWarning
