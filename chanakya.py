"""
CHANAKYA
========

Main CLI / application entry point.

Architecture:

    chanakya.py
        |
        +-- scanners.network
        |      +-- Port scanning
        |      +-- Service scanning
        |
        +-- scanners.sqli
        |      +-- SQL injection
        |
        +-- attack.idor.scanner
        |      +-- IDOR / BOLA
        |
        +-- attack.jwt.scanner
        |      +-- JWT security testing
        |
        +-- scanners.command_injection
        |      +-- Command injection
        |
        +-- scanners.xss
        |      +-- XSS
        |
        +-- scanners.dorking
        |      +-- Search-engine reconnaissance
        |      +-- Scope validation
        |      +-- URL normalization
        |      +-- AI analysis
        |      +-- SQLi indication
        |      +-- SQLMap handoff
        |
        +-- AI
        |      +-- Finding analysis
        |
        +-- Proxy utilities

IMPORTANT:
    Chanakya is intended for authorized security testing only.
"""

from __future__ import annotations

import importlib
import logging
import os
import platform
import random
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

import requests
import urllib3
from dotenv import load_dotenv

from ai.analyzer import ai_analyzer

from scanners.network import (
    scan_ports,
    scan_services,
)

from scanners.sqli import (
    sql_injection_advanced,
)

from scanners.dorking import (
    auto_dorking,
)

from utils.colors import (
    RED,
    GREEN,
    CYAN,
    MAGENTA,
    YELLOW,
    RESET,
)


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


# ============================================================
# HTTP SETTINGS
# ============================================================

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# PROXY CONFIGURATION
# ============================================================

HTTP_PROXY_LIST_URL = (
    "https://proxyspace.pro/http.txt"
)

PROXY_VALIDATION_URL = (
    "https://httpbin.org/ip"
)


# ============================================================
# ATTACK MODULE DEFINITIONS
# ============================================================

ATTACK_MODULES: dict[str, dict[str, Any]] = {

    "idor": {
        "module": "attack.idor.scanner",
        "functions": (
            "run_idor_scan",
            "scan_idor",
            "idor_scan",
            "run_idor",
            "test_idor",
        ),
    },

    "jwt": {
        "module": "attack.jwt.scanner",
        "functions": (
            "run_jwt_scan",
            "scan_jwt",
            "jwt_scan",
            "run_jwt",
            "test_jwt",
        ),
    },

    "command_injection": {
        "module": "scanners.command_injection",
        "functions": (
            "run_command_injection",
            "scan_command_injection",
            "command_injection_scan",
            "test_command_injection",
        ),
    },

    "xss": {
        "module": "scanners.xss",
        "functions": (
            "run_xss_scan",
            "scan_xss",
            "xss_scan",
            "run_xss",
            "test_xss",
        ),
    },
}


# ============================================================
# ATTACK MODULE LOADER
# ============================================================

def load_attack_function(
    attack_name: str,
) -> Callable[..., Any] | None:
    """
    Dynamically load an attack scanner.

    Optional attack modules are loaded only when requested.
    Therefore, a broken optional module does not prevent
    Chanakya's main CLI from starting.

    Returns:
        Callable scanner function or None.
    """

    config = ATTACK_MODULES.get(
        attack_name
    )

    if config is None:

        print(
            RED
            + f"[!] Unknown attack module: {attack_name}"
            + RESET
        )

        return None

    module_name = config["module"]
    function_names = config["functions"]

    # --------------------------------------------------------
    # Import module
    # --------------------------------------------------------

    try:

        module = importlib.import_module(
            module_name
        )

    except Exception as exc:

        logger.exception(
            "Failed to import attack module %s",
            module_name,
        )

        print()
        print(
            RED
            + f"[!] Failed to load {attack_name} module."
            + RESET
        )

        print(
            YELLOW
            + f"    Module: {module_name}"
            + RESET
        )

        print(
            YELLOW
            + f"    Error : {exc}"
            + RESET
        )

        return None

    # --------------------------------------------------------
    # Find supported scanner function
    # --------------------------------------------------------

    for function_name in function_names:

        function = getattr(
            module,
            function_name,
            None,
        )

        if callable(function):

            logger.info(
                "Loaded attack scanner %s.%s",
                module_name,
                function_name,
            )

            return function

    # --------------------------------------------------------
    # No supported function
    # --------------------------------------------------------

    print()
    print(
        RED
        + f"[!] No supported scanner function found "
          f"in {module_name}."
        + RESET
    )

    print(
        YELLOW
        + "[*] Expected one of:"
        + RESET
    )

    for function_name in function_names:

        print(
            f"    - {function_name}"
        )

    return None


# ============================================================
# RESULT DISPLAY
# ============================================================

def display_scanner_result(
    result: Any,
) -> None:
    """
    Display a scanner result without assuming a specific
    result structure.
    """

    if result is None:
        return

    print()

    print(
        GREEN
        + "[+] Scanner returned a result."
        + RESET
    )

    # --------------------------------------------------------
    # Dictionary result
    # --------------------------------------------------------

    if isinstance(result, dict):

        print(
            CYAN
            + "[*] Result summary:"
            + RESET
        )

        for key, value in result.items():

            print(
                f"    {key}: {value}"
            )

        return

    # --------------------------------------------------------
    # List result
    # --------------------------------------------------------

    if isinstance(result, list):

        print(
            CYAN
            + f"[*] Results: {len(result)}"
            + RESET
        )

        return

    # --------------------------------------------------------
    # Other result types
    # --------------------------------------------------------

    print(
        CYAN
        + "[*] Result:"
        + RESET
    )

    print(
        f"    {result}"
    )


# ============================================================
# GENERIC ATTACK RUNNER
# ============================================================

def run_attack_module(
    attack_name: str,
    display_name: str,
) -> None:
    """
    Run one of Chanakya's attack-validation modules.

    The target is supplied by the operator and passed directly
    to the selected scanner.
    """

    print()

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    print(
        CYAN
        + f"{display_name:^70}"
        + RESET
    )

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    print(
        YELLOW
        + "[!] Only test systems you own or are explicitly "
          "authorized to assess."
        + RESET
    )

    target = get_target(
        "\nTarget URL > "
    )

    if target is None:
        return

    scanner = load_attack_function(
        attack_name
    )

    if scanner is None:
        return

    print()

    print(
        GREEN
        + f"[+] Target: {target}"
        + RESET
    )

    print(
        CYAN
        + f"[*] Starting {display_name}..."
        + RESET
    )

    try:

        result = scanner(
            target
        )

        display_scanner_result(
            result
        )

        print()

        print(
            GREEN
            + f"[+] {display_name} completed."
            + RESET
        )

    except TypeError as exc:

        logger.exception(
            "%s scanner interface error.",
            display_name,
        )

        print()

        print(
            RED
            + f"[!] {display_name} interface mismatch."
            + RESET
        )

        print(
            YELLOW
            + f"    {exc}"
            + RESET
        )

        print(
            YELLOW
            + "[*] Check the scanner function signature."
            + RESET
        )

    except KeyboardInterrupt:

        print(
            RED
            + f"\n[!] {display_name} interrupted."
            + RESET
        )

    except Exception as exc:

        logger.exception(
            "%s scanner failed.",
            display_name,
        )

        print()

        print(
            RED
            + f"[!] {display_name} failed."
            + RESET
        )

        print(
            YELLOW
            + f"    Error: {exc}"
            + RESET
        )


# ============================================================
# PROXY VALIDATION
# ============================================================

def test_proxy(
    proxy: str,
) -> bool:
    """
    Check whether a proxy can reach the validation endpoint.
    """

    try:

        response = requests.get(
            PROXY_VALIDATION_URL,
            proxies={
                "http": proxy,
                "https": proxy,
            },
            timeout=5,
            verify=False,
        )

        return response.status_code == 200

    except requests.RequestException:

        return False


def get_valid_proxies(
    limit: int = 150,
) -> list[str]:
    """
    Fetch public HTTP proxies and validate them concurrently.

    Valid proxies are saved to:

        valid_proxies.txt
    """

    # --------------------------------------------------------
    # Fetch proxy list
    # --------------------------------------------------------

    try:

        print(
            CYAN
            + "[*] Fetching HTTP proxy list..."
            + RESET
        )

        response = requests.get(
            HTTP_PROXY_LIST_URL,
            timeout=10,
        )

        response.raise_for_status()

        raw = (
            response.text
            .strip()
            .splitlines()
        )

    except requests.RequestException as exc:

        logger.exception(
            "Failed to fetch proxy list."
        )

        print(
            RED
            + f"[!] Failed to fetch proxy list: {exc}"
            + RESET
        )

        return []

    # --------------------------------------------------------
    # Normalize candidates
    # --------------------------------------------------------

    candidates: list[str] = []

    for proxy in raw:

        proxy = proxy.strip()

        if not proxy:
            continue

        if not proxy.startswith(
            (
                "http://",
                "https://",
            )
        ):

            proxy = (
                "http://"
                + proxy
            )

        candidates.append(
            proxy
        )

        if len(candidates) >= limit:
            break

    if not candidates:

        print(
            RED
            + "[!] No proxy candidates were returned."
            + RESET
        )

        return []

    print(
        CYAN
        + f"[*] Validating up to "
          f"{len(candidates)} proxies..."
        + RESET
    )

    # --------------------------------------------------------
    # Concurrent validation
    # --------------------------------------------------------

    valid: list[str] = []

    with ThreadPoolExecutor(
        max_workers=min(
            20,
            len(candidates),
        )
    ) as executor:

        results = executor.map(
            test_proxy,
            candidates,
        )

        for proxy, is_valid in zip(
            candidates,
            results,
        ):

            if is_valid:

                valid.append(
                    proxy
                )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    if not valid:

        print(
            RED
            + "[!] No valid proxies found after validation."
            + RESET
        )

        return []

    try:

        with open(
            "valid_proxies.txt",
            "w",
            encoding="utf-8",
        ) as file:

            for proxy in valid:

                file.write(
                    proxy
                    + "\n"
                )

    except OSError as exc:

        logger.exception(
            "Failed to save proxy list."
        )

        print(
            RED
            + "[!] Failed to save valid proxies: "
              f"{exc}"
            + RESET
        )

        return valid

    print(
        GREEN
        + f"[+] {len(valid)} valid proxies saved "
          "to valid_proxies.txt"
        + RESET
    )

    return valid


# ============================================================
# PROXY FILE HELPERS
# ============================================================

def load_proxies_from_file() -> list[str]:
    """
    Load previously validated proxies.
    """

    try:

        with open(
            "valid_proxies.txt",
            "r",
            encoding="utf-8",
        ) as file:

            proxies = [
                line.strip()
                for line in file
                if line.strip()
            ]

        print(
            CYAN
            + f"[*] Loaded {len(proxies)} valid proxies "
              "from file."
            + RESET
        )

        return proxies

    except FileNotFoundError:

        return []

    except OSError as exc:

        logger.exception(
            "Failed to load proxy file."
        )

        print(
            RED
            + f"[!] Failed to load proxy file: {exc}"
            + RESET
        )

        return []


def get_random_proxy() -> dict[str, str] | None:
    """
    Return a randomly selected validated proxy.
    """

    proxies = load_proxies_from_file()

    if not proxies:

        print(
            YELLOW
            + "[!] No proxies available in "
              "valid_proxies.txt."
            + RESET
        )

        return None

    proxy = random.choice(
        proxies
    )

    return {
        "http": proxy,
        "https": proxy,
    }

# ============================================================
# UI
# ============================================================

CHANAKYA_VERSION = "3.1.6"

captions = [
    "Recon. Exploit. Dominate. #ChanakyaMindset",
    "Be the strategist, not the pawn.",
    "Where security meets ancient intelligence.",
    "One step ahead — the Chanakya way.",
    "Every system has a weakness — know it before others do.",
]

# Select a different caption whenever this module is loaded.
caption = random.choice(captions)


title = f"""
{RED}
       ██████ ██   ██  █████  ███    ██  █████  ██   ██ ██    ██  █████
      ██      ██   ██ ██   ██ ████   ██ ██   ██ ██  ██   ██  ██  ██   ██
      ██      ███████ ███████ ██ ██  ██ ███████ █████     ████   ███████
      ██      ██   ██ ██   ██ ██  ██ ██ ██   ██ ██  ██     ██    ██   ██
       ██████ ██   ██ ██   ██ ██   ████ ██   ██ ██   ██    ██    ██   ██
{RESET}

{CYAN}{'“Know your enemy before the battle.” – Chanakya'.center(80)}{RESET}

{YELLOW}{f'CHANAKYA v{CHANAKYA_VERSION}'.center(80)}{RESET}
{YELLOW}{'A JustHackIT Security Intelligence Framework'.center(80)}{RESET}
{YELLOW}{caption.center(80)}{RESET}

{MAGENTA}{'Made with ♥ by VirusZzWarning'.center(80)}{RESET}

{MAGENTA}{'JustHackIT'.center(80)}{RESET}
{MAGENTA}{'Website  : justhackit.in'.center(80)}{RESET}
{MAGENTA}{'Instagram: @justhackit.in'.center(80)}{RESET}
{MAGENTA}{'X        : @JustHackIT_HQ'.center(80)}{RESET}

{RED}{'[!] WARNING: This tool is intended for educational and authorized testing only,'.center(80)}{RESET}
{RED}{'Use it only on systems you own or have explicit permission to test.'.center(80)}{RESET}
"""


divider = (
    f"{CYAN}{'-' * 80}{RESET}"
)


def header() -> None:
    """
    Display Chanakya's main header.
    """

    print(divider)
    print(title)
    print(divider)


def clear_screen() -> None:
    """
    Clear terminal cross-platform.
    """

    command = (
        "cls"
        if platform.system().lower() == "windows"
        else "clear"
    )

    os.system(command)

# ============================================================
# AI STATUS
# ============================================================

def show_ai_status() -> None:
    """
    Display configured AI provider.
    """

    print(
        CYAN
        + "[*] AI Provider: "
        + RESET,
        end="",
    )

    if not ai_analyzer.available:

        print(
            YELLOW
            + "Not configured"
            + RESET
        )

        return

    try:

        status = ai_analyzer.status()

    except Exception as exc:

        logger.exception(
            "Failed to retrieve AI analyzer status."
        )

        print(
            RED
            + "Unavailable"
            + RESET
        )

        logger.error(
            "AI status error: %s",
            exc,
        )

        return

    print(
        GREEN
        + status
        + RESET
    )

    if ai_analyzer.provider == "Gemini":

        print(
            YELLOW
            + "[*] OpenAI API key not available. "
              "Using Gemini for analysis."
            + RESET
        )


# ============================================================
# MENU
# ============================================================

def show_menu() -> None:
    """
    Display the main Chanakya menu.
    """

    print()

    print(
        CYAN
        + "[+] Recon, Exploit, or Exit? Choose wisely:"
        + RESET
    )

    print()

    print(
        CYAN
        + "NETWORK / RECON"
        + RESET
    )

    print(
        "1. Port scanning"
    )

    print(
        "2. Service scanning"
    )

    print(
        "3. SQL injection testing"
    )

    print(
        "4. Auto Dorking + SQLi Enumeration"
    )

    print()

    print(
        CYAN
        + "WEB ATTACK VALIDATION"
        + RESET
    )

    print(
        "5. IDOR / BOLA testing"
    )

    print(
        "6. JWT security testing"
    )

    print(
        "7. Command injection testing"
    )

    print(
        "8. XSS testing"
    )

    print()

    print(
        CYAN
        + "UTILITY"
        + RESET
    )

    print(
        "9. Fetch & Save Valid Proxies"
    )

    print(
        "10. Exit the program"
    )


# ============================================================
# TARGET INPUT
# ============================================================

def get_target(
    prompt: str,
) -> str | None:
    """
    Read and validate a basic target string.
    """

    try:

        target = input(
            CYAN
            + prompt
            + RESET
        ).strip()

    except EOFError:

        print(
            RED
            + "\n[!] Input stream closed."
            + RESET
        )

        return None

    if not target:

        print(
            RED
            + "[!] Target cannot be empty."
            + RESET
        )

        return None

    return target


# ============================================================
# PAUSE
# ============================================================

def pause() -> None:
    """
    Pause before returning to the main menu.
    """

    try:

        input(
            "\nPress Enter to continue..."
        )

    except (
        EOFError,
        KeyboardInterrupt,
    ):

        pass


# ============================================================
# MAIN APPLICATION
# ============================================================

def main() -> None:
    """
    Main Chanakya application loop.
    """

    clear_screen()

    header()

    show_ai_status()

    while True:

        print()

        show_menu()

        try:

            option = input(
                GREEN
                + "\n> "
                + RESET
            ).strip()

        except EOFError:

            print(
                RED
                + "\n[!] Input stream closed."
                + RESET
            )

            return

        except KeyboardInterrupt:

            print(
                RED
                + "\n[!] Operation interrupted by user."
                + RESET
            )

            continue

        try:

            # =================================================
            # PORT SCANNING
            # =================================================

            if option == "1":

                target = get_target(
                    "[*] Enter the IP or domain to scan: "
                )

                if target:

                    scan_ports(
                        target
                    )

            # =================================================
            # SERVICE SCANNING
            # =================================================

            elif option == "2":

                target = get_target(
                    "[*] Enter the IP or domain to scan: "
                )

                if target:

                    scan_services(
                        target
                    )

            # =================================================
            # SQL INJECTION
            # =================================================

            elif option == "3":

                target = get_target(
                    "[*] Enter the URL to perform "
                    "SQL injection testing: "
                )

                if target:

                    sql_injection_advanced(
                        target
                    )

            # =================================================
            # DORKING
            # =================================================

            elif option == "4":

                auto_dorking()

            # =================================================
            # IDOR / BOLA
            # =================================================

            elif option == "5":

                run_attack_module(
                    attack_name="idor",
                    display_name="IDOR / BOLA TESTING",
                )

            # =================================================
            # JWT
            # =================================================

            elif option == "6":

                run_attack_module(
                    attack_name="jwt",
                    display_name="JWT SECURITY TESTING",
                )

            # =================================================
            # COMMAND INJECTION
            # =================================================

            elif option == "7":

                run_attack_module(
                    attack_name="command_injection",
                    display_name="COMMAND INJECTION TESTING",
                )

            # =================================================
            # XSS
            # =================================================

            elif option == "8":

                run_attack_module(
                    attack_name="xss",
                    display_name="XSS TESTING",
                )

            # =================================================
            # PROXY FETCHING
            # =================================================

            elif option == "9":

                get_valid_proxies()

            # =================================================
            # EXIT
            # =================================================

            elif option == "10":

                print()

                print(
                    RED
                    + "[*] Exiting the program..."
                    + RESET
                )

                print(
                    YELLOW
                    + "[♥] Made with ♥ by VirusZzWarning"
                    + RESET
                )

                print(
                    GREEN
                    + "[+] Happy hacking ;)"
                    + RESET
                )

                return

            # =================================================
            # INVALID OPTION
            # =================================================

            else:

                print()

                print(
                    RED
                    + "[!] Invalid option."
                    + RESET
                )

        except KeyboardInterrupt:

            print()

            print(
                RED
                + "[!] Operation interrupted by user."
                + RESET
            )

        except Exception as exc:

            logger.exception(
                "Unhandled exception in main menu."
            )

            print()

            print(
                RED
                + "[!] An unexpected error occurred."
                + RESET
            )

            print(
                YELLOW
                + f"    Error: {exc}"
                + RESET
            )

        # ----------------------------------------------------
        # Return to menu
        # ----------------------------------------------------

        pause()

        clear_screen()

        header()

        show_ai_status()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            RED
            + "\n\n[!] Chanakya terminated by user."
            + RESET
        )

    except Exception as exc:

        logger.exception(
            "Fatal Chanakya error."
        )

        print()

        print(
            RED
            + "[!] Fatal error:"
            + RESET
        )

        print(
            YELLOW
            + f"    {exc}"
            + RESET
        )