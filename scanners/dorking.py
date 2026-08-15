"""
Chanakya Dorking & Reconnaissance Engine
-----------------------------------------

Scope-aware search-engine reconnaissance module.

Responsibilities:
    - Search using configured providers
    - Normalize and canonicalize discovered URLs
    - Deduplicate URLs intelligently
    - Maintain persistent discovery history
    - Enforce explicit authorized target scope
    - Classify and prioritize discovered URLs
    - Perform low-impact SQLi indication checks
    - Send reconnaissance evidence to Chanakya AI
    - Hand selected in-scope URLs to SQLMap
    - Persist reconnaissance and SQLi reports

IMPORTANT:
    Search-engine discovery can return third-party systems.

    Chanakya therefore NEVER performs active testing against a
    discovered URL unless that URL belongs to the explicitly
    supplied authorized scope.

Compatible with:
    scanners.sqli.sql_injection_advanced()
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import time
import traceback
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

import requests
from dotenv import load_dotenv

from scanners.sqli import sql_injection_advanced

from utils.ai import analyze_with_ai
from utils.colors import (
    RED,
    GREEN,
    CYAN,
    YELLOW,
    RESET,
)
from utils.dork_generator import generate_dorks_interactive
from utils.paths import BASE_DIR, DORKING_REPORTS_DIR


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# LOGGER
# ============================================================

logger = logging.getLogger(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

SERPAPI_KEY = os.getenv("SERPAPI_KEY")
SCRAPINGANT_KEY = os.getenv("SCRAPINGANT_KEY")
GOOGLE_CSE_API_KEY = os.getenv("GOOGLE_CSE_API_KEY")
GOOGLE_CSE_CX = os.getenv("GOOGLE_CSE_CX")

DORKED_HISTORY_FILE = BASE_DIR / "scanned_dork_links.txt"

REQUEST_TIMEOUT = 10

# Delay between search-provider requests.
MIN_SEARCH_DELAY = 1.5
MAX_SEARCH_DELAY = 3.0

# Delay between active URL checks.
MIN_ACTIVE_DELAY = 0.8
MAX_ACTIVE_DELAY = 1.8

# Prevent a huge search result set from being actively tested.
MAX_ACTIVE_SQLI_CHECKS = 25

# Maximum URLs sent to AI in a single analysis.
MAX_AI_URLS = 150


# ============================================================
# SQL ERROR SIGNATURES
# ============================================================

SQL_ERROR_INDICATORS = (
    "sql syntax",
    "mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysqli",
    "you have an error in your sql syntax",
    "warning: mysql",
    "warning: pg_",
    "postgresql",
    "postgres",
    "sqlite error",
    "sqlite3.operationalerror",
    "ora-",
    "oracle error",
    "microsoft sql server",
    "odbc sql server",
    "odbc microsoft access",
    "jet database engine",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error in string in query expression",
)


# ============================================================
# USER AGENTS
# ============================================================

USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) "
        "Gecko/20100101 Firefox/122.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3_1) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/16.4 Safari/605.1.15"
    ),
    (
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Mobile Safari/537.36"
    ),
]


def get_random_headers() -> dict[str, str]:
    """
    Generate ordinary browser-like request headers.
    """

    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.8",
        "Connection": "keep-alive",
    }


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url: str) -> Optional[str]:
    """
    Normalize a discovered URL.

    Changes:
        - strips whitespace
        - requires HTTP/HTTPS
        - lowercases scheme and hostname
        - removes fragments
        - removes default ports
        - normalizes empty path
        - sorts query parameters
        - removes duplicate query parameters
    """

    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url:
        return None

    try:
        parsed = urllib.parse.urlsplit(url)

    except ValueError:
        return None

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        return None

    hostname = parsed.hostname

    if not hostname:
        return None

    hostname = hostname.lower().rstrip(".")

    # --------------------------------------------------------
    # Port handling
    # --------------------------------------------------------

    try:
        port = parsed.port

    except ValueError:
        return None

    netloc = hostname

    if port is not None:
        if not (
            (scheme == "http" and port == 80)
            or
            (scheme == "https" and port == 443)
        ):
            netloc = f"{hostname}:{port}"

    # --------------------------------------------------------
    # Path
    # --------------------------------------------------------

    path = parsed.path or "/"

    path = re.sub(
        r"/{2,}",
        "/",
        path,
    )

    # --------------------------------------------------------
    # Query
    # --------------------------------------------------------

    query_pairs = urllib.parse.parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    query_pairs = list(
        dict.fromkeys(query_pairs)
    )

    query_pairs.sort(
        key=lambda item: (
            item[0].lower(),
            item[1],
        )
    )

    query = urllib.parse.urlencode(
        query_pairs,
        doseq=True,
    )

    return urllib.parse.urlunsplit(
        (
            scheme,
            netloc,
            path,
            query,
            "",
        )
    )


def canonical_url_key(
    url: str,
) -> Optional[str]:
    """
    Generate a canonical comparison key.
    """

    normalized = normalize_url(url)

    if not normalized:
        return None

    parsed = urllib.parse.urlsplit(
        normalized
    )

    hostname = (
        parsed.hostname or ""
    ).lower()

    path = parsed.path or "/"

    pairs = urllib.parse.parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    normalized_pairs = sorted(
        (
            name.lower(),
            value,
        )
        for name, value in pairs
    )

    return (
        f"{parsed.scheme.lower()}://"
        f"{hostname}"
        f"{path}"
        f"?{urllib.parse.urlencode(normalized_pairs)}"
    )


def extract_urls_from_results(
    results: Iterable[str],
) -> set[str]:
    """
    Normalize and deduplicate provider results.
    """

    urls: dict[str, str] = {}

    for result in results or []:

        if not isinstance(result, str):
            continue

        normalized = normalize_url(
            result
        )

        if not normalized:
            continue

        key = canonical_url_key(
            normalized
        )

        if not key:
            continue

        urls[key] = normalized

    return set(
        urls.values()
    )


# ============================================================
# SCOPE ENGINE
# ============================================================

def normalize_scope_entry(
    scope: str,
) -> Optional[str]:
    """
    Normalize a scope entry.

    Supported:
        example.com
        www.example.com
        *.example.com
        https://example.com
    """

    if not isinstance(scope, str):
        return None

    scope = scope.strip().lower()

    if not scope:
        return None

    # --------------------------------------------------------
    # URL input
    # --------------------------------------------------------

    if "://" in scope:

        try:

            parsed = urllib.parse.urlsplit(
                scope
            )

            if parsed.hostname:
                scope = parsed.hostname.lower()

        except ValueError:

            return None

    # --------------------------------------------------------
    # Remove path/query/fragment
    # --------------------------------------------------------

    scope = scope.split("/", 1)[0]
    scope = scope.split("?", 1)[0]
    scope = scope.split("#", 1)[0]

    # --------------------------------------------------------
    # Remove port
    # --------------------------------------------------------

    if ":" in scope and not scope.startswith("["):

        scope = scope.rsplit(
            ":",
            1,
        )[0]

    scope = scope.strip(".")

    if scope.startswith("*."):

        scope = (
            "*."
            + scope[2:].strip(".")
        )

    return scope or None


def load_scope() -> set[str]:
    """
    Ask the operator for authorized target scope.
    """

    print()

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        CYAN
        + "                 AUTHORIZED TARGET SCOPE"
        + RESET
    )

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        YELLOW
        + "[!] Active testing will ONLY be performed against "
          "domains listed here."
        + RESET
    )

    print(
        YELLOW
        + "[!] Example: example.com, *.example.com"
        + RESET
    )

    raw_scope = input(
        GREEN
        + "Authorized scope > "
        + RESET
    ).strip()

    if not raw_scope:

        print(
            RED
            + "[!] Scope cannot be empty."
            + RESET
        )

        return set()

    entries = set()

    for item in raw_scope.split(","):

        normalized = normalize_scope_entry(
            item
        )

        if normalized:
            entries.add(normalized)

    if not entries:

        print(
            RED
            + "[!] No valid scope entries supplied."
            + RESET
        )

        return set()

    print(
        GREEN
        + f"[+] Loaded {len(entries)} authorized scope entries."
        + RESET
    )

    for entry in sorted(entries):

        print(
            f"    - {entry}"
        )

    return entries


def hostname_in_scope(
    hostname: str,
    scope_entries: set[str],
) -> bool:
    """
    Determine whether a hostname belongs to
    authorized scope.

    Exact:
        example.com

    Wildcard:
        *.example.com

    Wildcard matches subdomains but not the base domain.
    """

    if not hostname:
        return False

    hostname = (
        hostname
        .lower()
        .rstrip(".")
    )

    for scope in scope_entries:

        scope = (
            scope
            .lower()
            .rstrip(".")
        )

        if scope.startswith("*."):

            base = scope[2:]

            if (
                hostname != base
                and hostname.endswith(
                    "." + base
                )
            ):
                return True

        elif hostname == scope:

            return True

    return False


def url_in_scope(
    url: str,
    scope_entries: set[str],
) -> bool:
    """
    Check whether a URL belongs to authorized scope.
    """

    try:

        parsed = urllib.parse.urlsplit(
            url
        )

        if parsed.scheme not in {
            "http",
            "https",
        }:
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        return hostname_in_scope(
            hostname,
            scope_entries,
        )

    except ValueError:

        return False


# ============================================================
# URL CLASSIFICATION
# ============================================================

def classify_url(
    url: str,
) -> dict:
    """
    Extract useful reconnaissance metadata from a URL.
    """

    parsed = urllib.parse.urlsplit(
        url
    )

    parameters = urllib.parse.parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    parameter_names = [
        name
        for name, _ in parameters
        if name
    ]

    path_lower = parsed.path.lower()

    interesting_keywords = {
        "login",
        "admin",
        "account",
        "user",
        "profile",
        "search",
        "product",
        "item",
        "page",
        "download",
        "file",
        "view",
        "article",
        "news",
        "api",
        "redirect",
        "url",
        "return",
        "next",
        "id",
    }

    keyword_hits = []

    combined = (
        path_lower
        + " "
        + " ".join(
            parameter_names
        ).lower()
    )

    for keyword in sorted(
        interesting_keywords
    ):

        if keyword in combined:

            keyword_hits.append(
                keyword
            )

    score = 0

    if parameters:
        score += 40

    if len(parameters) >= 2:
        score += 10

    if keyword_hits:

        score += min(
            len(keyword_hits) * 5,
            30,
        )

    if any(
        name.lower()
        in {
            "id",
            "uid",
            "user_id",
            "item",
            "product",
            "page",
            "cat",
            "category",
        }
        for name in parameter_names
    ):

        score += 15

    if any(
        name.lower()
        in {
            "url",
            "uri",
            "redirect",
            "next",
            "return",
            "returnurl",
        }
        for name in parameter_names
    ):

        score += 10

    return {
        "url": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "path": parsed.path or "/",
        "parameters": parameter_names,
        "parameter_count": len(
            parameter_names
        ),
        "keyword_hits": keyword_hits,
        "score": min(
            score,
            100,
        ),
        "parameterized": bool(
            parameters
        ),
    }


def prioritize_urls(
    urls: Iterable[str],
) -> list[dict]:
    """
    Classify and sort URLs by reconnaissance value.
    """

    classified = [
        classify_url(url)
        for url in urls
    ]

    classified.sort(
        key=lambda item: (
            item["parameterized"],
            item["score"],
            item["parameter_count"],
        ),
        reverse=True,
    )

    return classified


# ============================================================
# SEARCH PROVIDERS
# ============================================================

def serpapi_dork_search(
    dork: str,
) -> list[str]:

    if not SERPAPI_KEY:

        print(
            YELLOW
            + "[!] SERPAPI_KEY is not configured."
            + RESET
        )

        return []

    try:

        response = requests.get(
            "https://serpapi.com/search",
            params={
                "q": dork,
                "engine": "google",
                "api_key": SERPAPI_KEY,
            },
            headers=get_random_headers(),
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        data = response.json()

        return [
            item["link"]
            for item in data.get(
                "organic_results",
                [],
            )
            if (
                isinstance(item, dict)
                and isinstance(
                    item.get("link"),
                    str,
                )
            )
        ]

    except requests.RequestException as exc:

        logger.warning(
            "SerpAPI request failed: %s",
            exc,
        )

        print(
            RED
            + f"[!] SerpAPI failed: {exc}"
            + RESET
        )

        return []

    except ValueError:

        print(
            RED
            + "[!] SerpAPI returned invalid JSON."
            + RESET
        )

        return []


def scrapingant_dork_search(
    dork: str,
) -> list[str]:

    if not SCRAPINGANT_KEY:

        print(
            YELLOW
            + "[!] SCRAPINGANT_KEY is not configured."
            + RESET
        )

        return []

    try:

        response = requests.get(
            "https://api.scrapingant.com/v2/search",
            params={
                "query": dork,
                "api_key": SCRAPINGANT_KEY,
                "country": "us",
            },
            headers=get_random_headers(),
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        data = response.json()

        results = []

        for item in data.get(
            "organic",
            [],
        ):

            if not isinstance(
                item,
                dict,
            ):
                continue

            url = item.get(
                "url"
            )

            if isinstance(
                url,
                str,
            ):

                results.append(
                    url
                )

        return results

    except requests.RequestException as exc:

        logger.warning(
            "ScrapingAnt request failed: %s",
            exc,
        )

        print(
            RED
            + f"[!] ScrapingAnt failed: {exc}"
            + RESET
        )

        return []

    except ValueError:

        print(
            RED
            + "[!] ScrapingAnt returned invalid JSON."
            + RESET
        )

        return []


def google_cse_dork_search(
    dork: str,
) -> list[str]:

    if (
        not GOOGLE_CSE_API_KEY
        or not GOOGLE_CSE_CX
    ):

        print(
            YELLOW
            + "[!] Google CSE credentials are not configured."
            + RESET
        )

        return []

    try:

        response = requests.get(
            "https://www.googleapis.com/customsearch/v1",
            params={
                "q": dork,
                "key": GOOGLE_CSE_API_KEY,
                "cx": GOOGLE_CSE_CX,
            },
            headers=get_random_headers(),
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        data = response.json()

        return [
            item["link"]
            for item in data.get(
                "items",
                [],
            )
            if (
                isinstance(item, dict)
                and isinstance(
                    item.get("link"),
                    str,
                )
            )
        ]

    except requests.RequestException as exc:

        logger.warning(
            "Google CSE request failed: %s",
            exc,
        )

        print(
            RED
            + f"[!] Google CSE failed: {exc}"
            + RESET
        )

        return []

    except ValueError:

        print(
            RED
            + "[!] Google CSE returned invalid JSON."
            + RESET
        )

        return []


# ============================================================
# PROVIDER SELECTION
# ============================================================

def choose_dorking_method() -> tuple[
    Optional[Callable[[str], list[str]]],
    Optional[str],
]:
    """
    Return provider function + provider name.
    """

    print()

    print(
        CYAN
        + "[?] Choose dorking provider:"
        + RESET
    )

    print("1. SerpAPI")
    print("2. ScrapingAnt")
    print("3. Google CSE")

    choice = input(
        GREEN
        + "Select option > "
        + RESET
    ).strip()

    if choice == "1":

        return (
            serpapi_dork_search,
            "SerpAPI",
        )

    if choice == "2":

        return (
            scrapingant_dork_search,
            "ScrapingAnt",
        )

    if choice == "3":

        return (
            google_cse_dork_search,
            "Google CSE",
        )

    print(
        RED
        + "[!] Invalid provider selection."
        + RESET
    )

    return None, None


# ============================================================
# HISTORY
# ============================================================

def load_dorked_history() -> set[str]:
    """
    Load canonical URL keys from previous runs.

    Older history files containing raw URLs are supported.
    """

    history: set[str] = set()

    try:

        if not DORKED_HISTORY_FILE.exists():
            return history

        with open(
            DORKED_HISTORY_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                key = canonical_url_key(
                    line
                )

                if key:
                    history.add(key)

    except OSError:

        logger.exception(
            "Failed to read dorking history."
        )

    return history


def save_dorked_history(
    urls: Iterable[str],
) -> None:
    """
    Persist normalized URLs.
    """

    existing = load_dorked_history()

    new_entries = []

    for url in urls:

        key = canonical_url_key(
            url
        )

        if not key:
            continue

        if key in existing:
            continue

        existing.add(key)

        new_entries.append(
            normalize_url(url)
        )

    if not new_entries:
        return

    try:

        DORKED_HISTORY_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            DORKED_HISTORY_FILE,
            "a",
            encoding="utf-8",
        ) as file:

            for url in new_entries:

                if url:

                    file.write(
                        url + "\n"
                    )

    except OSError:

        logger.exception(
            "Failed to save dorking history."
        )

        print(
            YELLOW
            + "[!] Failed to update dorking history."
            + RESET
        )


# ============================================================
# REPORTING
# ============================================================

def save_dorking_results(
    results: Iterable[str],
    filename_prefix: str = "dork_results",
) -> Optional[Path]:

    unique_results = sorted(
        set(
            filter(
                None,
                (
                    normalize_url(url)
                    for url in results
                ),
            )
        )
    )

    if not unique_results:
        return None

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S-%f"
    )

    filename = (
        DORKING_REPORTS_DIR
        / f"{timestamp}_{filename_prefix}.txt"
    )

    try:

        DORKING_REPORTS_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as file:

            for url in unique_results:

                file.write(
                    url + "\n"
                )

        print(
            GREEN
            + f"[+] Dorking results saved to {filename}"
            + RESET
        )

        return filename

    except OSError:

        logger.exception(
            "Failed to save dorking report."
        )

        print(
            RED
            + "[!] Failed to save dorking results."
            + RESET
        )

        return None


def save_json_report(
    data: object,
    filename_prefix: str,
) -> Optional[Path]:

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S-%f"
    )

    filename = (
        DORKING_REPORTS_DIR
        / f"{timestamp}_{filename_prefix}.json"
    )

    try:

        DORKING_REPORTS_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                data,
                file,
                indent=2,
                ensure_ascii=False,
            )

        return filename

    except OSError:

        logger.exception(
            "Failed to save JSON report."
        )

        return None


# ============================================================
# AI ANALYSIS
# ============================================================

def analyze_dork_results(
    urls: Iterable[str],
):
    """
    Analyze discovered URLs.

    AI only receives reconnaissance evidence.
    It does not control active scanning.
    """

    unique_urls = sorted(
        set(urls)
    )

    if not unique_urls:
        return None

    limited_urls = unique_urls[
        :MAX_AI_URLS
    ]

    evidence_lines = []

    for url in limited_urls:

        metadata = classify_url(
            url
        )

        evidence_lines.append(
            (
                f"- URL: {url}\n"
                f"  Parameters: "
                f"{', '.join(metadata['parameters']) or 'none'}\n"
                f"  Priority score: "
                f"{metadata['score']}\n"
                f"  Keywords: "
                f"{', '.join(metadata['keyword_hits']) or 'none'}"
            )
        )

    evidence = "\n".join(
        evidence_lines
    )

    try:

        return analyze_with_ai(
            target="Authorized dorking reconnaissance",
            scan_type=(
                "Web reconnaissance / "
                "URL classification / "
                "attack-surface prioritization"
            ),
            evidence=evidence,
        )

    except Exception:

        logger.exception(
            "Dorking AI analysis failed."
        )

        return None


# ============================================================
# SQLi INDICATOR CHECK
# ============================================================

def _append_quote_to_parameters(
    url: str,
) -> Optional[str]:
    """
    Create a minimally modified test URL by appending
    a quote to the first existing parameter value.

    This is intentionally limited to already-discovered,
    explicitly in-scope parameterized URLs.
    """

    try:

        parsed = urllib.parse.urlsplit(
            url
        )

        pairs = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        if not pairs:
            return None

        modified = []

        for index, (
            name,
            value,
        ) in enumerate(pairs):

            if index == 0:
                value = value + "'"

            modified.append(
                (
                    name,
                    value,
                )
            )

        query = urllib.parse.urlencode(
            modified,
            doseq=True,
        )

        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                query,
                "",
            )
        )

    except Exception:

        return None


def check_sqli_indicator(
    url: str,
) -> Optional[dict]:

    test_url = _append_quote_to_parameters(
        url
    )

    if not test_url:
        return None

    try:

        response = requests.get(
            test_url,
            headers=get_random_headers(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )

        response_text = (
            response.text or ""
        ).lower()

        matched = [
            indicator
            for indicator in SQL_ERROR_INDICATORS
            if indicator in response_text
        ]

        if not matched:
            return None

        return {
            "url": url,
            "test_url": test_url,
            "status_code": response.status_code,
            "matched_indicators": matched,
            "final_url": response.url,
        }

    except requests.RequestException as exc:

        logger.debug(
            "SQLi indicator request failed for %s: %s",
            url,
            exc,
        )

        return None

    except Exception:

        logger.debug(
            "Unexpected SQLi indicator error for %s",
            url,
            exc_info=True,
        )

        return None


# ============================================================
# SQLi DISCOVERY
# ============================================================

def run_sqli_indicator_checks(
    urls: Iterable[str],
    scope_entries: set[str],
) -> list[dict]:

    candidates = []

    for url in urls:

        if not url_in_scope(
            url,
            scope_entries,
        ):
            continue

        metadata = classify_url(
            url
        )

        if not metadata[
            "parameterized"
        ]:
            continue

        candidates.append(
            metadata
        )

    candidates.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    candidates = candidates[
        :MAX_ACTIVE_SQLI_CHECKS
    ]

    if not candidates:

        print(
            YELLOW
            + "[*] No in-scope parameterized URLs "
              "available for SQLi indication testing."
            + RESET
        )

        return []

    print()

    print(
        CYAN
        + f"[*] Performing low-impact SQLi indication "
          f"checks against {len(candidates)} "
          f"in-scope URL(s)..."
        + RESET
    )

    findings = []

    for index, metadata in enumerate(
        candidates,
        start=1,
    ):

        url = metadata["url"]

        print(
            CYAN
            + f"[{index}/{len(candidates)}] Checking {url}"
            + RESET
        )

        finding = check_sqli_indicator(
            url
        )

        if finding:

            findings.append(
                finding
            )

            print(
                GREEN
                + "[!] SQLi error indicator observed: "
                  f"{url}"
                + RESET
            )

        else:

            print(
                "    No SQL error indicator observed."
            )

        time.sleep(
            random.uniform(
                MIN_ACTIVE_DELAY,
                MAX_ACTIVE_DELAY,
            )
        )

    return findings


def save_sqli_findings(
    findings: list[dict],
) -> Optional[Path]:

    if not findings:
        return None

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S-%f"
    )

    filename = (
        DORKING_REPORTS_DIR
        / f"{timestamp}_possible_sqli.json"
    )

    try:

        DORKING_REPORTS_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                findings,
                file,
                indent=2,
            )

        print(
            GREEN
            + f"[+] SQLi indicator report saved to {filename}"
            + RESET
        )

        return filename

    except OSError:

        logger.exception(
            "Failed to save SQLi findings."
        )

        return None


# ============================================================
# SQLMAP HANDOFF
# ============================================================

def choose_sqlmap_target(
    findings: list[dict],
    scope_entries: set[str],
) -> Optional[str]:

    safe_findings = []

    seen = set()

    for finding in findings:

        url = finding.get(
            "url"
        )

        if not isinstance(
            url,
            str,
        ):
            continue

        normalized = normalize_url(
            url
        )

        if not normalized:
            continue

        key = canonical_url_key(
            normalized
        )

        if not key:
            continue

        if key in seen:
            continue

        if not url_in_scope(
            normalized,
            scope_entries,
        ):
            continue

        seen.add(key)

        safe_findings.append(
            normalized
        )

    if not safe_findings:
        return None

    print()

    print(
        CYAN
        + "[?] Select an in-scope URL for SQLMap:"
        + RESET
    )

    for index, url in enumerate(
        safe_findings,
        start=1,
    ):

        print(
            f"  {index}. {url}"
        )

    selection = input(
        GREEN
        + "SQLMap target number > "
        + RESET
    ).strip()

    try:

        index = int(
            selection
        ) - 1

    except ValueError:

        print(
            RED
            + "[!] Invalid selection."
            + RESET
        )

        return None

    if not (
        0 <= index < len(safe_findings)
    ):

        print(
            RED
            + "[!] Invalid selection."
            + RESET
        )

        return None

    return safe_findings[index]


def handoff_to_sqlmap(
    findings: list[dict],
    scope_entries: set[str],
) -> None:

    target = choose_sqlmap_target(
        findings,
        scope_entries,
    )

    if not target:
        return

    # Final scope check immediately before active SQLMap execution.
    if not url_in_scope(
        target,
        scope_entries,
    ):

        print(
            RED
            + "[!] Scope validation failed. "
              "SQLMap execution blocked."
            + RESET
        )

        return

    print()

    print(
        CYAN
        + "[*] Launching Chanakya SQLMap module..."
        + RESET
    )

    try:

        sql_injection_advanced(
            target
        )

    except Exception:

        logger.exception(
            "SQLMap handoff failed."
        )

        print(
            RED
            + "[!] SQLMap handoff failed."
            + RESET
        )


# ============================================================
# DORK LOADING
# ============================================================

def load_dorks(
    scope_entries: Iterable[str],
) -> list[str]:
    """
    Generate a fresh dorks.txt using the already-authorized
    scope supplied by auto_dorking(), then load it.

    IMPORTANT:
        The scope is NOT requested again here.

        auto_dorking()
            ↓
        load_scope()
            ↓
        scope_entries
            ↓
        load_dorks(scope_entries)
            ↓
        generate_dorks_interactive(scope_entries)
    """

    dorks_file = (
        BASE_DIR / "dorks.txt"
    )

    print(
        CYAN
        + f"[*] Dork output path: {dorks_file}"
        + RESET
    )

    # --------------------------------------------------------
    # GENERATE
    # --------------------------------------------------------

    try:

        generated = generate_dorks_interactive(
            scope_entries=scope_entries,
            output_file=dorks_file,
        )

    except Exception as exc:

        logger.exception(
            "Dork generator failed."
        )

        print()

        print(
            RED
            + "[!] Dork generator exception:"
            + RESET
        )

        print(
            RED
            + f"    {type(exc).__name__}: {exc}"
            + RESET
        )

        print()

        print(
            YELLOW
            + "[!] Full traceback:"
            + RESET
        )

        traceback.print_exc()

        return []

    if not generated:

        print(
            YELLOW
            + "[!] No dorks were generated."
            + RESET
        )

        return []

    # --------------------------------------------------------
    # READ GENERATED FILE
    # --------------------------------------------------------

    try:

        with open(
            dorks_file,
            "r",
            encoding="utf-8",
        ) as file:

            raw_dorks = [
                line.strip()
                for line in file
                if (
                    line.strip()
                    and not line
                    .lstrip()
                    .startswith("#")
                )
            ]

    except OSError as exc:

        logger.exception(
            "Unable to read generated dorks.txt."
        )

        print(
            RED
            + f"[!] Unable to read generated dorks file: {exc}"
            + RESET
        )

        return []

    # --------------------------------------------------------
    # DEDUPLICATE
    # --------------------------------------------------------

    seen: set[str] = set()

    dorks: list[str] = []

    for dork in raw_dorks:

        normalized = dork.strip()

        if not normalized:
            continue

        key = normalized.casefold()

        if key in seen:
            continue

        seen.add(key)

        dorks.append(
            normalized
        )

    print(
        GREEN
        + f"[+] Loaded {len(dorks)} generated dorks "
          f"from {dorks_file}"
        + RESET
    )

    return dorks


# ============================================================
# DORKING WORKFLOW
# ============================================================

def auto_dorking() -> None:
    """
    Main scope-aware dorking workflow.

    Workflow:

        Load authorized scope
              ↓
        Generate dorks using same scope
              ↓
        Load dorks.txt
              ↓
        Search provider
              ↓
        Normalize URLs
              ↓
        Canonical deduplication
              ↓
        History filtering
              ↓
        Scope classification
              ↓
        Recon prioritization
              ↓
        Save reports
              ↓
        AI analysis
              ↓
        Low-impact SQLi indication
              ↓
        Optional SQLMap handoff
    """

    print()

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        CYAN
        + "              CHANAKYA DORKING ENGINE"
        + RESET
    )

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    # ========================================================
    # SCOPE
    # ========================================================

    scope_entries = load_scope()

    if not scope_entries:

        print(
            RED
            + "[!] No authorized scope supplied."
            + RESET
        )

        print(
            YELLOW
            + "[!] Dorking workflow stopped."
            + RESET
        )

        return

    # ========================================================
    # DORK GENERATION
    # ========================================================

    print()

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        CYAN
        + "                 AUTOMATIC DORK GENERATION"
        + RESET
    )

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        YELLOW
        + "[*] Chanakya will automatically generate dorks "
          "for the authorized scope."
        + RESET
    )

    print(
        YELLOW
        + "[*] Generated dorks will be saved to dorks.txt."
        + RESET
    )

    # IMPORTANT:
    # Pass the SAME authorized scope into the generator.
    dorks = load_dorks(
        scope_entries=scope_entries
    )

    if not dorks:

        print(
            YELLOW
            + "[!] No usable dorks generated."
            + RESET
        )

        return

    print(
        GREEN
        + f"[+] Loaded {len(dorks)} unique generated dorks."
        + RESET
    )

    # ========================================================
    # PROVIDER
    # ========================================================

    search_function, provider_name = (
        choose_dorking_method()
    )

    if search_function is None:

        return

    print(
        GREEN
        + f"[+] Provider: {provider_name}"
        + RESET
    )

    # ========================================================
    # HISTORY
    # ========================================================

    history = load_dorked_history()

    discovered_urls: dict[str, str] = {}

    in_scope_urls: dict[str, str] = {}

    out_of_scope_urls: dict[str, str] = {}

    # ========================================================
    # SEARCH
    # ========================================================

    for dork_index, dork in enumerate(
        dorks,
        start=1,
    ):

        print()

        print(
            CYAN
            + f"[{dork_index}/{len(dorks)}] "
              f"Searching: {dork}"
            + RESET
        )

        try:

            result_urls = search_function(
                dork
            )

        except Exception:

            logger.error(
                "Dork search failed for %s:\n%s",
                dork,
                traceback.format_exc(),
            )

            print(
                RED
                + "[!] Search provider error."
                + RESET
            )

            continue

        if not result_urls:

            print(
                YELLOW
                + "[!] No results."
                + RESET
            )

            continue

        urls = extract_urls_from_results(
            result_urls
        )

        print(
            GREEN
            + f"[+] Provider returned "
              f"{len(urls)} unique usable URL(s)."
            + RESET
        )

        new_for_run = 0

        for url in urls:

            key = canonical_url_key(
                url
            )

            if not key:
                continue

            # ------------------------------------------------
            # Global duplicate detection.
            # ------------------------------------------------

            if key in discovered_urls:
                continue

            discovered_urls[key] = url

            new_for_run += 1

            # ------------------------------------------------
            # Persistent history.
            # ------------------------------------------------

            previously_seen = (
                key in history
            )

            # ------------------------------------------------
            # Scope classification.
            # ------------------------------------------------

            if url_in_scope(
                url,
                scope_entries,
            ):

                in_scope_urls[key] = url

                marker = "IN-SCOPE"

                if previously_seen:

                    print(
                        CYAN
                        + f"[=] {marker} previously seen: {url}"
                        + RESET
                    )

                else:

                    print(
                        GREEN
                        + f"[+] {marker}: {url}"
                        + RESET
                    )

            else:

                out_of_scope_urls[key] = url

                print(
                    YELLOW
                    + f"[-] OUT-OF-SCOPE: {url}"
                    + RESET
                )

        print(
            CYAN
            + f"[*] New unique URLs this search: "
              f"{new_for_run}"
            + RESET
        )

        time.sleep(
            random.uniform(
                MIN_SEARCH_DELAY,
                MAX_SEARCH_DELAY,
            )
        )

    # ========================================================
    # NOTHING FOUND
    # ========================================================

    if not discovered_urls:

        print(
            YELLOW
            + "[*] No URLs discovered."
            + RESET
        )

        return

    # ========================================================
    # SAVE HISTORY
    # ========================================================

    save_dorked_history(
        discovered_urls.values()
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        CYAN
        + "                    RECON SUMMARY"
        + RESET
    )

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        f"Total unique URLs : {len(discovered_urls)}"
    )

    print(
        GREEN
        + f"In-scope URLs     : {len(in_scope_urls)}"
        + RESET
    )

    print(
        YELLOW
        + f"Out-of-scope URLs : {len(out_of_scope_urls)}"
        + RESET
    )

    # ========================================================
    # SAVE RESULTS
    # ========================================================

    save_dorking_results(
        discovered_urls.values(),
        filename_prefix="all_discovered",
    )

    save_dorking_results(
        in_scope_urls.values(),
        filename_prefix="in_scope",
    )

    # ========================================================
    # CLASSIFICATION
    # ========================================================

    prioritized = prioritize_urls(
        in_scope_urls.values()
    )

    save_json_report(
        prioritized,
        "prioritized_attack_surface",
    )

    parameterized_urls = [
        item["url"]
        for item in prioritized
        if item["parameterized"]
    ]

    save_dorking_results(
        parameterized_urls,
        filename_prefix="parameterized_in_scope",
    )

    print()

    print(
        GREEN
        + f"[+] In-scope parameterized URLs: "
          f"{len(parameterized_urls)}"
        + RESET
    )

    # ========================================================
    # AI ANALYSIS
    # ========================================================

    if in_scope_urls:

        print()

        print(
            CYAN
            + "[*] Sending in-scope reconnaissance "
              "to Chanakya AI..."
            + RESET
        )

        try:

            ai_result = analyze_dork_results(
                in_scope_urls.values()
            )

            if ai_result:

                print(
                    GREEN
                    + "[+] AI reconnaissance analysis completed."
                    + RESET
                )

        except Exception:

            logger.exception(
                "AI analysis failed."
            )

            print(
                YELLOW
                + "[!] AI analysis failed. "
                  "Continuing."
                + RESET
            )

    # ========================================================
    # ACTIVE SQLi INDICATION
    # ========================================================

    if not parameterized_urls:

        print(
            YELLOW
            + "[*] No parameterized in-scope URLs "
              "available for SQLi checks."
            + RESET
        )

        print(
            GREEN
            + "[+] Dorking workflow completed."
            + RESET
        )

        return

    print()

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        CYAN
        + "              SQLi INDICATION STAGE"
        + RESET
    )

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        YELLOW
        + "[!] Active requests are restricted to authorized scope."
        + RESET
    )

    choice = input(
        GREEN
        + "[?] Run low-impact SQLi indication checks? (yes/no) > "
        + RESET
    ).strip().lower()

    if choice not in {
        "yes",
        "y",
    }:

        print(
            YELLOW
            + "[*] SQLi indication stage skipped."
            + RESET
        )

        print(
            GREEN
            + "[+] Dorking workflow completed."
            + RESET
        )

        return

    findings = run_sqli_indicator_checks(
        parameterized_urls,
        scope_entries,
    )

    # ========================================================
    # SAVE SQLi FINDINGS
    # ========================================================

    if findings:

        save_sqli_findings(
            findings
        )

        print()

        print(
            GREEN
            + f"[+] {len(findings)} URL(s) produced "
              "SQL error indicators."
            + RESET
        )

        # ----------------------------------------------------
        # SQLMAP HANDOFF
        # ----------------------------------------------------

        sqlmap_choice = input(
            CYAN
            + "[?] Send one detected in-scope URL to SQLMap? "
              "(yes/no) > "
            + RESET
        ).strip().lower()

        if sqlmap_choice in {
            "yes",
            "y",
        }:

            handoff_to_sqlmap(
                findings,
                scope_entries,
            )

    else:

        print(
            YELLOW
            + "[*] No SQL error indicators detected."
            + RESET
        )

    # ========================================================
    # FINAL REPORT
    # ========================================================

    report = {
        "timestamp": datetime.now().isoformat(),
        "provider": provider_name,
        "authorized_scope": sorted(
            scope_entries
        ),
        "total_unique_urls": len(
            discovered_urls
        ),
        "in_scope_urls": len(
            in_scope_urls
        ),
        "out_of_scope_urls": len(
            out_of_scope_urls
        ),
        "parameterized_in_scope_urls": len(
            parameterized_urls
        ),
        "sql_error_indicator_findings": len(
            findings
        ),
    }

    final_report = save_json_report(
        report,
        "dorking_summary",
    )

    if final_report:

        print(
            GREEN
            + f"[+] Summary saved to {final_report}"
            + RESET
        )

    print()

    print(
        GREEN
        + "============================================================"
        + RESET
    )

    print(
        GREEN
        + "             DORKING WORKFLOW COMPLETED"
        + RESET
    )

    print(
        GREEN
        + "============================================================"
        + RESET
    )


# ============================================================
# OPTIONAL DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    try:

        auto_dorking()

    except KeyboardInterrupt:

        print(
            RED
            + "\n[!] Dorking interrupted by user."
            + RESET
        )

    except Exception:

        logger.exception(
            "Unhandled dorking exception."
        )

        print(
            RED
            + "[!] Dorking engine terminated unexpectedly."
            + RESET
        )

        print()
        traceback.print_exc()