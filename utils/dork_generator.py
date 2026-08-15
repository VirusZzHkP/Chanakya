"""
Chanakya Dork Generator
-----------------------

Automated Google-style dork generation for authorized reconnaissance.

Responsibilities:
    - Generate dorks from the already-authorized scope
    - Ask what reconnaissance objective is required
    - Provide Basic / Intermediate / Pro / Comprehensive profiles
    - Support custom category selection
    - Deduplicate generated dorks
    - Persist generated dorks to dorks.txt

This module ONLY generates search queries.
It does not execute searches or perform active scanning.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from utils.colors import (
    RED,
    GREEN,
    CYAN,
    YELLOW,
    RESET,
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DORKS_FILE = BASE_DIR / "dorks.txt"


# ============================================================
# DORK CATEGORIES
# ============================================================

DORK_CATEGORIES = {
    "1": {
        "name": "Web Application",
        "description": (
            "Login, admin, account, dashboard and application pages."
        ),
    },
    "2": {
        "name": "API & Endpoints",
        "description": (
            "API routes, REST-style endpoints and common API paths."
        ),
    },
    "3": {
        "name": "Parameters",
        "description": (
            "URLs containing common application parameters."
        ),
    },
    "4": {
        "name": "Documents",
        "description": (
            "Publicly indexed documents and common office files."
        ),
    },
    "5": {
        "name": "Directories",
        "description": (
            "Directory listings and exposed web directories."
        ),
    },
    "6": {
        "name": "Downloads",
        "description": (
            "Download, upload and file-related application surfaces."
        ),
    },
    "7": {
        "name": "Search & Content",
        "description": (
            "Search, article, product and content pages."
        ),
    },
    "8": {
        "name": "Redirects",
        "description": (
            "Redirect and return-style URL parameters."
        ),
    },
    "9": {
        "name": "Configuration / Metadata",
        "description": (
            "Common public metadata and configuration artifacts."
        ),
    },
}


# ============================================================
# CATEGORY TEMPLATES
# ============================================================

CATEGORY_TEMPLATES = {

    # --------------------------------------------------------
    # WEB APPLICATION
    # --------------------------------------------------------

    "1": [
        'site:{scope} inurl:login',
        'site:{scope} inurl:signin',
        'site:{scope} inurl:signup',
        'site:{scope} inurl:register',
        'site:{scope} inurl:admin',
        'site:{scope} inurl:administrator',
        'site:{scope} inurl:dashboard',
        'site:{scope} inurl:account',
        'site:{scope} inurl:profile',
        'site:{scope} inurl:portal',
        'site:{scope} inurl:panel',
    ],

    # --------------------------------------------------------
    # API
    # --------------------------------------------------------

    "2": [
        'site:{scope} inurl:api',
        'site:{scope} inurl:api/v1',
        'site:{scope} inurl:api/v2',
        'site:{scope} inurl:api/v3',
        'site:{scope} inurl:rest',
        'site:{scope} inurl:graphql',
        'site:{scope} inurl:swagger',
        'site:{scope} inurl:openapi',
        'site:{scope} inurl:documentation',
        'site:{scope} inurl:endpoint',
    ],

    # --------------------------------------------------------
    # PARAMETERS
    # --------------------------------------------------------

    "3": [
        'site:{scope} inurl:?id=',
        'site:{scope} inurl:?page=',
        'site:{scope} inurl:?item=',
        'site:{scope} inurl:?product=',
        'site:{scope} inurl:?cat=',
        'site:{scope} inurl:?category=',
        'site:{scope} inurl:?user=',
        'site:{scope} inurl:?uid=',
        'site:{scope} inurl:?search=',
        'site:{scope} inurl:?query=',
        'site:{scope} inurl:?file=',
        'site:{scope} inurl:?url=',
        'site:{scope} inurl:?redirect=',
        'site:{scope} inurl:?next=',
    ],

    # --------------------------------------------------------
    # DOCUMENTS
    # --------------------------------------------------------

    "4": [
        'site:{scope} filetype:pdf',
        'site:{scope} filetype:doc',
        'site:{scope} filetype:docx',
        'site:{scope} filetype:xls',
        'site:{scope} filetype:xlsx',
        'site:{scope} filetype:ppt',
        'site:{scope} filetype:pptx',
        'site:{scope} filetype:txt',
        'site:{scope} filetype:csv',
    ],

    # --------------------------------------------------------
    # DIRECTORIES
    # --------------------------------------------------------

    "5": [
        'site:{scope} intitle:"index of"',
        'site:{scope} intitle:"index of" uploads',
        'site:{scope} intitle:"index of" files',
        'site:{scope} intitle:"index of" documents',
        'site:{scope} intitle:"index of" backup',
        'site:{scope} intitle:"index of" download',
    ],

    # --------------------------------------------------------
    # DOWNLOADS
    # --------------------------------------------------------

    "6": [
        'site:{scope} inurl:download',
        'site:{scope} inurl:downloads',
        'site:{scope} inurl:upload',
        'site:{scope} inurl:uploads',
        'site:{scope} inurl:file',
        'site:{scope} inurl:files',
        'site:{scope} inurl:attachment',
        'site:{scope} inurl:document',
    ],

    # --------------------------------------------------------
    # SEARCH / CONTENT
    # --------------------------------------------------------

    "7": [
        'site:{scope} inurl:search',
        'site:{scope} inurl:query',
        'site:{scope} inurl:article',
        'site:{scope} inurl:news',
        'site:{scope} inurl:product',
        'site:{scope} inurl:item',
        'site:{scope} inurl:view',
        'site:{scope} inurl:content',
    ],

    # --------------------------------------------------------
    # REDIRECTS
    # --------------------------------------------------------

    "8": [
        'site:{scope} inurl:redirect',
        'site:{scope} inurl:return',
        'site:{scope} inurl:returnurl',
        'site:{scope} inurl:next',
        'site:{scope} inurl:continue',
        'site:{scope} inurl:redirecturl',
    ],

    # --------------------------------------------------------
    # CONFIGURATION / METADATA
    # --------------------------------------------------------

    "9": [
        'site:{scope} filetype:xml',
        'site:{scope} filetype:json',
        'site:{scope} filetype:csv',
        'site:{scope} ext:conf',
        'site:{scope} ext:log',
        'site:{scope} ext:bak',
        'site:{scope} ext:old',
        'site:{scope} ext:backup',
    ],
}


# ============================================================
# OBJECTIVES
# ============================================================

OBJECTIVES = {
    "1": {
        "name": "Web Applications",
        "categories": {"1", "3", "7"},
    },

    "2": {
        "name": "Authentication / Login",
        "categories": {"1"},
    },

    "3": {
        "name": "APIs & Endpoints",
        "categories": {"2"},
    },

    "4": {
        "name": "Parameters / Dynamic Pages",
        "categories": {"3"},
    },

    "5": {
        "name": "Documents & Public Files",
        "categories": {"4"},
    },

    "6": {
        "name": "Directories / Downloads",
        "categories": {"5", "6"},
    },

    "7": {
        "name": "Search / Content / Products",
        "categories": {"7"},
    },

    "8": {
        "name": "Redirects",
        "categories": {"8"},
    },

    "9": {
        "name": "Configuration / Metadata",
        "categories": {"9"},
    },

    "10": {
        "name": "Everything",
        "categories": set(DORK_CATEGORIES.keys()),
    },
}


# ============================================================
# PROFILES
# ============================================================

PROFILES = {
    "1": {
        "name": "BASIC",
        "description": "Small, fast reconnaissance set.",
        "categories": {
            "1",
            "2",
            "3",
        },
    },

    "2": {
        "name": "INTERMEDIATE",
        "description": "Broader application and content reconnaissance.",
        "categories": {
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
        },
    },

    "3": {
        "name": "PRO",
        "description": "Full reconnaissance category set.",
        "categories": {
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
        },
    },

    "4": {
        "name": "COMPREHENSIVE",
        "description": "Maximum available generated query set.",
        "categories": set(DORK_CATEGORIES.keys()),
    },
}


# ============================================================
# SCOPE NORMALIZATION
# ============================================================

def normalize_scope(scope: str) -> str:
    """
    Normalize an authorized scope entry for search queries.
    """

    if not isinstance(scope, str):
        return ""

    scope = scope.strip().lower()

    if not scope:
        return ""

    scope = scope.replace("https://", "")
    scope = scope.replace("http://", "")

    scope = scope.split("/", 1)[0]

    return scope.strip()


# ============================================================
# DISPLAY OBJECTIVES
# ============================================================

def display_objectives() -> None:
    print()
    print(
        CYAN
        + "What do you want Chanakya to find?"
        + RESET
    )

    print(
        CYAN
        + "-" * 70
        + RESET
    )

    for key, objective in OBJECTIVES.items():
        print(
            f"{GREEN}{key}. {objective['name']}{RESET}"
        )


# ============================================================
# OBJECTIVE SELECTION
# ============================================================

def choose_objective() -> tuple[str, set[str]]:
    """
    Select the reconnaissance objective.

    Returns:
        objective name
        category set
    """

    display_objectives()

    choice = input(
        GREEN
        + "\nObjective > "
        + RESET
    ).strip()

    objective = OBJECTIVES.get(choice)

    if objective is None:

        print(
            YELLOW
            + "[!] Invalid objective. Using Everything."
            + RESET
        )

        objective = OBJECTIVES["10"]

    return (
        objective["name"],
        set(objective["categories"]),
    )


# ============================================================
# DISPLAY CATEGORIES
# ============================================================

def display_categories() -> None:
    print()
    print(
        CYAN
        + "Available Dork Categories"
        + RESET
    )

    print(
        CYAN
        + "-" * 70
        + RESET
    )

    for key, category in DORK_CATEGORIES.items():

        print(
            f"{GREEN}{key}. {category['name']}{RESET}"
        )

        print(
            f"   {category['description']}"
        )


# ============================================================
# CUSTOM CATEGORY SELECTION
# ============================================================

def choose_categories() -> set[str]:
    """
    Interactive custom category selection.
    """

    display_categories()

    print()
    print(
        YELLOW
        + "[*] Enter category numbers separated by commas."
        + RESET
    )

    print(
        YELLOW
        + "[*] Example: 1,2,3,6"
        + RESET
    )

    value = input(
        GREEN
        + "Categories > "
        + RESET
    ).strip()

    if not value:
        return set()

    selected = set()

    for item in value.split(","):

        item = item.strip()

        if item in DORK_CATEGORIES:
            selected.add(item)

    return selected


# ============================================================
# PROFILE SELECTION
# ============================================================

def choose_profile(
    objective_categories: set[str],
) -> tuple[str, set[str]]:
    """
    Select the generation depth.

    The selected profile is intersected with the objective
    categories so the generated queries remain focused.
    """

    print()
    print(
        CYAN
        + "Select Dorking Slab"
        + RESET
    )

    print(
        CYAN
        + "-" * 70
        + RESET
    )

    for key, profile in PROFILES.items():

        print(
            f"{GREEN}{key}. {profile['name']}{RESET}"
        )

        print(
            f"   {profile['description']}"
        )

    print()
    print("5. Custom")
    print("   Choose exact categories manually")

    choice = input(
        GREEN
        + "\nSlab > "
        + RESET
    ).strip()

    if choice in PROFILES:

        profile = PROFILES[choice]

        categories = (
            set(profile["categories"])
            & set(objective_categories)
        )

        return (
            profile["name"],
            categories,
        )

    if choice == "5":

        categories = choose_categories()

        return (
            "CUSTOM",
            categories,
        )

    print(
        YELLOW
        + "[!] Invalid slab. Using Basic."
        + RESET
    )

    categories = (
        set(PROFILES["1"]["categories"])
        & set(objective_categories)
    )

    return (
        PROFILES["1"]["name"],
        categories,
    )


# ============================================================
# DORK GENERATION
# ============================================================

def generate_dorks(
    scope_entries: Iterable[str],
    categories: set[str],
) -> list[str]:
    """
    Generate unique dorks for all authorized scope entries.
    """

    generated: list[str] = []
    seen: set[str] = set()

    for raw_scope in scope_entries:

        scope = normalize_scope(raw_scope)

        if not scope:
            continue

        for category in sorted(categories):

            templates = CATEGORY_TEMPLATES.get(
                category,
                [],
            )

            for template in templates:

                dork = template.format(
                    scope=scope,
                ).strip()

                if not dork:
                    continue

                key = dork.lower()

                if key in seen:
                    continue

                seen.add(key)

                generated.append(dork)

    return generated


# ============================================================
# SAVE DORKS
# ============================================================

def save_dorks(
    dorks: Iterable[str],
    profile: str,
    objective: str,
    output_file: Path = DORKS_FILE,
) -> Path:
    """
    Save generated dorks to dorks.txt.
    """

    dorks = list(dorks)

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    lines = [
        "# ============================================================",
        "# CHANAKYA GENERATED DORKS",
        "# ============================================================",
        f"# Objective: {objective}",
        f"# Profile: {profile}",
        f"# Generated: {timestamp}",
        f"# Total dorks: {len(dorks)}",
        "#",
        "# Automatically generated by Chanakya.",
        "# Intended for authorized reconnaissance only.",
        "# ============================================================",
        "",
    ]

    lines.extend(dorks)

    output_file.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return output_file


# ============================================================
# MAIN GENERATOR
# ============================================================

def generate_dorks_interactive(
    scope_entries: Iterable[str],
    output_file: Path = DORKS_FILE,
) -> list[str]:
    """
    Complete automated dork-generation workflow.

    IMPORTANT:
        scope_entries are supplied by the caller.

        This function does NOT ask the user to enter the
        authorized domain again.

    Workflow:

        Authorized scope
            ↓
        Objective
            ↓
        Slab
            ↓
        Automatic generation
            ↓
        dorks.txt
            ↓
        Return generated dorks

    Returns:
        List of generated dorks.
    """

    normalized_scopes = []

    for scope in scope_entries:

        normalized = normalize_scope(scope)

        if normalized:
            normalized_scopes.append(normalized)

    # --------------------------------------------------------
    # VALIDATE SCOPE
    # --------------------------------------------------------

    if not normalized_scopes:

        print(
            RED
            + "[!] Cannot generate dorks without authorized scope."
            + RESET
        )

        return []

    # --------------------------------------------------------
    # DISPLAY SCOPE
    # --------------------------------------------------------

    print()
    print(
        CYAN
        + "=" * 70
        + RESET
    )

    print(
        CYAN
        + "              AUTOMATED DORK GENERATOR"
        + RESET
    )

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    print()
    print(
        CYAN
        + "Authorized scope:"
        + RESET
    )

    for scope in normalized_scopes:

        print(
            GREEN
            + f"  [+] {scope}"
            + RESET
        )

    # --------------------------------------------------------
    # OBJECTIVE
    # --------------------------------------------------------

    objective, objective_categories = choose_objective()

    if not objective_categories:

        print(
            RED
            + "[!] No categories are available for this objective."
            + RESET
        )

        return []

    # --------------------------------------------------------
    # SLAB
    # --------------------------------------------------------

    profile, categories = choose_profile(
        objective_categories=objective_categories,
    )

    if not categories:

        print(
            RED
            + "[!] The selected slab has no categories "
              "for this objective."
            + RESET
        )

        return []

    # --------------------------------------------------------
    # GENERATE
    # --------------------------------------------------------

    print()
    print(
        CYAN
        + "[*] Generating dorks automatically..."
        + RESET
    )

    dorks = generate_dorks(
        scope_entries=normalized_scopes,
        categories=categories,
    )

    if not dorks:

        print(
            RED
            + "[!] No dorks were generated."
            + RESET
        )

        return []

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    try:

        saved = save_dorks(
            dorks=dorks,
            profile=profile,
            objective=objective,
            output_file=output_file,
        )

    except OSError as exc:

        print(
            RED
            + f"[!] Failed to save dorks.txt: {exc}"
            + RESET
        )

        return []

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    print()
    print(
        GREEN
        + f"[+] Generated {len(dorks)} unique dorks."
        + RESET
    )

    print(
        GREEN
        + f"[+] Saved automatically to: {saved}"
        + RESET
    )

    print()
    print(
        CYAN
        + f"[*] Objective: {objective}"
        + RESET
    )

    print(
        CYAN
        + f"[*] Slab: {profile}"
        + RESET
    )

    print(
        CYAN
        + "[*] Categories:"
        + RESET
    )

    for category in sorted(categories):

        category_name = DORK_CATEGORIES[
            category
        ]["name"]

        print(
            f"  {GREEN}[+]{RESET} {category_name}"
        )

    return dorks