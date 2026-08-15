"""
Chanakya Attack Engine
"""

from __future__ import annotations

import json
from pathlib import Path

from attack.idor import verify_idor
from utils.colors import (
    RED,
    GREEN,
    CYAN,
    YELLOW,
    RESET,
)


def _headers_from_cookie(
    cookie: str,
) -> dict[str, str]:

    return {
        "User-Agent": (
            "Chanakya-Security-Assessment/1.0"
        ),
        "Accept": (
            "application/json,text/plain,"
            "text/html;q=0.9,*/*;q=0.8"
        ),
        "Cookie": cookie.strip(),
    }


def run_idor():

    print()
    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        CYAN
        + "                     IDOR / BOLA"
        + RESET
    )

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print()
    print(
        YELLOW
        + "Use two authorized test accounts."
        + RESET
    )

    print(
        YELLOW
        + "Account A must own the object being tested."
        + RESET
    )

    print(
        YELLOW
        + "Account B must NOT own that object."
        + RESET
    )

    print()

    target = input(
        GREEN
        + "Target > "
        + RESET
    ).strip()

    if not target:
        print(
            RED
            + "[!] Target cannot be empty."
            + RESET
        )
        return

    endpoint = input(
        GREEN
        + "Endpoint "
          "(use {id} for the object identifier) > "
        + RESET
    ).strip()

    if not endpoint:
        print(
            RED
            + "[!] Endpoint cannot be empty."
            + RESET
        )
        return

    object_id = input(
        GREEN
        + "Object ID owned by Account A > "
        + RESET
    ).strip()

    if not object_id:
        print(
            RED
            + "[!] Object ID cannot be empty."
            + RESET
        )
        return

    cookie_a = input(
        GREEN
        + "Account A Cookie > "
        + RESET
    ).strip()

    cookie_b = input(
        GREEN
        + "Account B Cookie > "
        + RESET
    ).strip()

    if not cookie_a or not cookie_b:

        print(
            RED
            + "[!] Both authorization contexts are required."
            + RESET
        )

        return

    parameter = input(
        GREEN
        + "Object parameter name [id] > "
        + RESET
    ).strip()

    if not parameter:
        parameter = "id"

    finding = verify_idor(
        target=target,
        endpoint=endpoint,
        object_id=object_id,
        context_a_headers=_headers_from_cookie(
            cookie_a
        ),
        context_b_headers=_headers_from_cookie(
            cookie_b
        ),
        parameter_name=parameter,
    )

    if not finding:

        print(
            RED
            + "[!] IDOR verification failed."
            + RESET
        )

        return

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    reports_dir = (
        Path("reports")
        / "attacks"
        / "idor"
    )

    reports_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_file = (
        reports_dir
        / "idor_result.json"
    )

    with open(
        report_file,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            finding.to_dict(),
            file,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print(
        GREEN
        + f"[+] IDOR report saved: {report_file}"
        + RESET
    )

    