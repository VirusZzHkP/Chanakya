"""
Chanakya AI Utility Layer
-------------------------

Provides the common interface between Chanakya scanners and
the centralized AI analysis engine.

Responsibilities:
    - Validate scanner evidence inputs.
    - Check AI availability.
    - Forward evidence to AIAnalyzer.
    - Display the resulting analysis.

This module does NOT:
    - Execute commands.
    - Perform scans.
    - Make network requests.
    - Control scanner behavior.
"""

from __future__ import annotations

from ai.analyzer import ai_analyzer

from utils.colors import (
    CYAN,
    MAGENTA,
    YELLOW,
    RESET,
)


def analyze_with_ai(
    target: str,
    scan_type: str,
    evidence: str,
):
    """
    Send existing scanner evidence to Chanakya's AI engine.

    This function performs analysis only.

    It does not:
        - execute commands
        - perform additional scanning
        - modify scanner behavior
        - interact with the target

    Parameters:
        target:
            Target associated with the scanner evidence.

        scan_type:
            Name/type of the scanner that produced the evidence.

        evidence:
            Raw or processed evidence produced by the scanner.

    Returns:
        AI analysis as a string, or None if analysis is unavailable
        or fails.
    """

    # ========================================================
    # INPUT VALIDATION
    # ========================================================

    if not isinstance(target, str) or not target.strip():

        print(
            YELLOW
            + "[!] AI analysis skipped: invalid target."
            + RESET
        )

        return None

    if not isinstance(scan_type, str) or not scan_type.strip():

        print(
            YELLOW
            + "[!] AI analysis skipped: invalid scan type."
            + RESET
        )

        return None

    if not isinstance(evidence, str) or not evidence.strip():

        print(
            YELLOW
            + "[!] AI analysis skipped: no evidence supplied."
            + RESET
        )

        return None

    target = target.strip()
    scan_type = scan_type.strip()
    evidence = evidence.strip()

    # ========================================================
    # AI AVAILABILITY
    # ========================================================

    if not ai_analyzer.available:

        print(
            YELLOW
            + "[!] AI analysis unavailable: "
              "no AI provider configured."
            + RESET
        )

        return None

    # ========================================================
    # AI ANALYSIS
    # ========================================================

    print(
        CYAN
        + "[*] Chanakya AI analyzing results using "
        + f"{ai_analyzer.status()}..."
        + RESET
    )

    try:

        result = ai_analyzer.analyze(
            target=target,
            scan_type=scan_type,
            evidence=evidence,
        )

    except ValueError as exc:

        print(
            YELLOW
            + f"[!] AI analysis input error: {exc}"
            + RESET
        )

        return None

    except Exception:

        print(
            YELLOW
            + "[!] AI analysis failed unexpectedly."
            + RESET
        )

        return None

    # ========================================================
    # EMPTY RESULT
    # ========================================================

    if not result:

        print(
            YELLOW
            + "[!] AI analysis failed or returned no result."
            + RESET
        )

        return None

    # ========================================================
    # DISPLAY RESULT
    # ========================================================

    print(
        "\n"
        + CYAN
        + "-" * 80
        + RESET
    )

    print(
        MAGENTA
        + "                 CHANAKYA AI ANALYSIS"
        + RESET
    )

    print(
        CYAN
        + "-" * 80
        + RESET
    )

    print(result)

    print(
        CYAN
        + "-" * 80
        + RESET
    )

    return result