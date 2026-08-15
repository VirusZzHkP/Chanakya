"""
Chanakya XSS Validator
----------------------

Authorized XSS reflection and context assessment.

Workflow:
    1. Accept an authorized target URL.
    2. Identify query parameters.
    3. Establish a baseline response.
    4. Inject a unique inert XSS canary.
    5. Detect reflection.
    6. Determine reflection context.
    7. Produce evidence.
    8. Send evidence to Chanakya AI.
    9. Save a JSON assessment report.

IMPORTANT:
    This module intentionally does NOT:
        - execute JavaScript
        - use weaponized XSS payloads
        - attempt browser exploitation
        - steal cookies/tokens
        - perform credential theft

A reflected marker is evidence of reflection, not by itself
proof of exploitable XSS.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any, Optional
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

import requests

from utils.ai import analyze_with_ai
from utils.colors import (
    RED,
    GREEN,
    CYAN,
    YELLOW,
    RESET,
)


logger = logging.getLogger(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

REQUEST_TIMEOUT = 10

MAX_RESPONSE_SIZE = 2_000_000

MAX_REFLECTION_SNIPPETS = 10

REFLECTION_WINDOW = 300

REPORT_DIR = Path("reports/xss")

USER_AGENT = (
    "Chanakya-Security-Assessment/1.0 "
    "(Authorized Testing)"
)


# ============================================================
# HTTP SESSION
# ============================================================

def create_session() -> requests.Session:
    """
    Create a reusable HTTP session.

    The scanner does not disable TLS verification.
    """

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": (
                "text/html,"
                "application/xhtml+xml,"
                "application/json,"
                "*/*"
            ),
        }
    )

    return session


# ============================================================
# XSS CANARY
# ============================================================

def generate_canary() -> str:
    """
    Generate a unique inert marker.

    The marker contains no executable JavaScript.
    """

    return (
        "CHANAKYA_XSS_"
        + uuid.uuid4().hex[:16]
    )


# ============================================================
# TARGET VALIDATION
# ============================================================

def normalize_target(
    target: str,
) -> Optional[str]:
    """
    Normalize and validate the supplied target URL.
    """

    target = (target or "").strip()

    if not target:
        return None

    if not target.startswith(
        ("http://", "https://")
    ):
        target = "https://" + target

    try:

        parsed = urlsplit(target)

        if parsed.scheme not in {
            "http",
            "https",
        }:
            return None

        if not parsed.netloc:
            return None

        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.query,
                "",
            )
        )

    except Exception:

        return None


# ============================================================
# RESPONSE HELPERS
# ============================================================

def safe_response_text(
    response: requests.Response,
) -> str:
    """
    Safely retrieve a bounded response body.
    """

    try:

        text = response.text or ""

    except Exception:

        return ""

    if len(text) > MAX_RESPONSE_SIZE:

        return text[:MAX_RESPONSE_SIZE]

    return text


def response_fingerprint(
    response: requests.Response,
) -> dict[str, Any]:
    """
    Build a bounded response fingerprint.

    No cookies or authorization headers are stored.
    """

    body = safe_response_text(
        response
    )

    return {
        "status_code": response.status_code,
        "length": len(body),
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "final_url": response.url,
        "body_sample": body[:500],
    }


# ============================================================
# URL PARAMETER HANDLING
# ============================================================

def extract_parameters(
    url: str,
) -> list[tuple[str, str]]:
    """
    Extract query parameters from a URL.
    """

    try:

        parsed = urlsplit(url)

        return parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

    except Exception:

        return []


def replace_parameter(
    url: str,
    parameter: str,
    value: str,
) -> Optional[str]:
    """
    Replace exactly one occurrence of a query parameter.

    Other query parameters remain unchanged.
    """

    try:

        parsed = urlsplit(url)

        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        if not pairs:
            return None

        modified: list[
            tuple[str, str]
        ] = []

        replaced = False

        for name, current_value in pairs:

            if (
                name == parameter
                and not replaced
            ):

                modified.append(
                    (
                        name,
                        value,
                    )
                )

                replaced = True

            else:

                modified.append(
                    (
                        name,
                        current_value,
                    )
                )

        if not replaced:
            return None

        query = urlencode(
            modified,
            doseq=True,
        )

        return urlunsplit(
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


# ============================================================
# BASELINE
# ============================================================

def get_baseline(
    target: str,
    session: Optional[
        requests.Session
    ] = None,
) -> Optional[dict[str, Any]]:
    """
    Obtain a baseline response before injecting a marker.
    """

    own_session = False

    if session is None:

        session = create_session()

        own_session = True

    try:

        response = session.get(
            target,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )

        return {
            "url": target,
            "status_code": response.status_code,
            "fingerprint": response_fingerprint(
                response
            ),
        }

    except requests.RequestException as exc:

        logger.warning(
            "XSS baseline request failed: %s",
            exc,
        )

        return None

    finally:

        if own_session:

            session.close()


# ============================================================
# CONTEXT DETECTION
# ============================================================

def detect_context(
    body: str,
    marker: str,
) -> list[str]:
    """
    Determine where the reflected marker occurs.

    This is a heuristic classifier. It does not prove exploitability.
    """

    contexts: list[str] = []

    if not body or not marker:
        return contexts

    escaped_marker = re.escape(
        marker
    )

    # --------------------------------------------------------
    # HTML TEXT
    # --------------------------------------------------------

    html_text_pattern = re.compile(
        rf">[^<]{{0,500}}"
        rf"{escaped_marker}"
        rf"[^<]{{0,500}}<",
        re.IGNORECASE | re.DOTALL,
    )

    if html_text_pattern.search(body):

        contexts.append(
            "HTML_TEXT"
        )

    # --------------------------------------------------------
    # HTML ATTRIBUTE
    # --------------------------------------------------------

    quoted_attribute_pattern = re.compile(
        rf"<[^>]*\b[\w:-]+\s*=\s*"
        rf"(['\"])[^'\"]*"
        rf"{escaped_marker}"
        rf"[^'\"]*\1"
        rf"[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )

    if quoted_attribute_pattern.search(body):

        contexts.append(
            "HTML_ATTRIBUTE"
        )

    # Also detect unquoted attributes.

    unquoted_attribute_pattern = re.compile(
        rf"<[^>]*\b[\w:-]+\s*=\s*"
        rf"[^>\s]+"
        rf"{escaped_marker}"
        rf"[^>\s]*"
        rf"[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )

    if unquoted_attribute_pattern.search(body):

        contexts.append(
            "HTML_ATTRIBUTE"
        )

    # --------------------------------------------------------
    # SCRIPT
    # --------------------------------------------------------

    script_pattern = re.compile(
        rf"<script\b[^>]*>"
        rf".*?"
        rf"{escaped_marker}"
        rf".*?"
        rf"</script\s*>",
        re.IGNORECASE | re.DOTALL,
    )

    if script_pattern.search(body):

        contexts.append(
            "JAVASCRIPT"
        )

    # --------------------------------------------------------
    # STYLE
    # --------------------------------------------------------

    style_pattern = re.compile(
        rf"<style\b[^>]*>"
        rf".*?"
        rf"{escaped_marker}"
        rf".*?"
        rf"</style\s*>",
        re.IGNORECASE | re.DOTALL,
    )

    if style_pattern.search(body):

        contexts.append(
            "CSS"
        )

    # --------------------------------------------------------
    # HTML COMMENT
    # --------------------------------------------------------

    comment_pattern = re.compile(
        rf"<!--.*?"
        rf"{escaped_marker}"
        rf".*?-->",
        re.IGNORECASE | re.DOTALL,
    )

    if comment_pattern.search(body):

        contexts.append(
            "HTML_COMMENT"
        )

    return sorted(
        set(contexts)
    )


# ============================================================
# REFLECTION EXTRACTION
# ============================================================

def extract_reflection(
    body: str,
    marker: str,
    window: int = REFLECTION_WINDOW,
) -> list[str]:
    """
    Extract bounded snippets around reflected markers.
    """

    snippets: list[str] = []

    if not body or not marker:
        return snippets

    body_lower = body.lower()

    marker_lower = marker.lower()

    start = 0

    while True:

        position = body_lower.find(
            marker_lower,
            start,
        )

        if position == -1:
            break

        left = max(
            0,
            position - window,
        )

        right = min(
            len(body),
            position
            + len(marker)
            + window,
        )

        snippets.append(
            body[left:right]
        )

        start = (
            position
            + len(marker)
        )

        if (
            len(snippets)
            >= MAX_REFLECTION_SNIPPETS
        ):
            break

    return snippets


# ============================================================
# REFLECTION COUNT
# ============================================================

def count_reflections(
    body: str,
    marker: str,
) -> int:

    if not body or not marker:
        return 0

    return body.lower().count(
        marker.lower()
    )


# ============================================================
# PARAMETER TEST
# ============================================================

def test_parameter(
    target: str,
    parameter: str,
    original_value: str,
    session: Optional[
        requests.Session
    ] = None,
) -> Optional[dict[str, Any]]:
    """
    Test one query parameter using an inert unique marker.
    """

    own_session = False

    if session is None:

        session = create_session()

        own_session = True

    marker = generate_canary()

    test_url = replace_parameter(
        target,
        parameter,
        marker,
    )

    if not test_url:

        if own_session:
            session.close()

        return None

    try:

        response = session.get(
            test_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )

        body = safe_response_text(
            response
        )

        decoded_body = unescape(
            body
        )

        reflected_raw = (
            marker.lower()
            in body.lower()
        )

        reflected_decoded = (
            marker.lower()
            in decoded_body.lower()
        )

        reflected = (
            reflected_raw
            or reflected_decoded
        )

        contexts: list[str] = []

        snippets: list[str] = []

        if reflected:

            contexts = detect_context(
                decoded_body,
                marker,
            )

            snippets = extract_reflection(
                decoded_body,
                marker,
            )

        return {
            "parameter": parameter,
            "original_value": original_value,
            "test_url": test_url,
            "marker": marker,
            "status_code": response.status_code,
            "content_type": response.headers.get(
                "Content-Type",
                "",
            ),
            "response_length": len(body),
            "final_url": response.url,
            "reflected": reflected,
            "reflection_count": (
                count_reflections(
                    body,
                    marker,
                )
            ),
            "decoded_reflection": (
                reflected_decoded
            ),
            "contexts": contexts,
            "snippets": snippets,
        }

    except requests.RequestException as exc:

        logger.warning(
            "XSS request failed for %s: %s",
            parameter,
            exc,
        )

        return {
            "parameter": parameter,
            "original_value": original_value,
            "test_url": test_url,
            "marker": marker,
            "reflected": False,
            "error": str(exc),
        }

    finally:

        if own_session:

            session.close()


# ============================================================
# VERDICT
# ============================================================

def evaluate_xss(
    result: dict[str, Any],
) -> dict[str, Any]:
    """
    Evaluate reflection evidence.

    IMPORTANT:
        Reflection alone is not classified as confirmed XSS.
    """

    if not result.get(
        "reflected",
        False,
    ):

        return {
            "verdict": "NOT_REFLECTED",
            "confidence": "NONE",
            "severity": "informational",
            "reason": (
                "The unique inert canary was not "
                "observed in the response."
            ),
            "contexts": [],
        }

    contexts = result.get(
        "contexts",
        [],
    )

    if "JAVASCRIPT" in contexts:

        return {
            "verdict": "REFLECTED_IN_JAVASCRIPT_CONTEXT",
            "confidence": "HIGH",
            "severity": "medium",
            "reason": (
                "The inert canary was reflected inside "
                "a JavaScript context. Manual validation "
                "is required to determine exploitability."
            ),
            "contexts": contexts,
        }

    if "HTML_TEXT" in contexts:

        return {
            "verdict": "REFLECTED_HTML_TEXT",
            "confidence": "HIGH",
            "severity": "low",
            "reason": (
                "The inert canary was reflected in HTML "
                "text content."
            ),
            "contexts": contexts,
        }

    if "HTML_ATTRIBUTE" in contexts:

        return {
            "verdict": "REFLECTED_HTML_ATTRIBUTE",
            "confidence": "HIGH",
            "severity": "medium",
            "reason": (
                "The inert canary was reflected inside "
                "an HTML attribute context. Manual "
                "validation is required."
            ),
            "contexts": contexts,
        }

    if "HTML_COMMENT" in contexts:

        return {
            "verdict": "REFLECTED_HTML_COMMENT",
            "confidence": "HIGH",
            "severity": "informational",
            "reason": (
                "The inert canary was reflected inside "
                "an HTML comment."
            ),
            "contexts": contexts,
        }

    if "CSS" in contexts:

        return {
            "verdict": "REFLECTED_CSS_CONTEXT",
            "confidence": "HIGH",
            "severity": "medium",
            "reason": (
                "The inert canary was reflected inside "
                "a CSS context. Manual validation is "
                "required."
            ),
            "contexts": contexts,
        }

    return {
        "verdict": "REFLECTED_INPUT",
        "confidence": "MEDIUM",
        "severity": "low",
        "reason": (
            "The inert canary was reflected, but its "
            "exact rendering context could not be "
            "classified."
        ),
        "contexts": [],
    }


# ============================================================
# AI ANALYSIS
# ============================================================

def analyze_xss(
    target: str,
    evidence: dict[str, Any],
) -> Optional[Any]:
    """
    Send assessment evidence to Chanakya AI.
    """

    try:

        evidence_text = json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
        )

        return analyze_with_ai(
            target=target,
            scan_type=(
                "Cross-Site Scripting "
                "Reflection and Context Analysis"
            ),
            evidence=evidence_text,
        )

    except Exception as exc:

        logger.warning(
            "XSS AI analysis failed: %s",
            exc,
        )

        return None


# ============================================================
# REPORT
# ============================================================

def save_report(
    report: dict[str, Any],
) -> Optional[Path]:
    """
    Save JSON assessment report.
    """

    try:

        REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%d_%H-%M-%S-%f"
        )

        filename = (
            REPORT_DIR
            / f"{timestamp}_xss.json"
        )

        filename.write_text(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return filename

    except OSError as exc:

        logger.error(
            "Failed to save XSS report: %s",
            exc,
        )

        return None


# ============================================================
# MAIN XSS SCANNER
# ============================================================

def run_xss_scan(
    target: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Canonical Chanakya XSS scanner entry point.

    This function intentionally matches the scanner
    dispatcher contract.
    """

    print()
    print(
        CYAN
        + "=" * 60
        + RESET
    )

    print(
        CYAN
        + "                 CHANAKYA XSS"
        + RESET
    )

    print(
        CYAN
        + "=" * 60
        + RESET
    )

    print(
        YELLOW
        + "[!] Authorized testing only."
        + RESET
    )

    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    if target is None:

        target = input(
            GREEN
            + "Target URL > "
            + RESET
        ).strip()

    else:

        target = str(
            target
        ).strip()

    target = normalize_target(
        target
    )

    if not target:

        print(
            RED
            + "[!] Invalid target URL."
            + RESET
        )

        return None

    print(
        GREEN
        + f"[+] Target: {target}"
        + RESET
    )

    # --------------------------------------------------------
    # PARAMETERS
    # --------------------------------------------------------

    parameters = extract_parameters(
        target
    )

    if not parameters:

        print(
            YELLOW
            + "[!] No query parameters found."
            + RESET
        )

        print()
        print(
            "[*] Example:"
        )

        print(
            "    https://target.example/search?q=test"
        )

        return None

    print(
        GREEN
        + f"[+] Parameters found: {len(parameters)}"
        + RESET
    )

    for name, value in parameters:

        print(
            f"    - {name}={value}"
        )

    # --------------------------------------------------------
    # SESSION
    # --------------------------------------------------------

    session = create_session()

    try:

        # ----------------------------------------------------
        # BASELINE
        # ----------------------------------------------------

        print()
        print(
            CYAN
            + "[*] Obtaining baseline response..."
            + RESET
        )

        baseline = get_baseline(
            target,
            session=session,
        )

        if not baseline:

            print(
                RED
                + "[!] Baseline request failed."
                + RESET
            )

            return None

        baseline_status = baseline.get(
            "status_code"
        )

        baseline_length = (
            baseline.get(
                "fingerprint",
                {},
            ).get(
                "length"
            )
        )

        print(
            GREEN
            + "[+] Baseline obtained."
            + RESET
        )

        print(
            f"    Status : {baseline_status}"
        )

        print(
            f"    Length : {baseline_length}"
        )

        # ----------------------------------------------------
        # TEST PARAMETERS
        # ----------------------------------------------------

        findings: list[
            dict[str, Any]
        ] = []

        for index, (
            parameter,
            original_value,
        ) in enumerate(
            parameters,
            start=1,
        ):

            print()
            print(
                CYAN
                + f"[{index}/{len(parameters)}] "
                  f"Testing: {parameter}"
                + RESET
            )

            result = test_parameter(
                target=target,
                parameter=parameter,
                original_value=original_value,
                session=session,
            )

            if not result:

                print(
                    YELLOW
                    + "    Unable to construct test request."
                    + RESET
                )

                continue

            evaluation = evaluate_xss(
                result
            )

            finding = {
                **result,
                "evaluation": evaluation,
            }

            findings.append(
                finding
            )

            # ------------------------------------------------
            # DISPLAY
            # ------------------------------------------------

            verdict = evaluation.get(
                "verdict"
            )

            if verdict == "NOT_REFLECTED":

                print(
                    GREEN
                    + "    [+] Input not reflected."
                    + RESET
                )

            else:

                print(
                    YELLOW
                    + "    [!] Reflected input detected."
                    + RESET
                )

                print(
                    "        Verdict    : "
                    f"{verdict}"
                )

                print(
                    "        Confidence : "
                    f"{evaluation.get('confidence')}"
                )

                print(
                    "        Severity   : "
                    f"{evaluation.get('severity')}"
                )

                contexts = evaluation.get(
                    "contexts",
                    [],
                )

                print(
                    "        Context    : "
                    + (
                        ", ".join(contexts)
                        if contexts
                        else "unknown"
                    )
                )

                print(
                    "        Reflections: "
                    f"{result.get('reflection_count', 0)}"
                )

        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        reflected = [
            finding
            for finding in findings
            if finding.get(
                "evaluation",
                {},
            ).get(
                "verdict"
            )
            != "NOT_REFLECTED"
        ]

        javascript_contexts = [
            finding
            for finding in findings
            if "JAVASCRIPT"
            in finding.get(
                "evaluation",
                {},
            ).get(
                "contexts",
                [],
            )
        ]

        attribute_contexts = [
            finding
            for finding in findings
            if "HTML_ATTRIBUTE"
            in finding.get(
                "evaluation",
                {},
            ).get(
                "contexts",
                [],
            )
        ]

        report: dict[str, Any] = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "target": target,

            "vulnerability": (
                "Cross-Site Scripting"
            ),

            "assessment_type": (
                "Reflected XSS "
                "reflection/context assessment"
            ),

            "method": (
                "Inert unique-canary reflection "
                "and context analysis"
            ),

            "baseline": baseline,

            "parameters_tested": len(
                parameters
            ),

            "reflected_parameters": len(
                reflected
            ),

            "javascript_contexts": len(
                javascript_contexts
            ),

            "html_attribute_contexts": len(
                attribute_contexts
            ),

            "confirmed_xss": False,

            "manual_validation_required": (
                len(reflected) > 0
            ),

            "findings": findings,
        }

        # ----------------------------------------------------
        # AI
        # ----------------------------------------------------

        print()
        print(
            CYAN
            + "[*] Sending XSS evidence to "
              "Chanakya AI..."
            + RESET
        )

        ai_result = analyze_xss(
            target,
            report,
        )

        if ai_result:

            report["ai_analysis"] = (
                ai_result
            )

            print(
                GREEN
                + "[+] AI analysis completed."
                + RESET
            )

        else:

            report["ai_analysis"] = None

            print(
                YELLOW
                + "[!] AI analysis unavailable."
                + RESET
            )

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        report_path = save_report(
            report
        )

        if report_path:

            report[
                "report_path"
            ] = str(
                report_path
            )

            print(
                GREEN
                + f"[+] Evidence saved: {report_path}"
                + RESET
            )

        else:

            report[
                "report_path"
            ] = None

        # ----------------------------------------------------
        # FINAL RESULT
        # ----------------------------------------------------

        print()
        print(
            CYAN
            + "=" * 60
            + RESET
        )

        if reflected:

            print(
                YELLOW
                + "[!] REFLECTED INPUT FOUND"
                + RESET
            )

            print(
                "    Reflected parameters: "
                f"{len(reflected)}"
            )

            print(
                "    JavaScript contexts  : "
                f"{len(javascript_contexts)}"
            )

            print(
                "    Attribute contexts   : "
                f"{len(attribute_contexts)}"
            )

            print()

            print(
                YELLOW
                + "[!] Reflection does not by itself "
                  "confirm executable XSS."
                + RESET
            )

            print(
                "    Manual/browser validation is required."
            )

            for finding in reflected:

                parameter = finding.get(
                    "parameter",
                    "unknown",
                )

                contexts = finding.get(
                    "evaluation",
                    {},
                ).get(
                    "contexts",
                    [],
                )

                print()

                print(
                    f"    Parameter : {parameter}"
                )

                print(
                    "    Context   : "
                    + (
                        ", ".join(contexts)
                        if contexts
                        else "unknown"
                    )
                )

        else:

            print(
                GREEN
                + "[+] No reflected input detected."
                + RESET
            )

        print(
            CYAN
            + "=" * 60
            + RESET
        )

        return report

    finally:

        session.close()


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

def scan_xss(
    target: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Compatibility alias for the Chanakya dispatcher.
    """

    return run_xss_scan(
        target
    )


def xss_scan(
    target: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Compatibility alias for the Chanakya dispatcher.
    """

    return run_xss_scan(
        target
    )


def run_xss(
    target: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Compatibility alias for the Chanakya dispatcher.
    """

    return run_xss_scan(
        target
    )


def test_xss(
    target: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Compatibility alias for the Chanakya dispatcher.
    """

    return run_xss_scan(
        target
    )


# Preserve the original function name too.
def xss_test(
    target: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Backward-compatible alias for older Chanakya code.
    """

    return run_xss_scan(
        target
    )


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    try:

        run_xss_scan()

    except KeyboardInterrupt:

        print(
            RED
            + "\n[!] XSS testing interrupted."
            + RESET
        )

    except Exception as exc:

        logger.exception(
            "Unhandled XSS exception."
        )

        print(
            RED
            + f"[!] XSS module terminated unexpectedly: {exc}"
            + RESET
        )