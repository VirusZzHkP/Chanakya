"""
Chanakya Command Injection Validator
------------------------------------

Bounded, read-only command-injection assessment for
authorized security testing.

Design:
    - Baseline request
    - Controlled non-destructive probes
    - Response comparison
    - Evidence collection
    - AI-assisted analysis
    - JSON reporting

This module intentionally does NOT:
    - execute arbitrary attacker commands
    - spawn shells
    - create reverse shells
    - download payloads
    - establish persistence
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
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


# ============================================================
# CONFIGURATION
# ============================================================

REQUEST_TIMEOUT = 10

MAX_RESPONSE_SIZE = 2_000_000

MAX_BODY_PREVIEW = 1500

REQUEST_DELAY = 0.5

REPORT_DIR = Path(
    "reports"
) / "attacks" / "command_injection"

USER_AGENT = (
    "Chanakya-Security-Assessment/1.0 "
    "(Authorized Testing)"
)


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger(__name__)


# ============================================================
# CONTROLLED PROBES
# ============================================================

"""
These are intentionally limited validation probes.

They are NOT arbitrary OS commands.

The purpose is to detect obvious command-execution indicators
without providing a general-purpose command execution facility.
"""

PROBE_PATTERNS = (
    ";",
    "|",
    "&&",
)


# ============================================================
# HTTP HELPERS
# ============================================================

def request_headers() -> dict[str, str]:
    """
    Return standard headers used by Chanakya.
    """

    return {
        "User-Agent": USER_AGENT,
        "Accept": (
            "text/html,"
            "application/json,"
            "*/*"
        ),
    }


def safe_response_text(
    response: requests.Response,
) -> str:
    """
    Safely obtain a bounded response body.
    """

    try:
        body = response.text or ""

    except Exception:
        return ""

    if len(body) > MAX_RESPONSE_SIZE:
        return body[:MAX_RESPONSE_SIZE]

    return body


def body_hash(
    body: str,
) -> str:
    """
    SHA-256 fingerprint of a response body.
    """

    return hashlib.sha256(
        body.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def response_fingerprint(
    response: requests.Response,
) -> dict[str, Any]:
    """
    Build a compact response fingerprint.
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
        "body_hash": body_hash(body),
        "body_sample": body[:MAX_BODY_PREVIEW],
        "final_url": response.url,
    }


# ============================================================
# URL HELPERS
# ============================================================

def normalize_target(
    target: str,
) -> str:
    """
    Normalize the supplied target URL.
    """

    target = target.strip()

    if not target:
        return ""

    if not target.startswith(
        (
            "http://",
            "https://",
        )
    ):
        target = "https://" + target

    return target


def extract_parameters(
    url: str,
) -> list[tuple[str, str]]:
    """
    Extract query parameters from a URL.
    """

    try:

        parsed = urlsplit(
            url
        )

        return parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

    except Exception:

        return []


def parameterize_url(
    url: str,
    parameter: str,
    value: str,
) -> Optional[str]:
    """
    Replace exactly one query parameter.

    Returns None when the requested parameter
    does not exist.
    """

    try:

        parsed = urlsplit(
            url
        )

        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        if not pairs:
            return None

        modified = []

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
# HTTP REQUEST
# ============================================================

def perform_get(
    url: str,
) -> Optional[requests.Response]:
    """
    Perform a bounded GET request.
    """

    try:

        return requests.get(
            url,
            headers=request_headers(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )

    except requests.RequestException as exc:

        logger.warning(
            "HTTP request failed: %s",
            exc,
        )

        return None


# ============================================================
# BASELINE
# ============================================================

def obtain_baseline(
    url: str,
) -> Optional[dict[str, Any]]:
    """
    Obtain the normal response before probing.
    """

    response = perform_get(
        url
    )

    if response is None:
        return None

    return {
        "url": url,
        "fingerprint": response_fingerprint(
            response
        ),
    }


# ============================================================
# CONTROLLED PROBE
# ============================================================

def build_probe_value(
    original_value: str,
    separator: str,
    marker: str,
) -> str:
    """
    Build a controlled validation value.

    The probe contains only a deterministic marker and
    shell metacharacter. It does not contain a general
    arbitrary OS command.
    """

    return (
        f"{original_value}"
        f"{separator}"
        f"{marker}"
    )


def run_probe(
    url: str,
    parameter: str,
    original_value: str,
) -> Optional[dict[str, Any]]:
    """
    Run controlled command-injection probes against one
    query parameter.
    """

    marker = (
        "CHANAKYA_CI_"
        + uuid.uuid4().hex[:12]
    )

    tests: list[dict[str, Any]] = []

    for separator in PROBE_PATTERNS:

        probe_value = build_probe_value(
            original_value,
            separator,
            marker,
        )

        test_url = parameterize_url(
            url,
            parameter,
            probe_value,
        )

        if not test_url:
            continue

        response = perform_get(
            test_url
        )

        if response is None:

            tests.append(
                {
                    "separator": separator,
                    "probe_value": probe_value,
                    "request_url": test_url,
                    "error": (
                        "HTTP request failed"
                    ),
                    "marker_observed": False,
                }
            )

            continue

        body = safe_response_text(
            response
        )

        marker_observed = (
            marker.lower()
            in body.lower()
        )

        tests.append(
            {
                "separator": separator,
                "probe_value": probe_value,
                "request_url": test_url,
                "response": response_fingerprint(
                    response
                ),
                "marker": marker,
                "marker_observed": (
                    marker_observed
                ),
            }
        )

        time.sleep(
            REQUEST_DELAY
        )

    return {
        "parameter": parameter,
        "original_value": original_value,
        "marker": marker,
        "tests": tests,
    }


# ============================================================
# RESPONSE ANALYSIS
# ============================================================

def evaluate_probe(
    baseline: Optional[dict[str, Any]],
    probe_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Evaluate probe evidence.

    Important:
        Reflection of the marker alone is NOT treated as
        confirmed command execution because an application
        may simply reflect user input.

    A marker appearing in a response therefore produces
        REFLECTION_OBSERVED

    rather than a confirmed command-execution verdict.
    """

    tests = probe_result.get(
        "tests",
        [],
    )

    marker_reflected = any(
        test.get(
            "marker_observed",
            False,
        )
        for test in tests
    )

    baseline_status = None

    if baseline:

        baseline_status = (
            baseline.get(
                "fingerprint",
                {},
            ).get(
                "status_code"
            )
        )

    status_changes = []

    for test in tests:

        response = test.get(
            "response"
        )

        if not response:
            continue

        status = response.get(
            "status_code"
        )

        if (
            baseline_status is not None
            and status != baseline_status
        ):

            status_changes.append(
                {
                    "baseline_status": (
                        baseline_status
                    ),
                    "probe_status": status,
                    "separator": test.get(
                        "separator"
                    ),
                }
            )

    body_hashes = []

    for test in tests:

        response = test.get(
            "response"
        )

        if response:

            body_hashes.append(
                response.get(
                    "body_hash"
                )
            )

    body_changed = (
        len(
            set(
                hash_value
                for hash_value in body_hashes
                if hash_value
            )
        )
        > 1
    )

    if marker_reflected:

        verdict = (
            "REFLECTION_OBSERVED"
        )

        confidence = "LOW"

        explanation = (
            "The controlled marker was observed "
            "in the response. This demonstrates "
            "input reflection but does not by itself "
            "prove OS command execution."
        )

    elif status_changes or body_changed:

        verdict = (
            "ANOMALOUS_BEHAVIOR"
        )

        confidence = "LOW"

        explanation = (
            "The controlled probes produced response "
            "differences from the baseline. Further "
            "manual validation is required."
        )

    else:

        verdict = (
            "NO_INDICATOR"
        )

        confidence = "NONE"

        explanation = (
            "No command-execution indicator was "
            "observed during the bounded probes."
        )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "marker_reflected": marker_reflected,
        "status_changes": status_changes,
        "body_changed": body_changed,
        "explanation": explanation,
    }


# ============================================================
# AI ANALYSIS
# ============================================================

def analyze_command_injection(
    target: str,
    evidence: dict[str, Any],
) -> Optional[Any]:
    """
    Send collected evidence to the configured AI provider.
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
                "Command Injection Validation"
            ),
            evidence=evidence_text,
        )

    except Exception as exc:

        logger.warning(
            "Command injection AI analysis failed: %s",
            exc,
        )

        return None


# ============================================================
# REPORTING
# ============================================================

def save_report(
    report: dict[str, Any],
) -> Optional[Path]:
    """
    Save assessment evidence as JSON.
    """

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d_%H-%M-%S-%f"
    )

    report_file = (
        REPORT_DIR
        / f"command_injection_{timestamp}.json"
    )

    try:

        report_file.write_text(
            json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return report_file

    except OSError as exc:

        logger.error(
            "Unable to save command-injection "
            "report: %s",
            exc,
        )

        return None


# ============================================================
# DISPLAY
# ============================================================

def display_finding(
    finding: dict[str, Any],
) -> None:

    parameter = finding.get(
        "parameter",
        "unknown",
    )

    evaluation = finding.get(
        "evaluation",
        {},
    )

    verdict = evaluation.get(
        "verdict",
        "UNKNOWN",
    )

    confidence = evaluation.get(
        "confidence",
        "UNKNOWN",
    )

    print(
        f"    Parameter : {parameter}"
    )

    print(
        f"    Verdict   : {verdict}"
    )

    print(
        f"    Confidence: {confidence}"
    )

    if evaluation.get(
        "marker_reflected"
    ):

        print(
            YELLOW
            + "    [!] Controlled marker "
              "was reflected."
            + RESET
        )

    if evaluation.get(
        "status_changes"
    ):

        print(
            YELLOW
            + "    [!] HTTP status changes "
              "were observed."
            + RESET
        )


# ============================================================
# MAIN SCANNER
# ============================================================

def command_injection_test(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Main command-injection assessment.

    The launcher passes the target URL here.
    """

    print()

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    print(
        CYAN
        + "                 CHANAKYA COMMAND INJECTION"
        + RESET
    )

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    print(
        YELLOW
        + "[!] Authorized testing only."
        + RESET
    )

    target = normalize_target(
        target
    )

    if not target:

        print(
            RED
            + "[!] Target cannot be empty."
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

        print()

        print(
            YELLOW
            + "[!] No query parameters found."
            + RESET
        )

        print(
            "[*] This scanner currently tests "
            "query-string parameters."
        )

        print(
            "[*] Example:"
        )

        print(
            "    https://target.example/search?q=test"
        )

        return None

    print(
        GREEN
        + f"[+] Parameters discovered: "
          f"{len(parameters)}"
        + RESET
    )

    for name, value in parameters:

        print(
            f"    - {name}={value}"
        )

    # --------------------------------------------------------
    # BASELINE
    # --------------------------------------------------------

    print()

    print(
        CYAN
        + "[*] Obtaining baseline response..."
        + RESET
    )

    baseline = obtain_baseline(
        target
    )

    if baseline is None:

        print(
            RED
            + "[!] Unable to obtain baseline."
            + RESET
        )

        return None

    baseline_fp = baseline.get(
        "fingerprint",
        {},
    )

    print(
        GREEN
        + "[+] Baseline obtained."
        + RESET
    )

    print(
        f"    Status : "
        f"{baseline_fp.get('status_code')}"
    )

    print(
        f"    Length : "
        f"{baseline_fp.get('length')}"
    )

    findings: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # TEST PARAMETERS
    # --------------------------------------------------------

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
              f"Testing parameter: {parameter}"
            + RESET
        )

        probe_result = run_probe(
            url=target,
            parameter=parameter,
            original_value=original_value,
        )

        if not probe_result:

            print(
                YELLOW
                + "    [!] Probe failed."
                + RESET
            )

            continue

        evaluation = evaluate_probe(
            baseline,
            probe_result,
        )

        finding = {
            "parameter": parameter,
            "original_value": original_value,
            "evaluation": evaluation,
            "tests": probe_result.get(
                "tests",
                [],
            ),
        }

        findings.append(
            finding
        )

        display_finding(
            finding
        )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    reflection_count = sum(
        1
        for item in findings
        if item.get(
            "evaluation",
            {},
        ).get(
            "verdict"
        )
        == "REFLECTION_OBSERVED"
    )

    anomaly_count = sum(
        1
        for item in findings
        if item.get(
            "evaluation",
            {},
        ).get(
            "verdict"
        )
        == "ANOMALOUS_BEHAVIOR"
    )

    report: dict[str, Any] = {
        "attack_type": (
            "OS Command Injection"
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "target": target,
        "baseline": baseline,
        "findings": findings,
        "summary": {
            "parameters_tested": len(
                parameters
            ),
            "reflection_observed": (
                reflection_count
            ),
            "anomalous_parameters": (
                anomaly_count
            ),
            "confirmed_command_execution": 0,
        },
        "method": (
            "Bounded controlled-canary "
            "validation"
        ),
    }

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    print()

    print(
        CYAN
        + "[*] Sending command-injection evidence "
          "to Chanakya AI..."
        + RESET
    )

    ai_result = analyze_command_injection(
        target,
        report,
    )

    report["ai_analysis"] = (
        ai_result
    )

    if ai_result:

        print(
            GREEN
            + "[+] AI analysis completed."
            + RESET
        )

    else:

        print(
            YELLOW
            + "[!] AI analysis unavailable."
            + RESET
        )

    # --------------------------------------------------------
    # SAVE REPORT
    # --------------------------------------------------------

    report_path = save_report(
        report
    )

    if report_path:

        print()

        print(
            GREEN
            + f"[+] Evidence saved: {report_path}"
            + RESET
        )

    # --------------------------------------------------------
    # FINAL VERDICT
    # --------------------------------------------------------

    print()

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    if reflection_count:

        print(
            YELLOW
            + "[!] INPUT REFLECTION OBSERVED"
            + RESET
        )

        print(
            "    This is not sufficient by itself "
            "to confirm command execution."
        )

    elif anomaly_count:

        print(
            YELLOW
            + "[?] ANOMALOUS RESPONSE BEHAVIOR"
            + RESET
        )

        print(
            "    Manual validation is required."
        )

    else:

        print(
            GREEN
            + "[+] No command-injection indicator "
              "observed."
            + RESET
        )

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    return report


# ============================================================
# COMPATIBILITY ENTRY POINTS
# ============================================================
#
# IMPORTANT:
# Chanakya's launcher searches for one of several conventional
# scanner function names. The original module exposed only
# command_injection_test(), which caused:
#
#   No supported scanner function found
#
# These aliases make the module compatible with all of the
# names currently expected by your launcher.
#


def run_command_injection(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Launcher-compatible entry point.
    """

    return command_injection_test(
        target
    )


def scan_command_injection(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Launcher-compatible entry point.
    """

    return command_injection_test(
        target
    )


def command_injection_scan(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Launcher-compatible entry point.
    """

    return command_injection_test(
        target
    )


def test_command_injection(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Launcher-compatible entry point.
    """

    return command_injection_test(
        target
    )


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    try:

        target_input = input(
            "Authorized target URL > "
        ).strip()

        command_injection_test(
            target_input
        )

    except KeyboardInterrupt:

        print()

        print(
            YELLOW
            + "[!] Scan interrupted."
            + RESET
        )