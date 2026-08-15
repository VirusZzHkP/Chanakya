"""
Chanakya IDOR / BOLA verifier.

This module performs bounded, read-only authorization testing.

The operator supplies:
    - Target
    - Endpoint
    - Object identifier
    - Two authorized test contexts

The scanner compares:

    Context A -> Object A
    Context B -> Object A

A potential IDOR/BOLA condition is reported when Context B,
which should not own Object A, receives equivalent protected
resource data.

This module does NOT perform destructive operations.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from typing import Optional

import requests

from attack.models import (
    HTTPResponseEvidence,
    IDORFinding,
)

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

MAX_BODY_PREVIEW = 1000


# ============================================================
# RESPONSE HELPERS
# ============================================================

def _body_hash(body: str) -> str:
    """
    Generate a SHA-256 hash of the response body.
    """

    return hashlib.sha256(
        body.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def _safe_preview(
    body: str,
) -> str:
    """
    Normalize and truncate response body for evidence.
    """

    body = body or ""

    body = re.sub(
        r"\s+",
        " ",
        body,
    ).strip()

    return body[:MAX_BODY_PREVIEW]


def build_response_evidence(
    response: requests.Response,
) -> HTTPResponseEvidence:
    """
    Convert a requests.Response into structured evidence.
    """

    body = response.text or ""

    return HTTPResponseEvidence(
        status_code=response.status_code,
        url=response.url,
        content_length=len(body),
        content_type=response.headers.get(
            "Content-Type",
            "",
        ),
        body_hash=_body_hash(body),
        body_preview=_safe_preview(body),
    )


# ============================================================
# REQUEST
# ============================================================

def perform_request(
    url: str,
    headers: dict[str, str],
) -> Optional[HTTPResponseEvidence]:
    """
    Perform a bounded read-only GET request.
    """

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )

        return build_response_evidence(
            response
        )

    except requests.RequestException as exc:

        print(
            RED
            + f"[!] Request failed: {exc}"
            + RESET
        )

        return None


# ============================================================
# RESPONSE COMPARISON
# ============================================================

def compare_responses(
    baseline: HTTPResponseEvidence,
    cross_context: HTTPResponseEvidence,
) -> tuple[bool, list[str]]:
    """
    Compare Context A and Context B responses.

    A potential IDOR/BOLA is only considered strongly indicated
    when both contexts receive successful responses and the
    protected response bodies are identical.
    """

    evidence: list[str] = []

    successful_codes = {
        200,
        206,
    }

    rejection_codes = {
        401,
        403,
    }

    baseline_success = (
        baseline.status_code
        in successful_codes
    )

    cross_success = (
        cross_context.status_code
        in successful_codes
    )

    # --------------------------------------------------------
    # Context A
    # --------------------------------------------------------

    if baseline_success:

        evidence.append(
            "Context A successfully accessed the object."
        )

    else:

        evidence.append(
            "Context A did not receive a successful "
            "protected-resource response."
        )

    # --------------------------------------------------------
    # Context B
    # --------------------------------------------------------

    if cross_success:

        evidence.append(
            "Context B also received a successful response "
            "for the same object."
        )

    # --------------------------------------------------------
    # Authorization rejection
    # --------------------------------------------------------

    if cross_context.status_code in rejection_codes:

        evidence.append(
            "Context B was rejected with an authorization "
            "response."
        )

        return False, evidence

    # --------------------------------------------------------
    # Exact body comparison
    # --------------------------------------------------------

    if (
        baseline.body_hash
        == cross_context.body_hash
        and baseline.content_length > 0
    ):

        evidence.append(
            "The protected response body was identical "
            "between the two authorization contexts."
        )

    else:

        evidence.append(
            "The response bodies were not identical."
        )

    # --------------------------------------------------------
    # Strong indication
    # --------------------------------------------------------

    strong_match = (
        baseline_success
        and cross_success
        and baseline.body_hash
        == cross_context.body_hash
        and baseline.content_length > 0
    )

    return strong_match, evidence


# ============================================================
# AI ANALYSIS
# ============================================================

def analyze_idor_with_ai(
    finding: IDORFinding,
) -> Optional[object]:
    """
    Send structured IDOR evidence to Chanakya AI.
    """

    evidence = {
        "attack_type": finding.attack_type,
        "target": finding.target,
        "endpoint": finding.endpoint,
        "parameter": finding.parameter,
        "object_a": finding.object_a,
        "object_b": finding.object_b,
        "status": finding.status,
        "confidence": finding.confidence,
        "severity": finding.severity,

        "baseline": (
            asdict(finding.baseline)
            if finding.baseline
            else None
        ),

        "cross_context": (
            asdict(finding.cross_context)
            if finding.cross_context
            else None
        ),

        "evidence": finding.evidence,
    }

    try:

        return analyze_with_ai(
            target=finding.target,
            scan_type=(
                "IDOR / BOLA authorization verification"
            ),
            evidence=json.dumps(
                evidence,
                indent=2,
                ensure_ascii=False,
            ),
        )

    except Exception as exc:

        print(
            YELLOW
            + f"[!] AI analysis failed: {exc}"
            + RESET
        )

        return None


# ============================================================
# URL BUILDER
# ============================================================

def build_object_url(
    endpoint: str,
    object_id: str,
    parameter_name: str = "id",
) -> str:
    """
    Build the final object URL.

    Supported endpoint formats:

        https://example.com/api/user/{id}

        https://example.com/api/user/{object_id}

        https://example.com/api/user
            -> ?id=<object_id>
    """

    endpoint = endpoint.strip()

    if "{id}" in endpoint:

        return endpoint.replace(
            "{id}",
            object_id,
        )

    if "{object_id}" in endpoint:

        return endpoint.replace(
            "{object_id}",
            object_id,
        )

    separator = (
        "&"
        if "?" in endpoint
        else "?"
    )

    return (
        endpoint
        + separator
        + f"{parameter_name}={object_id}"
    )


# ============================================================
# HEADER INPUT
# ============================================================

def get_authorization_headers(
    context_name: str,
) -> dict[str, str]:
    """
    Collect authorization headers for a test context.

    The operator can provide a complete Authorization value,
    for example:

        Bearer eyJ...

    or:

        Basic xxxxxxxxx

    An empty value means no Authorization header is sent.
    """

    print()

    print(
        CYAN
        + f"{context_name} AUTHORIZATION"
        + RESET
    )

    print(
        YELLOW
        + "[*] Enter the Authorization header value."
        + RESET
    )

    print(
        YELLOW
        + "[*] Example: Bearer <token>"
        + RESET
    )

    print(
        YELLOW
        + "[*] Leave empty if no Authorization header is required."
        + RESET
    )

    authorization = input(
        GREEN
        + f"{context_name} Authorization > "
        + RESET
    ).strip()

    if not authorization:

        return {}

    return {
        "Authorization": authorization,
    }


# ============================================================
# IDOR VERIFICATION
# ============================================================

def verify_idor(
    target: str,
    endpoint: str,
    object_id: str,
    context_a_headers: dict[str, str],
    context_b_headers: dict[str, str],
    parameter_name: str = "id",
) -> Optional[IDORFinding]:
    """
    Verify whether Context B can access Object A.

    Example:

        target:
            https://app.example.test

        endpoint:
            https://app.example.test/api/users/{id}

        object_id:
            1001

    Context A should be authorized to access Object A.

    Context B should NOT be authorized to access Object A.
    """

    endpoint = endpoint.strip()

    object_id = object_id.strip()

    if not endpoint:

        print(
            RED
            + "[!] Endpoint cannot be empty."
            + RESET
        )

        return None

    if not object_id:

        print(
            RED
            + "[!] Object ID cannot be empty."
            + RESET
        )

        return None

    url = build_object_url(
        endpoint=endpoint,
        object_id=object_id,
        parameter_name=parameter_name,
    )

    print()

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        CYAN
        + "                  IDOR / BOLA VERIFIER"
        + RESET
    )

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        f"Target      : {target}"
    )

    print(
        f"Endpoint    : {url}"
    )

    print(
        f"Object      : {object_id}"
    )

    # --------------------------------------------------------
    # Context A
    # --------------------------------------------------------

    print()

    print(
        CYAN
        + "[1/2] Testing authorized owner context..."
        + RESET
    )

    baseline = perform_request(
        url,
        context_a_headers,
    )

    if not baseline:

        return None

    print(
        f"    Status: {baseline.status_code}"
    )

    print(
        f"    Size  : {baseline.content_length}"
    )

    # --------------------------------------------------------
    # Context B
    # --------------------------------------------------------

    print()

    print(
        CYAN
        + "[2/2] Testing second authorization context..."
        + RESET
    )

    cross_context = perform_request(
        url,
        context_b_headers,
    )

    if not cross_context:

        return None

    print(
        f"    Status: {cross_context.status_code}"
    )

    print(
        f"    Size  : {cross_context.content_length}"
    )

    # --------------------------------------------------------
    # Comparison
    # --------------------------------------------------------

    vulnerable, evidence = compare_responses(
        baseline,
        cross_context,
    )

    if vulnerable:

        status = "potential_vulnerability"

        confidence = "high"

        severity = "high"

        print()

        print(
            RED
            + "[!] Potential IDOR/BOLA detected."
            + RESET
        )

    else:

        status = "not_confirmed"

        confidence = "low"

        severity = "informational"

        print()

        print(
            GREEN
            + "[+] Cross-context unauthorized access "
              "was not confirmed."
            + RESET
        )

    # --------------------------------------------------------
    # Build finding
    # --------------------------------------------------------

    finding = IDORFinding(
        attack_type="IDOR/BOLA",
        target=target,
        endpoint=url,
        parameter=parameter_name,
        object_a=object_id,
        object_b="object owned by Context A",
        status=status,
        confidence=confidence,
        severity=severity,
        baseline=baseline,
        cross_context=cross_context,
        evidence=evidence,
    )

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    print()

    print(
        CYAN
        + "[*] Sending evidence to Chanakya AI..."
        + RESET
    )

    finding.ai_analysis = analyze_idor_with_ai(
        finding
    )

    if finding.ai_analysis:

        print(
            GREEN
            + "[+] AI analysis completed."
            + RESET
        )

    return finding


# ============================================================
# CLI SCANNER WRAPPER
# ============================================================

def run_idor_scan(
    target: str,
) -> Optional[IDORFinding]:
    """
    Chanakya CLI entry point.

    This is the function that chanakya.py dynamically loads.

    chanakya.py calls:

        run_idor_scan(target)

    The remaining IDOR-specific information is collected here.
    """

    target = target.strip()

    if not target:

        print(
            RED
            + "[!] Target cannot be empty."
            + RESET
        )

        return None

    print()

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        CYAN
        + "                    IDOR / BOLA SETUP"
        + RESET
    )

    print(
        CYAN
        + "============================================================"
        + RESET
    )

    print(
        YELLOW
        + "[!] Use two authorized test accounts/contexts."
        + RESET
    )

    print(
        YELLOW
        + "[!] Context B must NOT own the object being tested."
        + RESET
    )

    print()

    # --------------------------------------------------------
    # Endpoint
    # --------------------------------------------------------

    endpoint = input(
        GREEN
        + "[*] Endpoint URL > "
        + RESET
    ).strip()

    if not endpoint:

        print(
            RED
            + "[!] Endpoint cannot be empty."
            + RESET
        )

        return None

    # --------------------------------------------------------
    # Object ID
    # --------------------------------------------------------

    object_id = input(
        GREEN
        + "[*] Object ID > "
        + RESET
    ).strip()

    if not object_id:

        print(
            RED
            + "[!] Object ID cannot be empty."
            + RESET
        )

        return None

    # --------------------------------------------------------
    # Parameter
    # --------------------------------------------------------

    parameter_name = input(
        GREEN
        + "[*] Parameter name [id] > "
        + RESET
    ).strip()

    if not parameter_name:

        parameter_name = "id"

    # --------------------------------------------------------
    # Context A
    # --------------------------------------------------------

    context_a_headers = get_authorization_headers(
        "Context A"
    )

    # --------------------------------------------------------
    # Context B
    # --------------------------------------------------------

    context_b_headers = get_authorization_headers(
        "Context B"
    )

    # --------------------------------------------------------
    # Run verifier
    # --------------------------------------------------------

    return verify_idor(
        target=target,
        endpoint=endpoint,
        object_id=object_id,
        context_a_headers=context_a_headers,
        context_b_headers=context_b_headers,
        parameter_name=parameter_name,
    )


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

# Chanakya's dynamic loader checks these names.
#
# Keeping aliases means the module remains compatible if
# chanakya.py changes the preferred scanner function name.

scan_idor = run_idor_scan

idor_scan = run_idor_scan

run_idor = run_idor_scan

test_idor = run_idor_scan


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    print()

    print(
        CYAN
        + "Chanakya IDOR / BOLA Scanner"
        + RESET
    )

    print()

    target = input(
        GREEN
        + "Target URL > "
        + RESET
    ).strip()

    if target:

        run_idor_scan(
            target
        )

    else:

        print(
            RED
            + "[!] Target cannot be empty."
            + RESET
        )