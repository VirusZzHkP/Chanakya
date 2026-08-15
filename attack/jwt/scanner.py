"""
Chanakya JWT Security Assessment
================================

Defensive, read-only JWT security assessment module.

This module performs local analysis of a JWT supplied by the
operator during an authorized security assessment.

Checks:
    - JWT structure
    - Header fields
    - Algorithm
    - Registered claims
    - Token lifetime
    - exp / nbf / iat consistency
    - iss / aud / sub presence
    - Sensitive information in claims
    - Suspicious privilege-related claims
    - Algorithm/key-type indicators
    - AI-assisted assessment
    - JSON report generation

This module does NOT:
    - brute-force signing secrets
    - generate forged privileged tokens
    - perform credential theft
    - modify the target application
    - exploit JWT vulnerabilities

IMPORTANT:
    JWT contents are normally base64url-encoded, not encrypted.
    Never send real production secrets or credentials to an
    external AI provider unless your assessment policy permits it.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from utils.ai import analyze_with_ai
from utils.colors import (
    RED,
    GREEN,
    CYAN,
    YELLOW,
    RESET,
)


# ============================================================
# CONSTANTS
# ============================================================

MAX_TOKEN_LENGTH = 8192

REQUEST_TIMEOUT = 10

WEAK_ALGORITHMS = {
    "none",
}

HMAC_ALGORITHMS = {
    "HS256",
    "HS384",
    "HS512",
}

RSA_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
}

EC_ALGORITHMS = {
    "ES256",
    "ES384",
    "ES512",
}

RECOMMENDED_ALGORITHMS = (
    HMAC_ALGORITHMS
    | RSA_ALGORITHMS
    | EC_ALGORITHMS
)

SENSITIVE_CLAIM_NAMES = {
    "password",
    "passwd",
    "pass",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
}

PRIVILEGE_CLAIM_NAMES = {
    "admin",
    "is_admin",
    "administrator",
    "role",
    "roles",
    "privilege",
    "privileges",
    "permissions",
    "scope",
}

STANDARD_CLAIMS = {
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
}


# ============================================================
# BASE64URL HELPERS
# ============================================================

def decode_base64url(value: str) -> bytes:
    """
    Decode a JWT base64url component.
    """

    if not isinstance(value, str):
        raise ValueError(
            "JWT component must be a string."
        )

    padding = "=" * (
        (-len(value)) % 4
    )

    try:

        return base64.urlsafe_b64decode(
            value + padding
        )

    except Exception as exc:

        raise ValueError(
            "Invalid base64url JWT component."
        ) from exc


def decode_json_component(
    value: str,
) -> dict[str, Any]:
    """
    Decode a JWT base64url component and parse JSON.
    """

    decoded = decode_base64url(
        value
    )

    try:

        parsed = json.loads(
            decoded.decode(
                "utf-8"
            )
        )

    except UnicodeDecodeError as exc:

        raise ValueError(
            "JWT component is not valid UTF-8."
        ) from exc

    except json.JSONDecodeError as exc:

        raise ValueError(
            "JWT component does not contain valid JSON."
        ) from exc

    if not isinstance(
        parsed,
        dict,
    ):

        raise ValueError(
            "JWT component is not a JSON object."
        )

    return parsed


# ============================================================
# JWT PARSING
# ============================================================

def parse_jwt(
    token: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    str,
]:
    """
    Parse a compact JWT.

    Returns:

        header
        claims
        signature
    """

    token = (
        token or ""
    ).strip()

    if token.lower().startswith(
        "bearer "
    ):

        token = token[7:].strip()

    if not token:

        raise ValueError(
            "JWT cannot be empty."
        )

    if len(token) > MAX_TOKEN_LENGTH:

        raise ValueError(
            "JWT exceeds maximum supported length."
        )

    parts = token.split(".")

    if len(parts) != 3:

        raise ValueError(
            "JWT must contain exactly three components."
        )

    header_part = parts[0]
    payload_part = parts[1]
    signature = parts[2]

    if not header_part:

        raise ValueError(
            "JWT header is empty."
        )

    if not payload_part:

        raise ValueError(
            "JWT payload is empty."
        )

    header = decode_json_component(
        header_part
    )

    claims = decode_json_component(
        payload_part
    )

    return (
        header,
        claims,
        signature,
    )


# ============================================================
# TIME HELPERS
# ============================================================

def _numeric_timestamp(
    value: Any,
) -> Optional[float]:
    """
    Return a numeric JWT timestamp when valid.
    """

    if isinstance(
        value,
        bool,
    ):

        return None

    if isinstance(
        value,
        (int, float),
    ):

        return float(value)

    return None


def _utc_datetime(
    timestamp: float,
) -> str:
    """
    Convert Unix timestamp to UTC ISO-8601.
    """

    try:

        return datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc,
        ).isoformat()

    except (
        OverflowError,
        OSError,
        ValueError,
    ):

        return "invalid-timestamp"


# ============================================================
# FINDING HELPERS
# ============================================================

def finding(
    category: str,
    severity: str,
    confidence: str,
    description: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a normalized JWT finding.
    """

    return {
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "description": description,
        "evidence": evidence,
    }


# ============================================================
# HEADER ANALYSIS
# ============================================================

def analyze_header(
    header: dict[str, Any],
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    algorithm = header.get(
        "alg"
    )

    token_type = header.get(
        "typ"
    )

    key_id = header.get(
        "kid"
    )

    # --------------------------------------------------------
    # Algorithm
    # --------------------------------------------------------

    if not algorithm:

        findings.append(
            finding(
                category="Missing Algorithm",
                severity="high",
                confidence="high",
                description=(
                    "The JWT header does not contain "
                    "an alg field."
                ),
                evidence={
                    "header": header,
                },
            )
        )

    elif not isinstance(
        algorithm,
        str,
    ):

        findings.append(
            finding(
                category="Invalid Algorithm Field",
                severity="high",
                confidence="high",
                description=(
                    "The JWT alg field is not a string."
                ),
                evidence={
                    "alg": algorithm,
                },
            )
        )

    elif algorithm.lower() == "none":

        findings.append(
            finding(
                category="Unsecured JWT Algorithm",
                severity="critical",
                confidence="high",
                description=(
                    "The token declares the unsecured "
                    "JWT algorithm."
                ),
                evidence={
                    "alg": algorithm,
                },
            )
        )

    elif algorithm not in RECOMMENDED_ALGORITHMS:

        findings.append(
            finding(
                category="Unrecognized JWT Algorithm",
                severity="medium",
                confidence="medium",
                description=(
                    "The token uses an algorithm that "
                    "Chanakya does not classify as a "
                    "standard configured algorithm."
                ),
                evidence={
                    "alg": algorithm,
                },
            )
        )

    # --------------------------------------------------------
    # Token type
    # --------------------------------------------------------

    if token_type is None:

        findings.append(
            finding(
                category="Missing Token Type",
                severity="low",
                confidence="medium",
                description=(
                    "The JWT does not declare a typ header."
                ),
                evidence={
                    "typ": None,
                },
            )
        )

    # --------------------------------------------------------
    # Key identifier
    # --------------------------------------------------------

    if key_id is not None:

        findings.append(
            finding(
                category="Key Identifier Present",
                severity="informational",
                confidence="high",
                description=(
                    "The token specifies a key identifier."
                ),
                evidence={
                    "kid": str(key_id),
                },
            )
        )

    return findings


# ============================================================
# CLAIM ANALYSIS
# ============================================================

def analyze_claims(
    claims: dict[str, Any],
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # Sensitive data
    # --------------------------------------------------------

    sensitive_found: list[str] = []

    for name in claims:

        if (
            isinstance(name, str)
            and name.lower()
            in SENSITIVE_CLAIM_NAMES
        ):

            sensitive_found.append(
                name
            )

    if sensitive_found:

        findings.append(
            finding(
                category="Sensitive Information in JWT",
                severity="high",
                confidence="high",
                description=(
                    "Sensitive-looking information appears "
                    "directly inside JWT claims."
                ),
                evidence={
                    "claims": sensitive_found,
                },
            )
        )

    # --------------------------------------------------------
    # Privilege-related claims
    # --------------------------------------------------------

    privilege_found: list[
        dict[str, Any]
    ] = []

    for name in claims:

        if (
            isinstance(name, str)
            and name.lower()
            in PRIVILEGE_CLAIM_NAMES
        ):

            privilege_found.append(
                {
                    "claim": name,
                    "value": claims[name],
                }
            )

    if privilege_found:

        findings.append(
            finding(
                category="Privilege Claims Present",
                severity="informational",
                confidence="high",
                description=(
                    "The token contains claims that may "
                    "influence authorization."
                ),
                evidence={
                    "claims": privilege_found,
                },
            )
        )

    # --------------------------------------------------------
    # Expiration
    # --------------------------------------------------------

    if "exp" not in claims:

        findings.append(
            finding(
                category="Missing Expiration",
                severity="medium",
                confidence="high",
                description=(
                    "The JWT does not contain an exp claim."
                ),
                evidence={
                    "exp": None,
                },
            )
        )

    else:

        exp = _numeric_timestamp(
            claims["exp"]
        )

        if exp is None:

            findings.append(
                finding(
                    category="Invalid Expiration",
                    severity="medium",
                    confidence="high",
                    description=(
                        "The exp claim is not a numeric "
                        "JWT timestamp."
                    ),
                    evidence={
                        "exp": claims["exp"],
                    },
                )
            )

        else:

            now = datetime.now(
                timezone.utc
            ).timestamp()

            iat = _numeric_timestamp(
                claims.get("iat")
            )

            lifetime = None

            if iat is not None:

                lifetime = (
                    exp - iat
                )

            # ------------------------------------------------
            # Expired token
            # ------------------------------------------------

            if exp < now:

                findings.append(
                    finding(
                        category="Expired Token",
                        severity="informational",
                        confidence="high",
                        description=(
                            "The supplied JWT is already "
                            "expired."
                        ),
                        evidence={
                            "exp": _utc_datetime(exp),
                        },
                    )
                )

            # ------------------------------------------------
            # Excessive lifetime
            # ------------------------------------------------

            elif lifetime is not None:

                if lifetime > (
                    30 * 24 * 60 * 60
                ):

                    findings.append(
                        finding(
                            category="Long Token Lifetime",
                            severity="medium",
                            confidence="high",
                            description=(
                                "The JWT lifetime exceeds "
                                "30 days."
                            ),
                            evidence={
                                "issued_at": (
                                    _utc_datetime(iat)
                                ),
                                "expiration": (
                                    _utc_datetime(exp)
                                ),
                                "lifetime_seconds": (
                                    lifetime
                                ),
                                "lifetime_days": (
                                    lifetime / 86400
                                ),
                            },
                        )
                    )

    # --------------------------------------------------------
    # Issued at
    # --------------------------------------------------------

    if "iat" not in claims:

        findings.append(
            finding(
                category="Missing Issued-At Claim",
                severity="low",
                confidence="medium",
                description=(
                    "The JWT does not contain an iat claim."
                ),
                evidence={
                    "iat": None,
                },
            )
        )

    else:

        iat = _numeric_timestamp(
            claims["iat"]
        )

        if iat is None:

            findings.append(
                finding(
                    category="Invalid Issued-At Claim",
                    severity="low",
                    confidence="high",
                    description=(
                        "The iat claim is not a numeric "
                        "JWT timestamp."
                    ),
                    evidence={
                        "iat": claims["iat"],
                    },
                )
            )

    # --------------------------------------------------------
    # Not before
    # --------------------------------------------------------

    if "nbf" in claims:

        nbf = _numeric_timestamp(
            claims["nbf"]
        )

        if nbf is None:

            findings.append(
                finding(
                    category="Invalid Not-Before Claim",
                    severity="low",
                    confidence="high",
                    description=(
                        "The nbf claim is not numeric."
                    ),
                    evidence={
                        "nbf": claims["nbf"],
                    },
                )
            )

        else:

            now = datetime.now(
                timezone.utc
            ).timestamp()

            if nbf > now:

                findings.append(
                    finding(
                        category="Token Not Yet Valid",
                        severity="informational",
                        confidence="high",
                        description=(
                            "The token's nbf claim is "
                            "in the future."
                        ),
                        evidence={
                            "nbf": _utc_datetime(nbf),
                        },
                    )
                )

    # --------------------------------------------------------
    # Issuer
    # --------------------------------------------------------

    if "iss" not in claims:

        findings.append(
            finding(
                category="Missing Issuer",
                severity="low",
                confidence="medium",
                description=(
                    "The JWT does not contain an issuer claim."
                ),
                evidence={
                    "iss": None,
                },
            )
        )

    # --------------------------------------------------------
    # Audience
    # --------------------------------------------------------

    if "aud" not in claims:

        findings.append(
            finding(
                category="Missing Audience",
                severity="low",
                confidence="medium",
                description=(
                    "The JWT does not contain an audience claim."
                ),
                evidence={
                    "aud": None,
                },
            )
        )

    # --------------------------------------------------------
    # Subject
    # --------------------------------------------------------

    if "sub" not in claims:

        findings.append(
            finding(
                category="Missing Subject",
                severity="informational",
                confidence="medium",
                description=(
                    "The JWT does not contain a subject claim."
                ),
                evidence={
                    "sub": None,
                },
            )
        )

    return findings


# ============================================================
# CONSISTENCY ANALYSIS
# ============================================================

def analyze_consistency(
    header: dict[str, Any],
    claims: dict[str, Any],
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    algorithm = header.get(
        "alg"
    )

    # --------------------------------------------------------
    # HMAC
    # --------------------------------------------------------

    if algorithm in HMAC_ALGORITHMS:

        findings.append(
            finding(
                category="HMAC Signing Algorithm",
                severity="informational",
                confidence="high",
                description=(
                    "The token uses an HMAC signing algorithm. "
                    "The server-side signing secret must be "
                    "protected appropriately."
                ),
                evidence={
                    "alg": algorithm,
                },
            )
        )

    # --------------------------------------------------------
    # RSA
    # --------------------------------------------------------

    elif algorithm in RSA_ALGORITHMS:

        findings.append(
            finding(
                category="RSA Signing Algorithm",
                severity="informational",
                confidence="high",
                description=(
                    "The token uses an RSA-family signing "
                    "algorithm."
                ),
                evidence={
                    "alg": algorithm,
                },
            )
        )

    # --------------------------------------------------------
    # EC
    # --------------------------------------------------------

    elif algorithm in EC_ALGORITHMS:

        findings.append(
            finding(
                category="ECDSA Signing Algorithm",
                severity="informational",
                confidence="high",
                description=(
                    "The token uses an ECDSA signing algorithm."
                ),
                evidence={
                    "alg": algorithm,
                },
            )
        )

    # --------------------------------------------------------
    # iat / exp consistency
    # --------------------------------------------------------

    iat = _numeric_timestamp(
        claims.get("iat")
    )

    exp = _numeric_timestamp(
        claims.get("exp")
    )

    if (
        iat is not None
        and exp is not None
        and exp <= iat
    ):

        findings.append(
            finding(
                category="Invalid Token Lifetime",
                severity="medium",
                confidence="high",
                description=(
                    "The JWT expiration time is not later "
                    "than its issued-at time."
                ),
                evidence={
                    "iat": _utc_datetime(iat),
                    "exp": _utc_datetime(exp),
                },
            )
        )

    return findings


# ============================================================
# FULL ASSESSMENT
# ============================================================

def assess_jwt(
    token: str,
) -> dict[str, Any]:

    header, claims, signature = parse_jwt(
        token
    )

    findings: list[
        dict[str, Any]
    ] = []

    findings.extend(
        analyze_header(
            header
        )
    )

    findings.extend(
        analyze_claims(
            claims
        )
    )

    findings.extend(
        analyze_consistency(
            header,
            claims,
        )
    )

    return {
        "token_structure": {
            "parts": 3,
            "signature_present": bool(
                signature
            ),
        },
        "header": header,
        "claims": claims,
        "standard_claims_present": sorted(
            set(claims)
            & STANDARD_CLAIMS
        ),
        "findings": findings,
    }


# ============================================================
# AI ANALYSIS
# ============================================================

def analyze_jwt_with_ai(
    target: str,
    assessment: dict[str, Any],
) -> Optional[Any]:
    """
    Send sanitized JWT assessment evidence to the configured
    Chanakya AI provider.

    The raw JWT is deliberately NOT sent separately.
    """

    evidence = json.dumps(
        assessment,
        indent=2,
        ensure_ascii=False,
    )

    try:

        return analyze_with_ai(
            target=target,
            scan_type=(
                "JWT security assessment"
            ),
            evidence=evidence,
        )

    except Exception as exc:

        print(
            YELLOW
            + f"[!] AI analysis failed: {exc}"
            + RESET
        )

        return None


# ============================================================
# DISPLAY
# ============================================================

def display_jwt_results(
    assessment: dict[str, Any],
) -> None:

    header = assessment[
        "header"
    ]

    claims = assessment[
        "claims"
    ]

    findings = assessment[
        "findings"
    ]

    print()

    print(
        CYAN
        + "=" * 60
        + RESET
    )

    print(
        CYAN
        + "                     JWT ANALYSIS"
        + RESET
    )

    print(
        CYAN
        + "=" * 60
        + RESET
    )

    print()

    print(
        f"Algorithm : "
        f"{header.get('alg', 'missing')}"
    )

    print(
        f"Type      : "
        f"{header.get('typ', 'missing')}"
    )

    print(
        f"Key ID    : "
        f"{header.get('kid', 'not present')}"
    )

    print()

    print(
        CYAN
        + "Claims:"
        + RESET
    )

    for name, value in claims.items():

        if (
            isinstance(name, str)
            and name.lower()
            in SENSITIVE_CLAIM_NAMES
        ):

            display_value = "[REDACTED]"

        else:

            display_value = value

        print(
            f"  {name}: {display_value}"
        )

    print()

    print(
        CYAN
        + "Findings:"
        + RESET
    )

    if not findings:

        print(
            GREEN
            + "  [+] No obvious JWT configuration "
              "weaknesses detected."
            + RESET
        )

        return

    for index, item in enumerate(
        findings,
        start=1,
    ):

        severity = str(
            item["severity"]
        ).upper()

        if severity in {
            "CRITICAL",
            "HIGH",
        }:

            prefix = RED

        elif severity == "MEDIUM":

            prefix = YELLOW

        else:

            prefix = GREEN

        print(
            prefix
            + f"  [{index}] "
              f"{item['category']} "
              f"({severity})"
            + RESET
        )

        print(
            f"      {item['description']}"
        )


# ============================================================
# REPORT
# ============================================================

def save_jwt_report(
    target: str,
    assessment: dict[str, Any],
) -> Optional[Path]:
    """
    Save JWT assessment as a JSON report.
    """

    try:

        report_dir = (
            Path("reports")
            / "attacks"
            / "jwt"
        )

        report_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%d_%H-%M-%S"
        )

        report_file = (
            report_dir
            / f"jwt_{timestamp}.json"
        )

        report = {
            "attack_type": (
                "JWT Security Assessment"
            ),
            "target": target,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "assessment": assessment,
        }

        with open(
            report_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                report,
                file,
                indent=2,
                ensure_ascii=False,
            )

        return report_file

    except OSError as exc:

        print(
            RED
            + f"[!] Failed to save JWT report: {exc}"
            + RESET
        )

        return None


# ============================================================
# CORE SCANNER
# ============================================================

def scan_jwt(
    target: str,
    token: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Core JWT scanner interface.

    This function is compatible with Chanakya's dynamic
    attack module loader.

    If token is not supplied, the operator is prompted for it.

    Returns:
        Assessment dictionary or None.
    """

    target = (
        target or ""
    ).strip()

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
        + "=" * 60
        + RESET
    )

    print(
        CYAN
        + "                 CHANAKYA JWT ASSESSMENT"
        + RESET
    )

    print(
        CYAN
        + "=" * 60
        + RESET
    )

    print()

    print(
        YELLOW
        + "[!] Use only a JWT obtained during an "
          "authorized security assessment."
        + RESET
    )

    print(
        YELLOW
        + "[!] JWT analysis is read-only."
        + RESET
    )

    print()

    if token is None:

        token = input(
            GREEN
            + "JWT / Bearer token > "
            + RESET
        ).strip()

    else:

        token = token.strip()

    if not token:

        print(
            RED
            + "[!] JWT cannot be empty."
            + RESET
        )

        return None

    # --------------------------------------------------------
    # Parse and assess
    # --------------------------------------------------------

    try:

        assessment = assess_jwt(
            token
        )

    except (
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:

        print()

        print(
            RED
            + f"[!] Invalid JWT: {exc}"
            + RESET
        )

        return None

    except Exception as exc:

        print()

        print(
            RED
            + f"[!] JWT analysis failed: {exc}"
            + RESET
        )

        return None

    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    display_jwt_results(
        assessment
    )

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    print()

    print(
        CYAN
        + "[*] Sending JWT evidence to Chanakya AI..."
        + RESET
    )

    ai_result = analyze_jwt_with_ai(
        target=target,
        assessment=assessment,
    )

    assessment[
        "ai_analysis"
    ] = ai_result

    if ai_result:

        print(
            GREEN
            + "[+] AI JWT assessment completed."
            + RESET
        )

    else:

        print(
            YELLOW
            + "[!] AI analysis unavailable."
            + RESET
        )

    # --------------------------------------------------------
    # Save report
    # --------------------------------------------------------

    report_file = save_jwt_report(
        target=target,
        assessment=assessment,
    )

    if report_file:

        print()

        print(
            GREEN
            + f"[+] JWT report saved to: "
              f"{report_file}"
            + RESET
        )

    return assessment


# ============================================================
# CHANAKYA COMPATIBILITY ENTRY POINT
# ============================================================

def run_jwt_scan(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Chanakya-compatible JWT scanner entry point.

    chanakya.py calls:

        scanner(target)

    Therefore this function receives the target and then
    asks for the JWT.
    """

    return scan_jwt(
        target=target
    )


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

def jwt_scan(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Compatibility alias.
    """

    return run_jwt_scan(
        target
    )


def run_jwt(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Compatibility alias.
    """

    return run_jwt_scan(
        target
    )


def test_jwt(
    target: str,
) -> Optional[dict[str, Any]]:
    """
    Compatibility alias.
    """

    return run_jwt_scan(
        target
    )


# ============================================================
# INTERACTIVE COMPATIBILITY ENTRY POINT
# ============================================================

def run_jwt_assessment(
    target: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Backwards-compatible interactive entry point.

    Can be called either as:

        run_jwt_assessment()

    or:

        run_jwt_assessment(target)
    """

    if target is None:

        target = input(
            GREEN
            + "Authorized target > "
            + RESET
        ).strip()

    if not target:

        print(
            RED
            + "[!] Target cannot be empty."
            + RESET
        )

        return None

    return scan_jwt(
        target=target
    )


# ============================================================
# MODULE SELF-TEST / DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    print()

    print(
        CYAN
        + "=" * 60
        + RESET
    )

    print(
        CYAN
        + "              CHANAKYA JWT SCANNER"
        + RESET
    )

    print(
        CYAN
        + "=" * 60
        + RESET
    )

    print()

    target = input(
        GREEN
        + "Authorized target > "
        + RESET
    ).strip()

    if target:

        run_jwt_scan(
            target
        )

    else:

        print(
            RED
            + "[!] Target cannot be empty."
            + RESET
        )