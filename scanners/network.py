"""
Chanakya Network Scanner
------------------------

Nmap-based network reconnaissance and service assessment module.

Responsibilities:
    - Port discovery
    - Service/version detection
    - Optional OS detection
    - Optional NSE vulnerability assessment
    - Structured evidence collection
    - Persistent reports
    - Centralized AI analysis
    - Duplicate scan protection
    - Progressive scanning instead of blindly using every Nmap option

Architecture:

    Target
      |
      +--> Port discovery
      |
      +--> Service/version detection
      |
      +--> Optional OS detection
      |
      +--> Optional NSE vulnerability checks
      |
      +--> Evidence aggregation
      |
      +--> Chanakya AI analysis

Intended for authorized security testing only.
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import nmap

from utils.colors import (
    RED,
    GREEN,
    CYAN,
    YELLOW,
    RESET,
)

from utils.paths import (
    NMAP_REPORTS_DIR,
    SERVICE_REPORTS_DIR,
)

from utils.ai import analyze_with_ai


logger = logging.getLogger(__name__)


# ============================================================
# STATE
# ============================================================

_scanned_port_targets: set[str] = set()
_scanned_service_targets: set[str] = set()
_scanned_vulnerability_targets: set[str] = set()


# ============================================================
# NMAP AVAILABILITY
# ============================================================

def _nmap_available() -> bool:
    """
    Check whether the Nmap executable is available.
    """

    if shutil.which("nmap") is None:
        print(
            RED
            + "[!] Nmap executable was not found in PATH."
            + RESET
        )

        print(
            YELLOW
            + "[*] Install Nmap and make sure the nmap command "
              "is available."
            + RESET
        )

        return False

    return True


# ============================================================
# TARGET VALIDATION
# ============================================================

def _validate_target(target: str) -> bool:
    """
    Validate a basic IP address or hostname target.

    This does not attempt DNS resolution itself because Nmap
    performs target resolution.
    """

    if not isinstance(target, str):
        print(
            RED
            + "[!] Target must be a string."
            + RESET
        )
        return False

    target = target.strip()

    if not target:
        print(
            RED
            + "[!] Target cannot be empty."
            + RESET
        )
        return False

    if any(char.isspace() for char in target):
        print(
            RED
            + "[!] Target cannot contain whitespace."
            + RESET
        )
        return False

    # Accept normal IPv4/IPv6 targets.
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Hostnames/domain names.
    if len(target) > 253:
        print(
            RED
            + "[!] Target is too long."
            + RESET
        )
        return False

    if target.startswith("-"):
        print(
            RED
            + "[!] Invalid Nmap target."
            + RESET
        )
        return False

    return True


# ============================================================
# REPORT HELPERS
# ============================================================

def _timestamp() -> str:
    return datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S-%f"
    )


def _safe_filename(value: str) -> str:
    """
    Convert target text into a filesystem-safe filename.
    """

    safe = "".join(
        char
        if char.isalnum() or char in "-_."
        else "_"
        for char in value
    )

    return safe[:160] or "target"


def _report_path(
    directory: Path,
    target: str,
    suffix: str,
) -> Path:

    return (
        directory
        / f"{_timestamp()}_{_safe_filename(target)}_{suffix}.txt"
    )


def _write_report(
    filename: Path,
    content: str,
) -> Optional[Path]:

    try:

        filename.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        filename.write_text(
            content,
            encoding="utf-8",
        )

        return filename

    except OSError:

        logger.exception(
            "Failed to write report %s",
            filename,
        )

        print(
            YELLOW
            + f"[!] Failed to save report: {filename}"
            + RESET
        )

        return None


# ============================================================
# EVIDENCE HELPERS
# ============================================================

def _host_summary(
    nm: nmap.PortScanner,
    host: str,
) -> list[str]:

    hostname = nm[host].hostname()

    state = nm[host].state()

    return [
        f"Host: {host}",
        f"Hostname: {hostname or 'N/A'}",
        f"State: {state}",
    ]


def _extract_port_data(
    nm: nmap.PortScanner,
    host: str,
) -> list[dict[str, Any]]:

    services: list[dict[str, Any]] = []

    for proto in nm[host].all_protocols():

        ports = nm[host][proto].keys()

        for port in sorted(ports):

            data = nm[host][proto][port]

            services.append(
                {
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "state": data.get(
                        "state",
                        "unknown",
                    ),
                    "service": data.get(
                        "name",
                        "unknown",
                    ),
                    "product": data.get(
                        "product",
                        "",
                    ),
                    "version": data.get(
                        "version",
                        "",
                    ),
                    "extrainfo": data.get(
                        "extrainfo",
                        "",
                    ),
                    "reason": data.get(
                        "reason",
                        "",
                    ),
                    "cpe": data.get(
                        "cpe",
                        "",
                    ),
                }
            )

    return services


def _format_service(
    service: dict[str, Any],
) -> str:

    line = (
        f"{service['port']}/{service['protocol']} "
        f"state={service['state']} "
        f"service={service['service']}"
    )

    if service["product"]:
        line += (
            f" product={service['product']}"
        )

    if service["version"]:
        line += (
            f" version={service['version']}"
        )

    if service["extrainfo"]:
        line += (
            f" info={service['extrainfo']}"
        )

    if service["reason"]:
        line += (
            f" reason={service['reason']}"
        )

    if service["cpe"]:
        line += (
            f" cpe={service['cpe']}"
        )

    return line


# ============================================================
# GENERIC NMAP RUNNER
# ============================================================

def _run_nmap(
    target: str,
    arguments: str,
) -> Optional[nmap.PortScanner]:

    if not _nmap_available():
        return None

    try:

        nm = nmap.PortScanner()

        logger.info(
            "Running Nmap against %s with arguments: %s",
            target,
            arguments,
        )

        nm.scan(
            hosts=target,
            arguments=arguments,
        )

        return nm

    except nmap.PortScannerError as exc:

        logger.error(
            "Nmap error against %s: %s",
            target,
            exc,
        )

        print(
            RED
            + f"[!] Nmap error: {exc}"
            + RESET
        )

        return None

    except Exception:

        logger.error(
            "Unexpected Nmap error:\n%s",
            traceback.format_exc(),
        )

        print(
            RED
            + "[!] Unexpected error while running Nmap."
            + RESET
        )

        return None


# ============================================================
# PORT SCANNING
# ============================================================

def scan_ports(
    ip: str,
    ports: str = "1-1000",
    fast: bool = False,
) -> Optional[dict[str, Any]]:
    """
    Perform TCP port discovery.

    Default:
        1-1000

    Fast mode:
        Nmap's --top-ports 100

    Returns structured scan information.
    """

    ip = ip.strip()

    if not _validate_target(ip):
        return None

    if ip in _scanned_port_targets:

        print(
            YELLOW
            + f"[!] Port scan already performed for {ip}."
            + RESET
        )

        return None

    print(
        GREEN
        + f"[*] Discovering TCP ports on {ip}"
        + RESET
    )

    if fast:

        arguments = (
            "--top-ports 100 "
            "-T3 "
            "--open"
        )

    else:

        arguments = (
            f"-p {ports} "
            "-T3 "
            "--open"
        )

    nm = _run_nmap(
        target=ip,
        arguments=arguments,
    )

    if nm is None:
        return None

    _scanned_port_targets.add(ip)

    if not nm.all_hosts():

        print(
            YELLOW
            + "[!] Nmap returned no hosts."
            + RESET
        )

        return None

    report_lines: list[str] = []

    open_ports: list[dict[str, Any]] = []

    for host in nm.all_hosts():

        report_lines.extend(
            _host_summary(
                nm,
                host,
            )
        )

        report_lines.append("")

        services = _extract_port_data(
            nm,
            host,
        )

        for service in services:

            report_lines.append(
                _format_service(service)
            )

            if service["state"] == "open":

                open_ports.append(service)

                print(
                    GREEN
                    + "[OPEN] "
                    + _format_service(service)
                    + RESET
                )

    report = "\n".join(report_lines)

    filename = _report_path(
        NMAP_REPORTS_DIR,
        ip,
        "port_scan",
    )

    saved = _write_report(
        filename,
        report,
    )

    if saved:

        print(
            GREEN
            + f"[+] Port scan saved to {saved}"
            + RESET
        )

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    if report.strip():

        analyze_with_ai(
            target=ip,
            scan_type="Nmap TCP port discovery",
            evidence=report,
        )

    logger.info(
        "Port discovery completed for %s",
        ip,
    )

    return {
        "target": ip,
        "open_ports": open_ports,
        "report": saved,
    }


# ============================================================
# SERVICE / VERSION DETECTION
# ============================================================

def scan_services(
    ip: str,
    ports: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Perform service/version detection.

    If ports is None, Nmap determines the relevant ports using
    its normal service detection workflow.

    If ports are supplied, they are explicitly scanned.
    """

    ip = ip.strip()

    if not _validate_target(ip):
        return None

    if ip in _scanned_service_targets:

        print(
            YELLOW
            + f"[!] Service scan already performed for {ip}."
            + RESET
        )

        return None

    print(
        GREEN
        + f"[*] Detecting services and versions on {ip}"
        + RESET
    )

    arguments = "-sV -T3"

    if ports:
        arguments += f" -p {ports}"
    else:
        arguments += " --top-ports 1000"

    nm = _run_nmap(
        target=ip,
        arguments=arguments,
    )

    if nm is None:
        return None

    _scanned_service_targets.add(ip)

    if not nm.all_hosts():

        print(
            YELLOW
            + "[!] No hosts returned by Nmap."
            + RESET
        )

        return None

    report_lines: list[str] = []

    discovered_services: list[dict[str, Any]] = []

    for host in nm.all_hosts():

        report_lines.extend(
            _host_summary(
                nm,
                host,
            )
        )

        report_lines.append("")

        services = _extract_port_data(
            nm,
            host,
        )

        for service in services:

            if service["state"] != "open":
                continue

            discovered_services.append(
                service
            )

            line = _format_service(
                service
            )

            report_lines.append(line)

            print(
                GREEN
                + "[SERVICE] "
                + line
                + RESET
            )

    report = "\n".join(report_lines)

    filename = _report_path(
        SERVICE_REPORTS_DIR,
        ip,
        "service_scan",
    )

    saved = _write_report(
        filename,
        report,
    )

    if saved:

        print(
            GREEN
            + f"[+] Service scan saved to {saved}"
            + RESET
        )

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    if discovered_services:

        analyze_with_ai(
            target=ip,
            scan_type="Nmap service and version detection",
            evidence=report,
        )

    else:

        print(
            YELLOW
            + "[!] No open services discovered."
            + RESET
        )

    return {
        "target": ip,
        "services": discovered_services,
        "report": saved,
    }


# ============================================================
# OS DETECTION
# ============================================================

def scan_os(
    ip: str,
) -> Optional[dict[str, Any]]:
    """
    Optional OS fingerprinting.

    OS detection may require elevated privileges depending
    on the operating system and Nmap configuration.
    """

    ip = ip.strip()

    if not _validate_target(ip):
        return None

    print(
        CYAN
        + f"[*] Performing OS detection on {ip}"
        + RESET
    )

    nm = _run_nmap(
        target=ip,
        arguments="-O -T3",
    )

    if nm is None:
        return None

    if not nm.all_hosts():

        print(
            YELLOW
            + "[!] No hosts returned by Nmap."
            + RESET
        )

        return None

    evidence_lines: list[str] = []

    for host in nm.all_hosts():

        data = nm[host]

        evidence_lines.extend(
            _host_summary(
                nm,
                host,
            )
        )

        os_matches = data.get(
            "osmatch",
            [],
        )

        if not os_matches:

            evidence_lines.append(
                "OS detection: No confident match"
            )

            continue

        for match in os_matches[:5]:

            name = match.get(
                "name",
                "Unknown",
            )

            accuracy = match.get(
                "accuracy",
                "N/A",
            )

            line = (
                f"OS candidate={name} "
                f"accuracy={accuracy}%"
            )

            evidence_lines.append(line)

            print(
                CYAN
                + "[OS] "
                + line
                + RESET
            )

    evidence = "\n".join(
        evidence_lines
    )

    filename = _report_path(
        NMAP_REPORTS_DIR,
        ip,
        "os_scan",
    )

    saved = _write_report(
        filename,
        evidence,
    )

    if saved:

        print(
            GREEN
            + f"[+] OS report saved to {saved}"
            + RESET
        )

    if evidence.strip():

        analyze_with_ai(
            target=ip,
            scan_type="Nmap OS fingerprinting",
            evidence=evidence,
        )

    return {
        "target": ip,
        "report": saved,
        "evidence": evidence,
    }


# ============================================================
# NSE VULNERABILITY ASSESSMENT
# ============================================================

def scan_vulnerabilities(
    ip: str,
    ports: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Run Nmap's vulnerability NSE category.

    This is intentionally a separate explicit operation instead
    of being automatically chained into every port scan.

    Recommended usage:
        1. scan_ports()
        2. scan_services()
        3. review scope
        4. scan_vulnerabilities()
    """

    ip = ip.strip()

    if not _validate_target(ip):
        return None

    if ip in _scanned_vulnerability_targets:

        print(
            YELLOW
            + f"[!] Vulnerability scan already performed for {ip}."
            + RESET
        )

        return None

    print(
        YELLOW
        + "[!] Starting Nmap NSE vulnerability assessment."
        + RESET
    )

    arguments = (
        "-sV "
        "--script vuln "
        "-T3"
    )

    if ports:
        arguments += f" -p {ports}"

    nm = _run_nmap(
        target=ip,
        arguments=arguments,
    )

    if nm is None:
        return None

    _scanned_vulnerability_targets.add(ip)

    if not nm.all_hosts():

        print(
            YELLOW
            + "[!] No hosts returned by Nmap."
            + RESET
        )

        return None

    evidence_lines: list[str] = []

    for host in nm.all_hosts():

        evidence_lines.extend(
            _host_summary(
                nm,
                host,
            )
        )

        for proto in nm[host].all_protocols():

            for port in sorted(
                nm[host][proto].keys()
            ):

                service = nm[host][proto][port]

                state = service.get(
                    "state",
                    "unknown",
                )

                if state != "open":
                    continue

                base_line = (
                    f"{port}/{proto} "
                    f"service={service.get('name', 'unknown')} "
                    f"product={service.get('product', '')} "
                    f"version={service.get('version', '')}"
                )

                evidence_lines.append(
                    base_line
                )

                scripts = service.get(
                    "script",
                    {},
                )

                for script_name, script_output in scripts.items():

                    line = (
                        f"NSE[{script_name}]: "
                        f"{script_output}"
                    )

                    evidence_lines.append(
                        line
                    )

                    print(
                        YELLOW
                        + "[NSE] "
                        + line
                        + RESET
                    )

    evidence = "\n".join(
        evidence_lines
    )

    filename = _report_path(
        NMAP_REPORTS_DIR,
        ip,
        "vulnerability_scan",
    )

    saved = _write_report(
        filename,
        evidence,
    )

    if saved:

        print(
            GREEN
            + f"[+] Vulnerability report saved to {saved}"
            + RESET
        )

    if evidence.strip():

        analyze_with_ai(
            target=ip,
            scan_type="Nmap NSE vulnerability assessment",
            evidence=evidence,
        )

    return {
        "target": ip,
        "report": saved,
        "evidence": evidence,
    }


# ============================================================
# PROGRESSIVE NETWORK ASSESSMENT
# ============================================================

def network_assessment(
    ip: str,
    fast: bool = False,
    detect_os: bool = False,
    vulnerability_scan: bool = False,
) -> Optional[dict[str, Any]]:
    """
    Run the complete progressive network assessment.

    Default:
        Port discovery
        Service/version detection

    Optional:
        OS detection
        NSE vulnerability assessment

    This deliberately does NOT automatically run every
    potentially intrusive Nmap feature.
    """

    ip = ip.strip()

    if not _validate_target(ip):
        return None

    print()
    print(
        CYAN
        + "=" * 70
        + RESET
    )

    print(
        GREEN
        + f"CHANAKYA NETWORK ASSESSMENT: {ip}"
        + RESET
    )

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    results: dict[str, Any] = {
        "target": ip,
        "ports": None,
        "services": None,
        "os": None,
        "vulnerabilities": None,
    }

    # --------------------------------------------------------
    # PHASE 1 — PORT DISCOVERY
    # --------------------------------------------------------

    port_result = scan_ports(
        ip,
        fast=fast,
    )

    results["ports"] = port_result

    if not port_result:

        print(
            RED
            + "[!] Port discovery failed."
            + RESET
        )

        return results

    open_ports = port_result.get(
        "open_ports",
        [],
    )

    # --------------------------------------------------------
    # BUILD PORT LIST FOR FOLLOW-UP
    # --------------------------------------------------------

    discovered_ports = sorted(
        {
            str(service["port"])
            for service in open_ports
            if service.get("state") == "open"
        }
    )

    port_spec = ",".join(
        discovered_ports
    )

    if not port_spec:

        print(
            YELLOW
            + "[!] No open TCP ports found."
            + RESET
        )

        return results

    print(
        CYAN
        + f"[*] Open ports identified: {port_spec}"
        + RESET
    )

    # --------------------------------------------------------
    # PHASE 2 — SERVICE DETECTION
    # --------------------------------------------------------

    service_result = scan_services(
        ip,
        ports=port_spec,
    )

    results["services"] = service_result

    # --------------------------------------------------------
    # PHASE 3 — OPTIONAL OS DETECTION
    # --------------------------------------------------------

    if detect_os:

        results["os"] = scan_os(
            ip
        )

    # --------------------------------------------------------
    # PHASE 4 — OPTIONAL VULNERABILITY NSE
    # --------------------------------------------------------

    if vulnerability_scan:

        results["vulnerabilities"] = scan_vulnerabilities(
            ip,
            ports=port_spec,
        )

    print()
    print(
        GREEN
        + "[+] Network assessment completed."
        + RESET
    )

    return results


# ============================================================
# RESET SCAN STATE
# ============================================================

def reset_scan_state() -> None:
    """
    Clear in-memory duplicate protection.

    Useful for long-running applications when the user wants
    to deliberately reassess a target during the same session.
    """

    _scanned_port_targets.clear()
    _scanned_service_targets.clear()
    _scanned_vulnerability_targets.clear()

    logger.info(
        "Network scanner state reset."
    )