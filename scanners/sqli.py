"""
Chanakya SQL Injection Scanner
------------------------------

SQLMap-based SQL injection assessment module.

Responsibilities:
    - Validate SQLMap targets
    - Build staged SQLMap commands
    - Execute SQLMap safely without shell=True
    - Suppress SQLMap's terminal banner while preserving raw evidence
    - Persist SQLMap output
    - Send collected evidence to the centralized AI layer
    - Provide optional database/table/column enumeration
    - Provide controlled SQLMap configuration

AI is strictly an analysis layer.
It never executes SQLMap commands or controls the scanner.

Intended for authorized security testing only.
"""

from __future__ import annotations

import logging
import shlex
import shutil
import subprocess
import traceback
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import parse_qs, urlparse

from utils.ai import analyze_with_ai
from utils.colors import (
    RED,
    GREEN,
    CYAN,
    YELLOW,
    RESET,
)
from utils.paths import SQLMAP_REPORTS_DIR


logger = logging.getLogger(__name__)


# ============================================================
# STATE
# ============================================================

# URLs already submitted during the current application run.
scanned_urls: set[str] = set()


# ============================================================
# SQLMAP CONFIGURATION
# ============================================================

DEFAULT_LEVEL = 2
DEFAULT_RISK = 1
DEFAULT_THREADS = 4

# Keep SQLMap from waiting for interactive input.
SQLMAP_BASE_OPTIONS = [
    "--batch",
]

# Options which are controlled internally by Chanakya.
#
# Users can still provide normal SQLMap testing options such as:
#
#   --cookie
#   --headers
#   --user-agent
#   --proxy
#   --delay
#   --timeout
#   --retries
#   --level
#   --risk
#   --technique
#
# But they cannot replace the target, config file, executable
# behavior, or Chanakya's staged enumeration logic.
_BLOCKED_CUSTOM_OPTIONS = {
    "-u",
    "--url",

    "-c",
    "--config-file",
    "--config",

    "--sqlmap-shell",
    "--smoke-test",

    "--wizard",

    "--purge",
}

# Options which could terminate SQLMap's normal scan workflow.
_BLOCKED_CONTROL_OPTIONS = {
    "--update",
    "--dependencies",
    "--list-tampers",
    "--list-payloads",
    "--list-waf",
}

# SQLMap options that can cause duplicate/conflicting behavior
# when Chanakya controls the same functionality.
_BLOCKED_ENUMERATION_OPTIONS = {
    "--dbs",
    "--tables",
    "--columns",
    "--dump",
    "--dump-all",
    "--schema",
    "--count",
    "--current-db",
    "--current-user",
    "--current-role",
    "--is-dba",
    "--users",
    "--passwords",
    "--privileges",
    "--roles",
}

# Options that Chanakya itself manages.
_BLOCKED_INTERNAL_OPTIONS = {
    "--batch",
}

ALL_BLOCKED_OPTIONS = (
    _BLOCKED_CUSTOM_OPTIONS
    | _BLOCKED_CONTROL_OPTIONS
    | _BLOCKED_ENUMERATION_OPTIONS
    | _BLOCKED_INTERNAL_OPTIONS
)

# ============================================================
# URL VALIDATION
# ============================================================

def validate_sqlmap_target(url: str) -> bool:
    """
    Validate that a target is a parameterized HTTP(S) URL.

    Example:
        https://example.com/page?id=1

    Rejected:
        example.com/page
        ftp://example.com/page?id=1
        https://example.com/page
    """

    if not isinstance(url, str):
        print(
            RED
            + "[!] Target URL must be a string."
            + RESET
        )
        return False

    url = url.strip()

    if not url:
        print(
            RED
            + "[!] Target URL cannot be empty."
            + RESET
        )
        return False

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            print(
                RED
                + "[!] URL must use HTTP or HTTPS."
                + RESET
            )
            return False

        if not parsed.netloc:
            print(
                RED
                + "[!] Invalid URL: missing hostname."
                + RESET
            )
            return False

        parameters = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        if not parameters:
            print(
                YELLOW
                + "[!] URL does not contain GET parameters."
                + RESET
            )

            print(
                CYAN
                + "[*] Expected format:"
                + RESET
            )

            print(
                "    https://example.com/page?id=1"
            )

            print(
                YELLOW
                + "[!] SQLMap will not be started for this URL."
                + RESET
            )

            return False

        return True

    except ValueError:
        print(
            RED
            + "[!] Failed to parse target URL."
            + RESET
        )
        return False

    except Exception:
        logger.exception(
            "Unexpected target validation error."
        )

        print(
            RED
            + "[!] Failed to validate target URL."
            + RESET
        )

        return False


# ============================================================
# OUTPUT HELPERS
# ============================================================

def _safe_target_filename(target: str) -> str:
    """
    Convert a target into a filesystem-safe filename component.
    """

    safe_target = "".join(
        char
        if char.isalnum() or char in "-_."
        else "_"
        for char in target
    )

    return safe_target[:180] or "target"


def save_sqlmap_output(
    target: str,
    output: str,
) -> Optional[Path]:
    """
    Save raw SQLMap output into reports/sqlmap/.
    """

    if not output or not output.strip():
        return None

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S-%f"
    )

    safe_target = _safe_target_filename(target)

    filename = (
        SQLMAP_REPORTS_DIR
        / f"{timestamp}_{safe_target}.txt"
    )

    try:
        with open(
            filename,
            "w",
            encoding="utf-8",
        ) as file:
            file.write(output)

        return filename

    except OSError:
        logger.exception(
            "Failed to save SQLMap output to %s",
            filename,
        )

        print(
            YELLOW
            + "[!] Failed to save SQLMap output."
            + RESET
        )

        return None


# ============================================================
# CUSTOM SQLMAP PARAMETERS
# ============================================================

def _validate_custom_arguments(
    arguments: Iterable[str],
) -> tuple[bool, list[str]]:
    """
    Validate interactive SQLMap arguments.

    shell=True is never used.

    The target and Chanakya-controlled workflow options cannot
    be overridden.
    """

    validated: list[str] = []

    for argument in arguments:

        argument = argument.strip()

        if not argument:
            continue

        option_name = (
            argument
            .split("=", 1)[0]
            .strip()
            .lower()
        )

        # Handle short option aliases where appropriate.
        if option_name in ALL_BLOCKED_OPTIONS:

            print(
                RED
                + f"[!] SQLMap option '{option_name}' "
                  "is controlled by Chanakya."
                + RESET
            )

            return False, []

        validated.append(argument)

    return True, validated


def get_custom_sqlmap_arguments() -> Optional[list[str]]:
    """
    Ask the user for optional SQLMap arguments.

    Returns:
        Parsed arguments
        [] for defaults
        None on invalid input
    """

    print(
        CYAN
        + "[?] Enter custom SQLMap parameters or press Enter "
          "to use Chanakya defaults."
        + RESET
    )

    print(
        YELLOW
        + "Examples:"
        + RESET
    )

    print("  --cookie=SESSIONID=abc123")
    print('  --headers="X-Forwarded-For: 127.0.0.1"')
    print("  --level=3 --risk=1")
    print("  --technique=BEUSTQ")
    print("  --delay=1 --timeout=15")

    extra = input(
        GREEN
        + "Parameters > "
        + RESET
    ).strip()

    if not extra:
        return []

    try:
        arguments = shlex.split(extra)

    except ValueError as exc:
        print(
            RED
            + f"[!] Invalid SQLMap parameters: {exc}"
            + RESET
        )
        return None

    valid, arguments = _validate_custom_arguments(
        arguments
    )

    if not valid:
        return None

    return arguments


# ============================================================
# SQLMAP COMMAND BUILDER
# ============================================================

def build_sqlmap_command(
    target: str,
    custom_arguments: Optional[list[str]] = None,
    *,
    level: int = DEFAULT_LEVEL,
    risk: int = DEFAULT_RISK,
    threads: int = DEFAULT_THREADS,
    technique: Optional[str] = None,
    enumeration_arguments: Optional[list[str]] = None,
) -> list[str]:
    """
    Build a SQLMap subprocess argument list.

    Chanakya uses a staged approach:

        Detection
            ↓
        Confirmation
            ↓
        Enumeration
            ↓
        Optional dump

    SQLMap remains responsible for the actual technical testing.
    """

    command = [
        "sqlmap",
        "-u",
        target,

        # Never wait for interactive SQLMap questions.
        "--batch",

        # Disable SQLMap's colored output.
        "--disable-coloring",
    ]

    # --------------------------------------------------------
    # DEFAULT TESTING CONFIGURATION
    # --------------------------------------------------------

    command.extend(
        [
            f"--level={max(1, min(level, 5))}",
            f"--risk={max(1, min(risk, 3))}",
            f"--threads={max(1, min(threads, 10))}",
        ]
    )

    # Randomized User-Agent is useful for basic WAF variation.
    command.append("--random-agent")

    # --------------------------------------------------------
    # OPTIONAL TECHNIQUE
    # --------------------------------------------------------

    if technique:
        technique = technique.upper().strip()

        allowed_techniques = set("BEUSTQ")

        if (
            technique
            and set(technique).issubset(allowed_techniques)
        ):
            command.append(
                f"--technique={technique}"
            )

    # --------------------------------------------------------
    # CUSTOM OPTIONS
    # --------------------------------------------------------

    if custom_arguments:
        command.extend(custom_arguments)

    # --------------------------------------------------------
    # ENUMERATION OPTIONS
    # --------------------------------------------------------

    if enumeration_arguments:
        command.extend(enumeration_arguments)

    return command


# ============================================================
# SQLMAP EXECUTION
# ============================================================

def run_sqlmap_command(
    args: list[str],
    target: Optional[str] = None,
    *,
    analyze_output: bool = True,
) -> tuple[Optional[int], str]:
    """
    Execute SQLMap safely.

    Returns:
        (return_code, raw_output)

    return_code:
        0      -> process completed successfully
        nonzero -> SQLMap reported failure/error
        None   -> process could not be executed/interrupted

    Raw SQLMap output is preserved for reports and AI analysis.
    The terminal presentation suppresses the SQLMap banner.
    """

    if not args:
        logger.error(
            "Attempted to execute an empty SQLMap command."
        )
        return None, ""

    output_lines: list[str] = []

    process: Optional[subprocess.Popen] = None

    try:

        sqlmap_path = shutil.which(args[0])

        if sqlmap_path is None:

            print(
                RED
                + "[!] SQLMap was not found."
                + RESET
            )

            print(
                YELLOW
                + "[*] Make sure sqlmap is installed and available "
                  "in PATH."
                + RESET
            )

            return None, ""

        executable_args = [
            sqlmap_path,
            *args[1:],
        ]

        logger.info(
            "Starting SQLMap assessment for target %s",
            target or "unknown",
        )

        print(
            CYAN
            + "[*] Running SQLMap assessment..."
            + RESET
        )

        process = subprocess.Popen(
            executable_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            shell=False,
        )

        if process.stdout is not None:

            for line in process.stdout:

                line = line.rstrip()

                if not line:
                    continue

                # ALWAYS preserve raw evidence.
                output_lines.append(line)

                # Suppress only the banner from the terminal.
                print(line)

        return_code = process.wait()

        output = "\n".join(output_lines)

        logger.info(
            "SQLMap completed with return code %s",
            return_code,
        )

        # ----------------------------------------------------
        # SAVE RAW EVIDENCE
        # ----------------------------------------------------

        if output.strip() and target:

            report_file = save_sqlmap_output(
                target=target,
                output=output,
            )

            if report_file:

                print(
                    GREEN
                    + f"[+] SQLMap evidence saved to {report_file}"
                    + RESET
                )

        # ----------------------------------------------------
        # AI ANALYSIS
        # ----------------------------------------------------

        if analyze_output and output.strip():

            analyze_with_ai(
                target=target or "unknown",
                scan_type="SQLMap SQL injection assessment",
                evidence=output,
            )

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        if return_code != 0:

            print(
                YELLOW
                + f"[!] SQLMap exited with code {return_code}."
                + RESET
            )

        return return_code, output

    except FileNotFoundError:

        print(
            RED
            + "[!] SQLMap executable could not be started."
            + RESET
        )

        return None, "\n".join(output_lines)

    except KeyboardInterrupt:

        print(
            RED
            + "\n[!] SQLMap operation interrupted."
            + RESET
        )

        if process is not None:

            try:
                process.terminate()
                process.wait(timeout=3)

            except Exception:

                try:
                    process.kill()
                except Exception:
                    pass

        return None, "\n".join(output_lines)

    except Exception:

        logger.error(
            "SQLMap execution error:\n%s",
            traceback.format_exc(),
        )

        print(
            RED
            + "[!] Error during SQLMap operation."
            + RESET
        )

        return None, "\n".join(output_lines)


# ============================================================
# FOLLOW-UP EXECUTION
# ============================================================

def _run_follow_up(
    base_command: list[str],
    extra_arguments: list[str],
    target: str,
    failure_message: str,
) -> tuple[bool, str]:

    command = [
        *base_command,
        *extra_arguments,
    ]

    return_code, output = run_sqlmap_command(
        command,
        target=target,
    )

    if return_code is None or return_code != 0:

        print(
            YELLOW
            + f"[!] {failure_message}"
            + RESET
        )

        return False, output

    return True, output


# ============================================================
# SQLMAP PROFILE SELECTION
# ============================================================

def choose_scan_profile() -> tuple[int, int, int, Optional[str]]:
    """
    Select a logical SQLMap testing profile.

    Profiles intentionally avoid maximum settings by default.

    Returns:
        level, risk, threads, technique
    """

    print()
    print(
        CYAN
        + "[?] Select SQLMap assessment profile:"
        + RESET
    )

    print("1. Balanced      (level 2 / risk 1)")
    print("2. Thorough      (level 3 / risk 2)")
    print("3. Comprehensive (level 5 / risk 3)")
    print("4. Custom")

    choice = input(
        GREEN
        + "> "
        + RESET
    ).strip()

    if choice == "1":

        return (
            2,
            1,
            4,
            None,
        )

    if choice == "2":

        return (
            3,
            2,
            4,
            None,
        )

    if choice == "3":

        return (
            5,
            3,
            4,
            None,
        )

    if choice == "4":

        try:

            level = int(
                input("Level (1-5): ").strip()
            )

            risk = int(
                input("Risk (1-3): ").strip()
            )

            threads = int(
                input("Threads (1-10): ").strip()
            )

        except ValueError:

            print(
                YELLOW
                + "[!] Invalid profile values. "
                  "Using balanced profile."
                + RESET
            )

            return (
                2,
                1,
                4,
                None,
            )

        level = max(1, min(level, 5))
        risk = max(1, min(risk, 3))
        threads = max(1, min(threads, 10))

        technique_input = input(
            "Technique subset "
            "(BEUSTQ, or Enter for automatic): "
        ).strip().upper()

        technique = (
            technique_input
            if technique_input
            and set(technique_input).issubset(set("BEUSTQ"))
            else None
        )

        return (
            level,
            risk,
            threads,
            technique,
        )

    print(
        YELLOW
        + "[!] Invalid selection. Using balanced profile."
        + RESET
    )

    return (
        2,
        1,
        4,
        None,
    )


# ============================================================
# SQL INJECTION WORKFLOW
# ============================================================

def sql_injection_advanced(url: str) -> None:
    """
    Run an interactive SQLMap SQL injection assessment.

    Workflow:

        Validate target
            ↓
        Prevent duplicate scan
            ↓
        Select logical SQLMap profile
            ↓
        Optional custom options
            ↓
        Initial SQLi assessment
            ↓
        Optional database enumeration
            ↓
        Optional table enumeration
            ↓
        Optional column enumeration
            ↓
        Optional data dump

    AI analyzes collected SQLMap evidence.
    AI never controls SQLMap.
    """

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------

    if not isinstance(url, str):

        print(
            RED
            + "[!] Target URL must be a string."
            + RESET
        )

        return

    url = url.strip()

    if not url:

        print(
            RED
            + "[!] Target URL cannot be empty."
            + RESET
        )

        return

    print(
        GREEN
        + f"[*] Testing for SQL injection: {url}"
        + RESET
    )

    # --------------------------------------------------------
    # TARGET VALIDATION
    # --------------------------------------------------------

    if not validate_sqlmap_target(url):
        return

    # --------------------------------------------------------
    # DUPLICATE CHECK
    # --------------------------------------------------------

    if url in scanned_urls:

        print(
            YELLOW
            + "[!] Already tested this URL. Skipping..."
            + RESET
        )

        return

    scanned_urls.add(url)

    # --------------------------------------------------------
    # SCAN PROFILE
    # --------------------------------------------------------

    level, risk, threads, technique = (
        choose_scan_profile()
    )

    print()
    print(
        CYAN
        + "[*] SQLMap profile:"
        + RESET
        + f" level={level}"
        + f" risk={risk}"
        + f" threads={threads}"
        + (
            f" technique={technique}"
            if technique
            else ""
        )
    )

    # --------------------------------------------------------
    # CUSTOM PARAMETERS
    # --------------------------------------------------------

    custom_arguments = (
        get_custom_sqlmap_arguments()
    )

    if custom_arguments is None:
        return

    # --------------------------------------------------------
    # BASE COMMAND
    # --------------------------------------------------------

    command = build_sqlmap_command(
        target=url,
        custom_arguments=custom_arguments,
        level=level,
        risk=risk,
        threads=threads,
        technique=technique,
    )

    # --------------------------------------------------------
    # INITIAL SQLi ASSESSMENT
    # --------------------------------------------------------

    print()
    print(
        CYAN
        + "=" * 70
        + RESET
    )

    print(
        GREEN
        + "              INITIAL SQLi ASSESSMENT"
        + RESET
    )

    print(
        CYAN
        + "=" * 70
        + RESET
    )

    return_code, output = run_sqlmap_command(
        command,
        target=url,
    )

    if return_code is None or return_code != 0:

        print(
            YELLOW
            + "[!] Initial SQLMap assessment did not complete "
              "successfully."
            + RESET
        )

        return

    # --------------------------------------------------------
    # CHECK FOR SQLMAP INJECTION EVIDENCE
    # --------------------------------------------------------

    output_lower = output.lower()

    injection_indicators = (
        "is vulnerable",
        "parameter '",
        "injectable",
        "sql injection",
        "back-end dbms",
        "type: boolean-based",
        "type: error-based",
        "type: time-based",
        "type: union query",
        "type: stacked queries",
    )

    injection_detected = any(
        indicator in output_lower
        for indicator in injection_indicators
    )

    if not injection_detected:

        print()
        print(
            YELLOW
            + "[*] No strong SQL injection confirmation "
              "was identified in SQLMap output."
            + RESET
        )

        print(
            CYAN
            + "[*] Stopping before database enumeration."
            + RESET
        )

        return

    print()
    print(
        GREEN
        + "[+] SQLMap produced SQL injection evidence."
        + RESET
    )

    # --------------------------------------------------------
    # DATABASE ENUMERATION
    # --------------------------------------------------------

    follow_up = input(
        CYAN
        + "[?] Enumerate databases? (yes/no): "
        + RESET
    ).strip().lower()

    if follow_up not in {"yes", "y"}:
        return

    success, _ = _run_follow_up(
        base_command=command,
        extra_arguments=[
            "--dbs",
        ],
        target=url,
        failure_message="Database enumeration failed.",
    )

    if not success:
        return

    # --------------------------------------------------------
    # DATABASE NAME
    # --------------------------------------------------------

    dbname = input(
        CYAN
        + "[?] Enter a database name to enumerate tables: "
        + RESET
    ).strip()

    if not dbname:
        return

    # --------------------------------------------------------
    # TABLE ENUMERATION
    # --------------------------------------------------------

    success, _ = _run_follow_up(
        base_command=command,
        extra_arguments=[
            "-D",
            dbname,
            "--tables",
        ],
        target=url,
        failure_message="Table enumeration failed.",
    )

    if not success:
        return

    # --------------------------------------------------------
    # TABLE NAME
    # --------------------------------------------------------

    table = input(
        CYAN
        + "[?] Enter table name to enumerate columns: "
        + RESET
    ).strip()

    if not table:
        return

    # --------------------------------------------------------
    # COLUMN ENUMERATION
    # --------------------------------------------------------

    success, _ = _run_follow_up(
        base_command=command,
        extra_arguments=[
            "-D",
            dbname,
            "-T",
            table,
            "--columns",
        ],
        target=url,
        failure_message="Column enumeration failed.",
    )

    if not success:
        return

    # --------------------------------------------------------
    # DATA DUMP
    # --------------------------------------------------------

    dump = input(
        CYAN
        + "[?] Dump data from this table? (yes/no): "
        + RESET
    ).strip().lower()

    if dump not in {"yes", "y"}:
        return

    _run_follow_up(
        base_command=command,
        extra_arguments=[
            "-D",
            dbname,
            "-T",
            table,
            "--dump",
        ],
        target=url,
        failure_message="Data dump failed.",
    )

    print()
    print(
        GREEN
        + "[+] SQL injection workflow completed."
        + RESET
    )