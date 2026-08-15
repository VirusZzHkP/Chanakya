from pathlib import Path


# ============================================================
# CHANAKYA BASE PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

REPORTS_DIR = BASE_DIR / "reports"


# ============================================================
# REPORT DIRECTORIES
# ============================================================

NMAP_REPORTS_DIR = REPORTS_DIR / "nmap"
SERVICE_REPORTS_DIR = REPORTS_DIR / "services"
SQLMAP_REPORTS_DIR = REPORTS_DIR / "sqlmap"
DORKING_REPORTS_DIR = REPORTS_DIR / "dorking"


# ============================================================
# CREATE DIRECTORIES
# ============================================================

for directory in (
    REPORTS_DIR,
    NMAP_REPORTS_DIR,
    SERVICE_REPORTS_DIR,
    SQLMAP_REPORTS_DIR,
    DORKING_REPORTS_DIR,
):
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )