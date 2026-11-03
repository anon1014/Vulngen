import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEN_MODEL = os.getenv("GEMINI_GEN_MODEL", "gemini-3.8-flash")
REVIEW_MODEL = os.getenv("GEMINI_REVIEW_MODEL", GEN_MODEL)

SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "vulngen-sandbox:latest")
SANDBOX_DIR = ROOT / "sandbox"

LINE_TOLERANCE = int(os.getenv("LINE_TOLERANCE", "2"))

SEMGREP_CONFIG = {
    "python": os.getenv("SEMGREP_CONFIG_PYTHON", "p/python"),
    "c": os.getenv("SEMGREP_CONFIG_C", "p/c"),
}

DATA_DIR = ROOT / "data"
CASES_DIR = DATA_DIR / "cases"
DB_PATH = DATA_DIR / "vulngen.db"
SAMPLES_DIR = ROOT / "samples"
