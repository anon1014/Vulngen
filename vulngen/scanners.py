"""Detectors under test. Each returns a list of {line, cwe, message} dicts.

Scanners only ever see the target file (vulnerable or patched), never the trigger or the manifest.
They are static tools, so they run on the host rather than in the sandbox.
"""

import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from . import config

TOOLS = {
    "semgrep": {"label": "Semgrep", "languages": ["python", "c"], "kind": "traditional"},
    "bandit": {"label": "Bandit", "languages": ["python"], "kind": "traditional"},
    "cppcheck": {"label": "Cppcheck", "languages": ["c"], "kind": "traditional"},
    "gemini": {"label": "Gemini reviewer", "languages": ["python", "c"], "kind": "ai"},
}

_CWE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)


def _norm_cwe(value) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return f"CWE-{value}"
    if isinstance(value, list):
        value = " ".join(map(str, value))
    m = _CWE.search(str(value))
    if m:
        return f"CWE-{m.group(1)}"
    return f"CWE-{value}" if str(value).isdigit() else ""


def available(tool: str) -> bool:
    if tool == "gemini":
        return bool(config.GEMINI_API_KEY)
    return shutil.which(tool) is not None


def run_semgrep(path: Path, language: str) -> list[dict]:
    r = subprocess.run(
        ["semgrep", "scan", "--config", config.SEMGREP_CONFIG[language], "--json",
         "--metrics", "off", "--quiet", str(path)],
        capture_output=True, text=True, timeout=300,
    )
    if not r.stdout.strip():
        raise RuntimeError(f"semgrep produced no output: {r.stderr[-500:]}")
    data = json.loads(r.stdout)
    return [
        {
            "line": res["start"]["line"],
            "cwe": _norm_cwe(res.get("extra", {}).get("metadata", {}).get("cwe")),
            "message": res.get("extra", {}).get("message", res.get("check_id", ""))[:300],
        }
        for res in data.get("results", [])
    ]


def run_bandit(path: Path, language: str) -> list[dict]:
    r = subprocess.run(["bandit", "-f", "json", "-q", str(path)], capture_output=True, text=True, timeout=120)
    data = json.loads(r.stdout or "{}")
    return [
        {
            "line": res["line_number"],
            "cwe": _norm_cwe((res.get("issue_cwe") or {}).get("id")),
            "message": f"{res.get('test_id', '')}: {res.get('issue_text', '')}"[:300],
        }
        for res in data.get("results", [])
    ]


def run_cppcheck(path: Path, language: str) -> list[dict]:
    r = subprocess.run(
        ["cppcheck", "--enable=warning,portability", "--inconclusive", "--xml", "--xml-version=2", str(path)],
        capture_output=True, text=True, timeout=120,
    )
    root = ET.fromstring(r.stderr[r.stderr.find("<?xml"):]) if "<?xml" in r.stderr else None
    out = []
    if root is None:
        return out
    for err in root.iter("error"):
        if err.get("severity") == "information":
            continue
        loc = err.find("location")
        if loc is None:
            continue
        out.append({
            "line": int(loc.get("line", 0)),
            "cwe": _norm_cwe(err.get("cwe")),
            "message": f"{err.get('id')}: {err.get('msg')}"[:300],
        })
    return out


def run_gemini(path: Path, language: str) -> list[dict]:
    from .llm import review_code  # imported lazily so the app runs without a key

    return [
        {"line": f.line, "cwe": _norm_cwe(f.cwe), "message": f.message[:300]}
        for f in review_code(path.read_text(), language)
    ]


RUNNERS = {"semgrep": run_semgrep, "bandit": run_bandit, "cppcheck": run_cppcheck, "gemini": run_gemini}


def run_tool(tool: str, path: Path, language: str) -> list[dict]:
    return RUNNERS[tool](path, language)
